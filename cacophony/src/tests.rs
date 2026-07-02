use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dave::{Codec, DAVE_PROTOCOL_VERSION, DecryptError, FrameDecryptError, MediaType};
use openmls::prelude::{
    BasicCredential, Ciphersuite, ExternalProposal, ExternalSender, GroupEpoch, GroupId,
    KeyPackageIn, MlsMessageOut, OpenMlsProvider, ProtocolVersion, SenderExtensionIndex, VLBytes,
    tls_codec::{Deserialize, Serialize},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use opus_rs::{Application as OpusApplication, OpusEncoder as RawOpusEncoder};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};

use crate::{
    AEAD_TAG_LEN, DAVE_SEND_MEDIA_READY_TIMEOUT, RTP_VERSION, RTPSIZE_NONCE_LEN,
    codecs::{self, DiscordRtpCodecMap},
    connection::{
        Connection, ConnectionClose, ConnectionCommand, ConnectionInner, ConnectionStateStore,
        PendingReceive, PlayoutCommand, ReadyFrameQueue, spawn_voice_connection_join_task,
    },
    dave::{
        DaveCoordinator, DaveIdentityKey, DaveIgnoredProposalsEvent, DaveMediaStatus,
        DavePreparedEpoch,
    },
    errors::{
        DaveDecryptError, DaveError, DaveGatewayPayloadError, Error, PayloadKind, RtpError,
        UnsupportedCodecError,
    },
    gateway::{
        BinaryEvent, DaveTransitionReadyCommand, DiscordId, GatewayCommand, GatewayEventEffects,
        GatewayEventHandler, GatewayHeartbeatAckState, GatewayReady, GatewayReadyStream,
        HeartbeatCommand, HelloData, Opcode, ParsedVoiceGatewayEvent, SelectProtocolCommand,
        SpeakingCommand, SpeakingFlags, UdpDiscoveryPacket, handle_voice_binary_event,
    },
    media::{
        FrameRaw, NoRawPackets, OutboundEncryptParams, RawFramePackets, RawUdpPacket,
        RawUdpPacketInfo, ReceivedFrame, RtpFrameAssembler, RtpHeader, RtpHeaderFields,
        RtpSizeNonceSuffix, VoiceEndpoint, VoiceUdpRemote, build_rtp_header,
        decrypt_transport_payload, encrypt_transport_payload, ordered_voice_socket_addrs,
    },
    observer::{
        ConnectionObserver, DavePendingMediaReason, NoopConnectionObserver, ReceiveDecodeErrorKind,
        ReceiveFrameDroppedEvent, ReceiveRtpPacketLossEvent, RtcpHeader,
    },
    opus::{
        Decoder,
        discord::{
            CHANNELS, EncodeConfig, MAX_PACKET_BYTES, PacketEncoder, PcmBlock, PcmEncoder,
            RTP_PAYLOAD_TYPE, SAMPLE_RATE_HZ, SAMPLES_PER_CHANNEL, STEREO_SAMPLES_PER_BLOCK,
        },
    },
    pcm::{
        ALaw, F32, Mono, MonoSincResampler, MuLaw, PcmChunk, PcmEncoding, S16Le, Samples,
        StereoInterleaved, interleaved_i16_to_mono_s16le, s16le_rms,
    },
    queue::DriverReply,
    rtp::RtpPayloadType,
    state::{
        ConnectionCodecPreferences, ConnectionConfig, ConnectionInternalState, ConnectionOptions,
        ConnectionTuning, DaveInternalState, DaveMlsMessageIdentity, DaveMlsMessageKind,
        DavePendingMediaRetry, EncryptionMode, OfferedEncryptionMode, PendingDaveMediaQueues,
        PendingDaveMlsMessage, PendingMediaFrame, PendingMediaPacket, ReceiveSsrcState,
        ReceiveState, SecretKey, SessionDescription, SessionDescriptionParts,
    },
};

const TEST_DISCORD_ID: u64 = 0xDEADBEEF;
const TEST_DISCORD_ID_JSON: &str = "3735928559";

fn test_opus_payload_type() -> RtpPayloadType {
    RtpPayloadType::new_const(RTP_PAYLOAD_TYPE)
}

type TestVoiceConnection = Connection<NoopConnectionObserver, NoRawPackets>;
type TestPendingPacketReceive = PendingReceive<RawUdpPacket>;
type TestReceiveState = ReceiveState<NoRawPackets>;
type TestReceiveSsrcState = ReceiveSsrcState<NoRawPackets>;
type TestReadyVoiceFrameQueue = ReadyFrameQueue<NoRawPackets>;

fn test_connection_config() -> ConnectionConfig {
    ConnectionConfig {
        guild_id: 1,
        channel_id: 2,
        user_id: 3,
        session_id: "session".to_string(),
        token: "token".to_string(),
        endpoint: "127.0.0.1".to_string(),
    }
}

fn test_state() -> ConnectionInternalState {
    let selected_mode = EncryptionMode::aead_aes256_gcm_rtpsize();
    let config = test_connection_config()
        .validate()
        .unwrap()
        .runtime_config();
    let session_description = SessionDescription::new(SessionDescriptionParts {
        mode: EncryptionMode::aead_aes256_gcm_rtpsize(),
        secret_key: SecretKey::new(vec![0; 32]),
        audio_codec: None,
        video_codec: None,
        dave_protocol_version: Some(1),
    })
    .unwrap();
    let rtp_codecs =
        DiscordRtpCodecMap::new(&session_description, &config.options.codec_preferences).unwrap();
    ConnectionInternalState {
        config,
        heartbeat_interval_ms: 50,
        last_seq: None,
        ready: GatewayReady {
            ssrc: 42,
            ip: "127.0.0.1".to_string(),
            port: 5000,
            modes: vec![selected_mode.into()],
            heartbeat_interval: None,
            streams: Vec::new(),
        },
        discovery: UdpDiscoveryPacket {
            ssrc: 42,
            address: "127.0.0.1".to_string(),
            port: 5001,
        },
        selected_mode,
        session_description: Some(session_description),
        rtp_codecs: Some(rtp_codecs),
        connected_user_ids: Arc::new(HashSet::new()),
        ssrc_users: Arc::new(HashMap::new()),
        speaking: Arc::new(HashMap::new()),
        dave: DaveInternalState::default(),
        roster_authoritative: false,
        resumed: false,
    }
}

fn test_pending_mls(kind: DaveMlsMessageKind) -> PendingDaveMlsMessage {
    PendingDaveMlsMessage::new(
        DaveMlsMessageIdentity {
            kind,
            seq: 7,
            transition_id: 8,
        },
        vec![0xad],
    )
}

fn test_state_store() -> ConnectionStateStore {
    ConnectionStateStore::new(test_state())
}

fn handle_test_voice_text_event(
    state: &mut ConnectionStateStore,
    event: ParsedVoiceGatewayEvent,
) -> crate::Result<GatewayEventEffects> {
    let mut heartbeat_ack = GatewayHeartbeatAckState::default();
    GatewayEventHandler::new(state, &mut heartbeat_ack, &NoopConnectionObserver)
        .handle_text_event(event)
}

async fn test_connection_with_state(state: ConnectionInternalState) -> TestVoiceConnection {
    let state = ConnectionStateStore::new(state);
    let (command_tx, mut command_rx) = mpsc::channel::<ConnectionCommand<NoRawPackets>>(16);
    let (media_tx, mut media_rx) = mpsc::channel::<PlayoutCommand>(16);
    let close = ConnectionClose::new();
    let task_close = close.clone();
    let task = tokio::spawn(async move {
        let mut commands = VecDeque::new();
        let mut sends = VecDeque::new();
        loop {
            tokio::select! {
                command = command_rx.recv() => {
                    match command {
                        Some(command) => commands.push_back(command),
                        None => break,
                    }
                }
                send = media_rx.recv() => {
                    match send {
                        Some(send) => sends.push_back(send),
                        None => break,
                    }
                }
                () = task_close.closed() => {
                    while let Ok(command) = command_rx.try_recv() {
                        commands.push_back(command);
                    }
                    while let Ok(send) = media_rx.try_recv() {
                        sends.push_back(send);
                    }
                    while let Some(command) = commands.pop_front() {
                        command.complete_closed();
                    }
                    while let Some(send) = sends.pop_front() {
                        send.complete_closed();
                    }
                    break;
                }
            }
        }
        Ok(())
    });
    let abort = task.abort_handle();
    let join_tx = spawn_voice_connection_join_task(task);
    Connection {
        inner: Arc::new(ConnectionInner {
            state_rx: state.subscribe_public(),
            command_tx,
            media_tx,
            close,
            join_tx,
            abort,
            observer: NoopConnectionObserver,
        }),
    }
}

async fn test_connection() -> TestVoiceConnection {
    test_connection_with_state(test_state()).await
}

#[test]
fn default_config_uses_dave_protocol_version() {
    let config = test_connection_config().validate().unwrap();

    assert_eq!(
        config.options().max_dave_protocol_version,
        Some(DAVE_PROTOCOL_VERSION.get())
    );
    assert_eq!(
        config.options().dave_send_media_ready_timeout,
        DAVE_SEND_MEDIA_READY_TIMEOUT
    );
    assert_eq!(config.options().dave_identity, None);
}

#[tokio::test]
async fn recv_raw_udp_packet_returns_closed_when_connection_closes() {
    let connection = test_connection().await;
    let receive = tokio::spawn({
        let connection = connection.clone();
        async move { connection.recv_raw_udp_packet(1200).await }
    });

    tokio::task::yield_now().await;
    assert!(connection.close());
    let result = timeout(Duration::from_secs(1), receive)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(Error::Closed)));
}

#[tokio::test]
async fn frame_stream_returns_closed_when_connection_closes() {
    let connection = test_connection().await;
    let receive = tokio::spawn({
        let connection = connection.clone();
        async move { connection.frame_stream(1200).await }
    });

    tokio::task::yield_now().await;
    assert!(connection.close());
    let result = timeout(Duration::from_secs(1), receive)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(Error::Closed)));
}

#[test]
fn abandoned_low_level_receive_request_is_inactive() {
    let (response, receive) = oneshot::channel();
    drop(receive);
    let request: TestPendingPacketReceive = PendingReceive {
        max_len: 1200,
        response: DriverReply::new(response),
    };

    assert!(request.is_closed());
}

#[tokio::test]
async fn send_returns_closed_after_connection_closes() {
    let connection = test_connection().await;
    assert!(connection.close());
    assert!(matches!(
        connection.set_speaking(SpeakingFlags::MICROPHONE, 0),
        Err(Error::Closed)
    ));
}

#[tokio::test]
async fn wait_until_media_ready_returns_closed_after_connection_closes() {
    let mut state = test_state();
    state
        .dave
        .set_session_protocol(Some(DAVE_PROTOCOL_VERSION.get()));
    let connection = test_connection_with_state(state).await;

    assert!(connection.close());
    assert!(matches!(
        connection
            .wait_until_media_ready(Duration::from_secs(1))
            .await,
        Err(Error::Closed)
    ));
}

#[test]
fn receive_rtp_reorders_adjacent_packets_without_loss() {
    let observer = TestReceiveObserver::default();
    let mut receive = TestReceiveState::default();

    assert_eq!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 7))
            .unwrap()
            .unwrap()
            .rtp
            .seq,
        7
    );
    assert!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 9))
            .unwrap()
            .is_none()
    );
    assert_eq!(observer.loss_count(), 0);
    assert_eq!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 8))
            .unwrap()
            .unwrap()
            .rtp
            .seq,
        8
    );
    assert_eq!(
        receive
            .drain_ordered_media(&observer)
            .unwrap()
            .unwrap()
            .rtp
            .seq,
        9
    );
    assert_eq!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 10))
            .unwrap()
            .unwrap()
            .rtp
            .seq,
        10
    );
    assert_eq!(observer.loss_count(), 0);
}

#[test]
fn receive_rtp_reports_loss_only_after_reorder_window_expires() {
    let observer = TestReceiveObserver::default();
    let mut receive = TestReceiveState::default();

    assert_eq!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 7))
            .unwrap()
            .unwrap()
            .rtp
            .seq,
        7
    );
    assert!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 9))
            .unwrap()
            .is_none()
    );
    assert!(receive.drain_ordered_media(&observer).is_none());
    receive
        .ssrc
        .get_mut(&7)
        .unwrap()
        .missing
        .get_mut(&8)
        .unwrap()
        .detected_at =
        Instant::now() - ConnectionTuning::default().rtp_reorder_ttl - Duration::from_millis(1);
    receive.refresh_ssrc_schedules(7);

    assert_eq!(
        receive
            .drain_ordered_media(&observer)
            .unwrap()
            .unwrap()
            .rtp
            .seq,
        9
    );
    assert_eq!(observer.loss_count(), 1);
    assert_eq!(observer.first_seq(), 8);
    assert_eq!(observer.last_seq(), 8);
    assert_eq!(observer.missing_packets(), 1);
}

#[test]
fn ready_voice_frame_queue_reports_overflow() {
    let observer = TestReceiveObserver::default();
    let mut queue = TestReadyVoiceFrameQueue::default();
    let max_frames = ConnectionTuning::default().ready_frame_buffer_max;

    for seq in 0..=max_frames {
        queue.push(
            &observer,
            Ok(test_received_frame_with_seq(seq as u16, vec![0xde])),
        );
    }

    assert_eq!(queue.len(), max_frames);
    assert_eq!(observer.frame_drop_count(), 1);
    assert_eq!(observer.frame_drop_seq(), Some(0));
    assert_eq!(observer.frame_drop_queued_frames(), max_frames - 1);
    assert!(!observer.frame_drop_was_error());
}

#[test]
fn ready_voice_frame_queue_preserves_decode_errors() {
    let observer = TestReceiveObserver::default();
    let mut queue = TestReadyVoiceFrameQueue::default();

    queue.push(&observer, Err(RtpError::PacketTooShort { len: 1 }.into()));

    assert!(matches!(
        queue.pop_front(),
        Some(Err(Error::Rtp(RtpError::PacketTooShort { len: 1 })))
    ));
}

#[test]
fn receive_max_len_is_applied_after_packet_capture() {
    let raw = RawUdpPacket::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]);

    assert!(matches!(
        raw.ensure_len_at_most(3, PayloadKind::RawUdpPacket),
        Err(Error::PayloadTooLarge {
            kind: PayloadKind::RawUdpPacket,
            len: 4,
            max_len: 3,
        })
    ));
    assert!(matches!(
        test_received_frame(vec![0xde, 0xad]).ensure_len_at_most(1),
        Err(Error::PayloadTooLarge {
            kind: PayloadKind::Frame,
            len: 2,
            max_len: 1,
        })
    ));
}

#[test]
fn public_state_snapshots_keep_roster_maps_immutable() {
    let mut state = test_state_store();
    let receiver = state.subscribe_public();
    let before = receiver.borrow().clone();

    state.update(|state| {
        state.connected_user_ids_mut().insert(TEST_DISCORD_ID);
        state.ssrc_users_mut().insert(123, TEST_DISCORD_ID);
        state.ready.ssrc = 777;
    });

    let after = receiver.borrow().clone();
    assert!(!before.connected_user_ids.contains(&TEST_DISCORD_ID));
    assert!(!before.ssrc_users.contains_key(&123));
    assert_eq!(before.local_ssrc, 42);
    assert!(after.connected_user_ids.contains(&TEST_DISCORD_ID));
    assert_eq!(after.ssrc_users.get(&123), Some(&TEST_DISCORD_ID));
    assert_eq!(after.local_ssrc, 777);
}

#[test]
fn receive_raw_packet_retention_is_type_selected() {
    let observer = NoopConnectionObserver;
    let mut compact_receive = TestReceiveState::default();

    assert_eq!(
        compact_receive
            .push_media_packet(&observer, test_pending_media(7, 1))
            .unwrap()
            .unwrap()
            .raw,
        NoRawPackets,
    );

    let mut raw_receive = ReceiveState::<RawFramePackets>::default();
    let raw_bytes = build_rtp_header(1, 960, 7, test_opus_payload_type());
    let frame = raw_receive
        .push_media_packet(&observer, test_pending_raw_media(7, 1, raw_bytes.clone()))
        .unwrap()
        .unwrap();

    assert_eq!(frame.raw.packets.len(), 1);
    assert_eq!(frame.raw.packets[0].bytes, raw_bytes);
    assert_eq!(frame.raw.packets[0].info.seq, Some(1));
}

#[test]
fn av1_receive_uses_timestamp_change_to_finish_markerless_temporal_unit() {
    let observer = NoopConnectionObserver;
    let mut receive = TestReceiveState::default();

    assert!(
        receive
            .push_media_packet(
                &observer,
                test_pending_video_media(7, 1, 90_000, Codec::Av1, false, vec![0x10, 0xaa])
            )
            .unwrap()
            .is_none()
    );
    assert!(
        receive
            .push_media_packet(
                &observer,
                test_pending_video_media(7, 2, 90_000, Codec::Av1, false, vec![0x10, 0xbb])
            )
            .unwrap()
            .is_none()
    );

    let first = receive
        .push_media_packet(
            &observer,
            test_pending_video_media(7, 3, 180_000, Codec::Av1, true, vec![0x10, 0xcc]),
        )
        .unwrap()
        .unwrap();
    let second = receive.drain_ordered_media(&observer).unwrap().unwrap();

    assert_eq!(first.rtp.seq, 1);
    assert_eq!(first.encrypted_frame, [0xaa, 0xbb]);
    assert_eq!(second.rtp.seq, 3);
    assert_eq!(second.encrypted_frame, [0xcc]);
}

#[test]
fn rtp_frame_assembler_drops_non_contiguous_fragmented_frame() {
    let mut assembler = RtpFrameAssembler::<NoRawPackets>::default();

    assert!(
        assembler
            .push_packet(test_pending_video_media(
                7,
                1,
                90_000,
                Codec::Vp8,
                false,
                vec![0x10, 0xaa],
            ))
            .unwrap()
            .is_none()
    );
    assert!(
        assembler
            .push_packet(test_pending_video_media(
                7,
                3,
                90_000,
                Codec::Vp8,
                true,
                vec![0x00, 0xbb],
            ))
            .unwrap()
            .is_none()
    );

    let frame = assembler
        .push_packet(test_pending_video_media(
            7,
            4,
            180_000,
            Codec::Vp8,
            true,
            vec![0x10, 0xcc],
        ))
        .unwrap()
        .unwrap();

    assert_eq!(frame.rtp.seq, 4);
    assert_eq!(frame.encrypted_frame, [0xcc]);
}

#[test]
fn rtp_codec_detection_accepts_negotiated_audio_and_video_payloads() {
    let mut session_description = test_state().session_description.unwrap();
    let codec_preferences =
        ConnectionCodecPreferences::with_video_codecs([Codec::Av1, Codec::H264]).unwrap();
    let codec_map = DiscordRtpCodecMap::new(&session_description, &codec_preferences).unwrap();
    let rtp = test_rtp_header(test_opus_payload_type());

    assert_eq!(codec_map.detect(rtp.payload_type).unwrap(), Codec::Opus);

    session_description.audio_codec = Some("aac".to_string());
    assert!(matches!(
        DiscordRtpCodecMap::new(&session_description, &codec_preferences),
        Err(UnsupportedCodecError::UnsupportedAudioCodec { codec }) if codec == "aac"
    ));

    session_description.audio_codec = Some("opus".to_string());
    session_description.video_codec = Some("AV1".to_string());
    let codec_map = DiscordRtpCodecMap::new(&session_description, &codec_preferences).unwrap();
    assert_eq!(
        codec_map
            .detect(test_rtp_header(codecs::payload_type(Codec::Av1)).payload_type)
            .unwrap(),
        Codec::Av1
    );
    assert_eq!(
        codec_map
            .detect(test_rtp_header(codecs::payload_type(Codec::H264)).payload_type)
            .unwrap(),
        Codec::H264
    );

    assert!(matches!(
        codec_map.detect(test_rtp_header(codecs::payload_type(Codec::Vp8)).payload_type),
        Err(UnsupportedCodecError::UnexpectedRtpPayloadCodec {
            payload_type,
            codec: Codec::Vp8,
            expected_payload_types,
        }) if payload_type == codecs::payload_type(Codec::Vp8)
            && expected_payload_types == vec![
                test_opus_payload_type(),
                codecs::payload_type(Codec::Av1),
                codecs::payload_type(Codec::H264),
            ]
    ));
}

#[test]
fn missing_dave_user_is_typed_error() {
    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        dave.decrypt_media_frame_into(None, MediaType::Audio, b"frame", &mut output)
            .unwrap_err(),
        DaveDecryptError::MissingUser
    );
}

#[test]
fn dave_no_valid_cryptor_error_preserves_details() {
    let error = DaveDecryptError::from(DecryptError::Frame(FrameDecryptError::NoValidCryptor {
        media_type: MediaType::Audio,
        encrypted_size: 12,
        plaintext_capacity: 8,
        manager_count: 2,
    }));
    assert_eq!(
        error,
        DaveDecryptError::Source(DecryptError::Frame(FrameDecryptError::NoValidCryptor {
            media_type: MediaType::Audio,
            encrypted_size: 12,
            plaintext_capacity: 8,
            manager_count: 2,
        }))
    );
    assert_eq!(
        error.receive_decode_kind(),
        ReceiveDecodeErrorKind::DaveNoValidCryptor
    );
}

fn test_external_sender_with_signer() -> (SignatureKeyPair, Vec<u8>) {
    let signer = SignatureKeyPair::new(
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.signature_algorithm(),
    )
    .unwrap();
    let external_sender = ExternalSender::new(
        signer.public().into(),
        BasicCredential::new(0xDEADBEEF_u64.to_be_bytes().into()).into(),
    )
    .tls_serialize_detached()
    .unwrap();
    (signer, external_sender)
}

fn test_external_sender() -> Vec<u8> {
    test_external_sender_with_signer().1
}

fn test_proposal_vector(messages: impl IntoIterator<Item = MlsMessageOut>) -> Vec<u8> {
    let mut proposals = Vec::new();
    for message in messages {
        proposals.extend_from_slice(&message.tls_serialize_detached().unwrap());
    }
    VLBytes::new(proposals).tls_serialize_detached().unwrap()
}

fn test_dave_append_add_proposal(
    key_package: &[u8],
    signer: &SignatureKeyPair,
    channel_id: u64,
    epoch: u64,
) -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let mut key_package_bytes = key_package;
    let key_package = KeyPackageIn::tls_deserialize(&mut key_package_bytes)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let add = ExternalProposal::new_add::<OpenMlsRustCrypto>(
        key_package,
        GroupId::from_slice(&channel_id.to_be_bytes()),
        GroupEpoch::from(epoch),
        signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap();
    let proposals = test_proposal_vector([add]);
    let mut payload = Vec::with_capacity(proposals.len() + 1);
    payload.push(0);
    payload.extend_from_slice(&proposals);
    payload
}

#[derive(Clone, Default)]
struct TestDaveProposalObserver {
    ignored: Arc<Mutex<Vec<String>>>,
}

impl TestDaveProposalObserver {
    fn ignored(&self) -> Vec<String> {
        self.ignored.lock().unwrap().clone()
    }
}

impl ConnectionObserver for TestDaveProposalObserver {
    fn dave_proposals_ignored(&self, event: DaveIgnoredProposalsEvent<'_>) {
        self.ignored.lock().unwrap().push(event.error.to_string());
    }
}

#[test]
fn dave_sole_member_reset_transition_zero_creates_pending_local_group() {
    let mut state = DaveInternalState::default();
    state.prepare_epoch(1, 1);
    state.external_sender = Some(test_external_sender());
    state.prepare_transition(0, 1);

    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let commands = dave
        .pump(&state, &HashSet::from([1]), true, &NoopConnectionObserver)
        .unwrap();

    assert!(commands.iter().any(|command| {
        matches!(
            command,
            GatewayCommand::DaveMlsKeyPackage { key_package } if !key_package.is_empty()
        )
    }));
    assert!(!dave.ready());
    assert!(!dave.send_ready());
    assert_eq!(dave.transition_ready(), None);
}

#[test]
fn dave_prepare_epoch_keeps_established_transition_zero_sender() {
    let (gateway_signer, external_sender) = test_external_sender_with_signer();
    let mut state = DaveInternalState::default();
    state.prepare_epoch(1, 1);
    state.external_sender = Some(external_sender);
    state.prepare_transition(0, 1);

    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let observer = TestDaveProposalObserver::default();
    let commands = dave
        .pump(&state, &HashSet::from([1]), true, &observer)
        .unwrap();
    let key_package = commands
        .iter()
        .find_map(|command| match command {
            GatewayCommand::DaveMlsKeyPackage { key_package } => Some(key_package.as_slice()),
            _ => None,
        })
        .expect("initial pump sends our DAVE key package");
    assert!(!key_package.is_empty());

    let mut joining_user = ::dave::Session::new(::dave::SessionConfig {
        self_user_id: 4,
        channel_id: 2,
        options: ::dave::SessionOptions::default(),
    })
    .unwrap();
    let joining_key_package = joining_user.create_key_package().unwrap();
    state.proposals.push(test_dave_append_add_proposal(
        &joining_key_package,
        &gateway_signer,
        2,
        0,
    ));
    let commands = dave
        .pump(&state, &HashSet::from([1, 4]), true, &observer)
        .unwrap();
    let commit = commands
        .into_iter()
        .find_map(|command| match command {
            GatewayCommand::DaveMlsCommitWelcome { commit, .. } => Some(commit),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "processing our add proposal creates a commit: {:?}",
                observer.ignored()
            )
        });

    state.proposals.clear();
    state.pending_mls.set_message(PendingDaveMlsMessage::new(
        DaveMlsMessageIdentity {
            kind: DaveMlsMessageKind::Commit,
            seq: 1,
            transition_id: 0,
        },
        commit,
    ));
    dave.pump(&state, &HashSet::from([1, 4]), true, &observer)
        .unwrap();

    assert!(dave.ready());
    assert!(dave.send_ready());

    state.prepare_epoch(1, 1);
    dave.pump(&state, &HashSet::from([1, 4]), true, &observer)
        .unwrap();

    assert!(dave.ready());
    assert!(dave.send_ready());
}

#[test]
fn heartbeat_payload_includes_seq_ack() {
    let payload = GatewayCommand::Heartbeat(HeartbeatCommand {
        t: 123,
        seq_ack: Some(456),
    })
    .text_payload()
    .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"t":123,"seq_ack":456}}}}"#,
            Opcode::Heartbeat.code()
        )
    );
}

#[test]
fn voice_endpoint_host_port_uses_discord_endpoint_port() {
    assert_eq!(
        VoiceEndpoint::new("wss://c-syd05-e6e612f0.discord.media:2053/?v=8")
            .host_port()
            .unwrap(),
        ("c-syd05-e6e612f0.discord.media".to_string(), 2053)
    );
}

#[test]
fn voice_endpoint_host_port_defaults_wss_to_443() {
    assert_eq!(
        VoiceEndpoint::new("wss://example.discord.media/?v=8")
            .host_port()
            .unwrap(),
        ("example.discord.media".to_string(), 443)
    );
}

#[test]
fn ordered_voice_socket_addrs_deduplicates_and_prefers_ipv4() {
    let addresses = ordered_voice_socket_addrs([
        "[2606:4700::1]:2053".parse().unwrap(),
        "162.159.128.235:2053".parse().unwrap(),
        "162.159.128.235:2053".parse().unwrap(),
        "[2606:4700::2]:2053".parse().unwrap(),
    ]);
    assert_eq!(
        addresses,
        vec![
            "162.159.128.235:2053".parse().unwrap(),
            "[2606:4700::1]:2053".parse().unwrap(),
            "[2606:4700::2]:2053".parse().unwrap(),
        ]
    );
}

#[test]
fn udp_bind_addr_matches_remote_ip_family() {
    assert_eq!(
        VoiceUdpRemote::new("127.0.0.1".parse().unwrap()).bind_addr(),
        "0.0.0.0:0".parse().unwrap()
    );
    assert_eq!(
        VoiceUdpRemote::new("::1".parse().unwrap()).bind_addr(),
        "[::]:0".parse().unwrap()
    );
}

#[test]
fn discord_id_exposes_raw_snowflake() {
    assert_eq!(DiscordId::new(TEST_DISCORD_ID).get(), TEST_DISCORD_ID);
}

#[test]
fn dave_transition_ready_payload_contains_transition_id() {
    let payload = GatewayCommand::DaveProtocolTransitionReady(DaveTransitionReadyCommand {
        transition_id: 7,
    })
    .text_payload()
    .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"transition_id":7}}}}"#,
            Opcode::DaveTransitionReady.code()
        )
    );
}

#[test]
fn dave_transition_ready_payload_serializes_transition_zero() {
    let payload = GatewayCommand::DaveProtocolTransitionReady(DaveTransitionReadyCommand {
        transition_id: 0,
    })
    .text_payload()
    .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"transition_id":0}}}}"#,
            Opcode::DaveTransitionReady.code()
        )
    );
}

#[test]
fn dave_init_transition_zero_marks_local_ready_without_gateway_command() {
    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let mut commands = Vec::new();

    dave.mark_transition_ready(&mut commands, &NoopConnectionObserver, Some(0), Some(1));

    assert_eq!(dave.transition_ready(), Some(0));
    assert!(commands.is_empty());
}

#[test]
fn dave_disabled_init_transition_zero_marks_local_ready_without_gateway_command() {
    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let mut commands = Vec::new();

    dave.mark_transition_ready(&mut commands, &NoopConnectionObserver, Some(0), Some(0));

    assert_eq!(dave.transition_ready(), Some(0));
    assert!(commands.is_empty());
}

#[test]
fn dave_nonzero_transition_ready_sends_gateway_command() {
    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let mut commands = Vec::new();

    dave.mark_transition_ready(&mut commands, &NoopConnectionObserver, Some(7), Some(1));

    assert_eq!(dave.transition_ready(), Some(7));
    assert_eq!(commands.len(), 1);
    assert!(matches!(
        commands.first(),
        Some(GatewayCommand::DaveProtocolTransitionReady(
            DaveTransitionReadyCommand { transition_id: 7 },
        ))
    ));
}

#[test]
fn speaking_payload_matches_discord_shape() {
    let payload = GatewayCommand::Speaking(SpeakingCommand {
        speaking: SpeakingFlags::MICROPHONE.bits(),
        delay: Some(0),
        ssrc: 42,
        user_id: None,
    })
    .text_payload()
    .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"speaking":1,"delay":0,"ssrc":42}}}}"#,
            Opcode::Speaking.code()
        )
    );
}

#[test]
fn select_protocol_codecs_are_top_level_discord_wire_metadata() {
    let codec_preferences =
        ConnectionCodecPreferences::with_video_codecs([Codec::Av1, Codec::H264]).unwrap();
    let payload = GatewayCommand::SelectProtocol(SelectProtocolCommand::udp(
        "127.0.0.1".to_string(),
        5000,
        EncryptionMode::aead_aes256_gcm_rtpsize(),
        &codec_preferences,
    ))
    .text_payload()
    .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let data = &payload["d"];

    assert_eq!(data["protocol"], "udp");
    assert!(data["data"].get("codecs").is_none());
    assert_eq!(data["data"]["address"], "127.0.0.1");
    assert_eq!(data["data"]["port"], 5000);

    let codecs = data["codecs"].as_array().unwrap();
    assert_eq!(codecs[0]["name"], "opus");
    assert_eq!(codecs[0]["type"], "audio");
    assert_eq!(codecs[0]["priority"], 1_000);
    assert_eq!(codecs[1]["name"], "AV1");
    assert_eq!(codecs[1]["priority"], 2_000);
    assert_eq!(
        codecs[1]["payload_type"],
        codecs::payload_type(Codec::Av1).get()
    );
    assert_eq!(codecs[1]["rtx_payload_type"], 102);
    assert_eq!(codecs[2]["name"], "H264");
    assert_eq!(codecs[2]["priority"], 3_000);
}

#[test]
fn ready_primary_video_stream_matches_identify_rid_and_keeps_rtx() {
    let ready = GatewayReady {
        ssrc: 42,
        ip: "127.0.0.1".to_string(),
        port: 5000,
        modes: vec![EncryptionMode::aead_aes256_gcm_rtpsize().into()],
        heartbeat_interval: None,
        streams: vec![
            GatewayReadyStream {
                kind: Some("video".to_string()),
                rid: Some("50".to_string()),
                ssrc: 50,
                rtx_ssrc: Some(51),
                quality: Some(50),
                active: Some(true),
            },
            GatewayReadyStream {
                kind: Some("video".to_string()),
                rid: Some("100".to_string()),
                ssrc: 100,
                rtx_ssrc: Some(101),
                quality: Some(100),
                active: Some(true),
            },
        ],
    };
    let stream = ready.primary_video_stream().unwrap();

    assert_eq!(stream.ssrc, 100);
    assert_eq!(stream.rtx_ssrc, Some(101));
}

#[test]
fn dave_mls_commands_do_not_have_json_fallback_payloads() {
    let error = GatewayCommand::DaveMlsKeyPackage {
        key_package: vec![0xde, 0xad],
    }
    .text_payload()
    .unwrap_err()
    .to_string();
    assert!(error.contains("binary websocket frames"));
}

#[test]
fn session_description_debug_and_json_do_not_expose_secret_key() {
    let description = SessionDescription::new(SessionDescriptionParts {
        mode: EncryptionMode::aead_aes256_gcm_rtpsize(),
        secret_key: SecretKey::new(vec![0xde; 32]),
        audio_codec: Some("opus".to_string()),
        video_codec: Some("AV1".to_string()),
        dave_protocol_version: Some(1),
    })
    .unwrap();

    let debug = format!("{description:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("222"));
    assert!(!debug.contains("173"));

    let json = serde_json::to_string(&description).unwrap();
    assert!(!json.contains("secret_key"));
    assert!(!json.contains("222"));
    assert!(!json.contains("173"));
}

#[test]
fn unsupported_voice_encryption_modes_fail_selection() {
    let options = ConnectionOptions::default().validate().unwrap();
    let error = GatewayReady {
        ssrc: 42,
        ip: "127.0.0.1".to_string(),
        port: 5000,
        modes: vec![OfferedEncryptionMode::new("xsalsa20_poly1305_lite")],
        heartbeat_interval: None,
        streams: Vec::new(),
    }
    .select_encryption_mode(&options)
    .unwrap_err()
    .to_string();

    assert!(error.contains("required voice encryption mode"));
}

#[test]
fn transport_crypto_round_trips_aes_gcm_rtpsize_packets() {
    transport_crypto_round_trips(EncryptionMode::aead_aes256_gcm_rtpsize());
}

#[test]
fn transport_crypto_round_trips_xchacha_rtpsize_packets() {
    transport_crypto_round_trips(EncryptionMode::aead_xchacha20_poly1305_rtpsize());
}

#[test]
fn transport_crypto_decrypts_packets_with_discord_rtp_extensions() {
    transport_crypto_decrypts_rtp_extensions(EncryptionMode::aead_aes256_gcm_rtpsize());
    transport_crypto_decrypts_rtp_extensions(EncryptionMode::aead_xchacha20_poly1305_rtpsize());
}

#[test]
fn transport_crypto_strips_rtp_padding_after_decrypt() {
    transport_crypto_strips_rtp_padding(EncryptionMode::aead_aes256_gcm_rtpsize());
    transport_crypto_strips_rtp_padding(EncryptionMode::aead_xchacha20_poly1305_rtpsize());
}

#[test]
fn raw_udp_packet_parses_rtcp_header() {
    let packet = RawUdpPacket::from_bytes(vec![0x81, 201, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef]);

    assert!(packet.is_rtcp());
    assert_eq!(
        packet.rtcp_header(),
        Some(RtcpHeader {
            version: 2,
            padding: false,
            report_count: 1,
            packet_type: 201,
            length_words: 7,
            ssrc: Some(0xdeadbeef),
        })
    );
}

fn transport_crypto_round_trips(mode: EncryptionMode) {
    let opus = b"opus-frame";
    let nonce_suffix = RtpSizeNonceSuffix::from_be_bytes([0xde, 0xad, 0xbe, 0xef]);
    let packet = encrypt_transport_payload(
        OutboundEncryptParams {
            header: RtpHeaderFields {
                seq: 10,
                timestamp: 20,
                ssrc: 30,
                payload_type: test_opus_payload_type(),
            },
            marker: false,
            nonce_suffix,
        },
        opus.to_vec(),
        mode,
        &[7; 32],
    )
    .unwrap();

    assert_eq!(
        packet.len(),
        12 + opus.len() + AEAD_TAG_LEN + RTPSIZE_NONCE_LEN
    );
    assert_eq!(
        &packet[packet.len() - RTPSIZE_NONCE_LEN..],
        &nonce_suffix.to_be_bytes()
    );

    let rtp = RtpHeader::parse(&packet).unwrap();
    assert_eq!(
        decrypt_transport_payload(&packet, &rtp, mode, &[7; 32]).unwrap(),
        opus
    );
}

fn transport_crypto_decrypts_rtp_extensions(mode: EncryptionMode) {
    let opus = b"opus-frame-with-extension";
    let key = [7; 32];
    let nonce_suffix = [0xde, 0xad, 0xbe, 0xef];
    let packet = TestEncryptedRtpPacket::with_extension(&mode, &key, nonce_suffix, opus);
    let rtp = RtpHeader::parse(&packet.bytes).unwrap();

    assert!(rtp.extension);
    assert_eq!(rtp.encrypted_body_offset, 16);
    assert_eq!(rtp.header_len, 20);
    assert_eq!(
        decrypt_transport_payload(&packet.bytes, &rtp, mode, &key).unwrap(),
        opus
    );
}

fn transport_crypto_strips_rtp_padding(mode: EncryptionMode) {
    let opus = b"opus-frame-with-padding";
    let key = [7; 32];
    let nonce_suffix = [0xde, 0xad, 0xbe, 0xef];
    let packet = TestEncryptedRtpPacket::with_padding(&mode, &key, nonce_suffix, opus);
    let rtp = RtpHeader::parse(&packet.bytes).unwrap();

    assert!(rtp.padding);
    assert_eq!(
        decrypt_transport_payload(&packet.bytes, &rtp, mode, &key).unwrap(),
        opus
    );
}

#[test]
fn rtp_parser_rejects_unsupported_version() {
    let mut packet = [0_u8; 12];
    packet[0] = 1 << 6;

    assert_eq!(
        RtpHeader::parse(&packet),
        Err(RtpError::UnsupportedVersion { version: 1 })
    );
}

#[test]
fn opus_round_trip_decodes_one_discord_frame() {
    let samples = (0..STEREO_SAMPLES_PER_BLOCK)
        .map(|index| {
            let phase = index as f32 / SAMPLE_RATE_HZ as f32 * std::f32::consts::TAU;
            phase.sin() * 0.1
        })
        .collect::<Vec<_>>();
    let frame = PcmBlock::from_48khz::<F32, StereoInterleaved>(&samples).unwrap();
    let opus = PacketEncoder::new(EncodeConfig::default())
        .unwrap()
        .encode(&frame)
        .unwrap();
    let mut decoder = Decoder::discord_default().unwrap();
    let decoded = decoder
        .decode_frame(ReceivedFrame {
            raw: NoRawPackets,
            rtp: RtpHeader {
                version: RTP_VERSION,
                padding: false,
                extension: false,
                marker: false,
                payload_type: test_opus_payload_type(),
                seq: 0,
                timestamp: 0,
                ssrc: 0,
                header_len: 12,
                encrypted_body_offset: 12,
            },
            user_id: Some(1),
            media_type: MediaType::Audio,
            codec: Codec::Opus,
            frame: opus.into_bytes(),
        })
        .unwrap();

    assert_eq!(decoded.pcm_layout.sample_rate_hz, SAMPLE_RATE_HZ);
    assert_eq!(decoded.pcm_layout.channels, CHANNELS);
    assert_eq!(decoded.pcm_layout.samples_per_channel, SAMPLES_PER_CHANNEL);
    assert_eq!(decoded.pcm.len(), STEREO_SAMPLES_PER_BLOCK);
}

#[test]
fn opus_encoder_writes_to_caller_buffer() {
    let samples = vec![0.0; STEREO_SAMPLES_PER_BLOCK];
    let frame = PcmBlock::from_48khz::<F32, StereoInterleaved>(&samples).unwrap();
    let mut encoder = PacketEncoder::new(EncodeConfig::default()).unwrap();
    let mut output = Vec::with_capacity(MAX_PACKET_BYTES);

    let written = encoder.encode_into(&frame, &mut output).unwrap();

    assert_eq!(written, output.len());
    assert!(!output.is_empty());
    assert!(output.len() <= MAX_PACKET_BYTES);
    assert!(output.capacity() >= MAX_PACKET_BYTES);
}

#[test]
fn opus_streaming_encoder_resamples_and_pads_final_packet() {
    let mut encoder = PcmEncoder::<S16Le, Mono>::new(
        std::num::NonZeroU32::new(24_000).unwrap(),
        EncodeConfig::default(),
    )
    .unwrap();
    let mut input = Vec::new();
    for _ in 0..240 {
        input.extend_from_slice(&1234_i16.to_le_bytes());
    }
    let mut packets = Vec::new();

    assert_eq!(encoder.push(&input, &mut packets).unwrap(), 0);
    assert_eq!(encoder.finish(&mut packets).unwrap(), 1);
    assert!(encoder.resampling_required());
    assert_eq!(packets[0].duration(), Duration::from_millis(20));
}

#[test]
fn pcm_runtime_chunk_validates_and_decodes_s16le() {
    let bytes = [1234_i16, -1234_i16]
        .into_iter()
        .flat_map(i16::to_le_bytes)
        .collect::<Vec<_>>();
    let chunk =
        PcmChunk::from_mono_bytes(16_000, PcmEncoding::parse("pcm_s16le").unwrap(), bytes).unwrap();
    let mut samples = Vec::new();

    assert_eq!(chunk.frame_count(), 2);
    assert_eq!(chunk.append_f32(&mut samples).unwrap(), 2);
    assert!((samples[0] - 1234.0 / 32767.0).abs() < 0.000_001);
    assert!((samples[1] + 1234.0 / 32768.0).abs() < 0.000_001);
}

#[test]
fn pcm_companded_silence_decodes_near_zero() {
    for (encoding, silence) in [(PcmEncoding::MuLaw, 0xff), (PcmEncoding::ALaw, 0xd5)] {
        let chunk = PcmChunk::from_mono_bytes(8_000, encoding, vec![silence; 160]).unwrap();
        let mut samples = Vec::new();

        chunk.append_f32(&mut samples).unwrap();

        assert_eq!(samples.len(), 160);
        assert!(samples.iter().all(|sample| sample.abs() < 0.001));
    }
}

#[test]
fn pcm_marker_companded_samples_decode() {
    let mut mulaw = Vec::new();
    let mut alaw = Vec::new();

    Samples::<MuLaw>::append_f32(&vec![0xff_u8; 8], &mut mulaw).unwrap();
    Samples::<ALaw>::append_f32(&vec![0xd5_u8; 8], &mut alaw).unwrap();

    assert!(mulaw.iter().all(|sample| sample.abs() < 0.001));
    assert!(alaw.iter().all(|sample| sample.abs() < 0.001));
}

#[test]
fn pcm_streaming_resampler_outputs_16khz_and_flushes_tail() {
    let mut resampler = MonoSincResampler::new(
        std::num::NonZeroU32::new(48_000).unwrap(),
        std::num::NonZeroU32::new(16_000).unwrap(),
        SAMPLES_PER_CHANNEL,
    )
    .unwrap();

    let first = resampler.push(&vec![0.25; SAMPLES_PER_CHANNEL]).unwrap();
    let flushed = resampler.finish().unwrap();

    assert!(resampler.resampling_required());
    assert_eq!(first.len() + flushed.len(), 320);
}

#[test]
fn pcm_interleaved_downmix_and_rms_are_checked() {
    let mono = interleaved_i16_to_mono_s16le(&[1000, -1000, 2000, -2000], 2).unwrap();

    assert_eq!(mono, vec![0, 0, 0, 0]);
    assert_eq!(s16le_rms(&mono).unwrap(), 0.0);
}

#[test]
fn opus_decoder_accepts_mono_discord_speech_frames() {
    let samples = (0..SAMPLES_PER_CHANNEL)
        .map(|index| {
            let phase = index as f32 / SAMPLE_RATE_HZ as f32 * std::f32::consts::TAU;
            phase.sin() * 0.1
        })
        .collect::<Vec<_>>();
    let mut encoder = RawOpusEncoder::new(SAMPLE_RATE_HZ as i32, 1, OpusApplication::Voip).unwrap();
    let mut opus = vec![0; 4096];
    let written = encoder
        .encode(&samples, SAMPLES_PER_CHANNEL, &mut opus)
        .unwrap();
    let mut decoder = Decoder::discord_default().unwrap();
    let decoded = decoder
        .decode_frame(test_received_frame(opus[..written].to_vec()))
        .unwrap();

    assert_eq!(decoded.pcm_layout.sample_rate_hz, SAMPLE_RATE_HZ);
    assert_eq!(decoded.pcm_layout.channels, CHANNELS);
    assert_eq!(decoded.pcm_layout.samples_per_channel, SAMPLES_PER_CHANNEL);
    assert_eq!(decoded.pcm.len(), STEREO_SAMPLES_PER_BLOCK);
    for frame in decoded.pcm.chunks_exact(CHANNELS) {
        assert_eq!(frame[0], frame[1]);
    }
}

#[derive(Clone, Default)]
struct TestReceiveObserver {
    loss_count: Arc<std::sync::atomic::AtomicUsize>,
    first_seq: Arc<std::sync::atomic::AtomicUsize>,
    last_seq: Arc<std::sync::atomic::AtomicUsize>,
    missing_packets: Arc<std::sync::atomic::AtomicUsize>,
    frame_drop_count: Arc<std::sync::atomic::AtomicUsize>,
    frame_drop_seq: Arc<std::sync::atomic::AtomicUsize>,
    frame_drop_queued_frames: Arc<std::sync::atomic::AtomicUsize>,
    frame_drop_was_error: Arc<std::sync::atomic::AtomicBool>,
}

impl TestReceiveObserver {
    fn loss_count(&self) -> usize {
        self.loss_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn first_seq(&self) -> u16 {
        self.first_seq.load(std::sync::atomic::Ordering::Relaxed) as u16
    }

    fn last_seq(&self) -> u16 {
        self.last_seq.load(std::sync::atomic::Ordering::Relaxed) as u16
    }

    fn missing_packets(&self) -> u16 {
        self.missing_packets
            .load(std::sync::atomic::Ordering::Relaxed) as u16
    }

    fn frame_drop_count(&self) -> usize {
        self.frame_drop_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn frame_drop_seq(&self) -> Option<u16> {
        let seq = self
            .frame_drop_seq
            .load(std::sync::atomic::Ordering::Relaxed);
        (seq != usize::MAX).then_some(seq as u16)
    }

    fn frame_drop_queued_frames(&self) -> usize {
        self.frame_drop_queued_frames
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn frame_drop_was_error(&self) -> bool {
        self.frame_drop_was_error
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl ConnectionObserver for TestReceiveObserver {
    const ENABLE_RECEIVE_TELEMETRY: bool = true;

    fn receive_rtp_packet_loss(&self, event: ReceiveRtpPacketLossEvent) {
        self.loss_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.first_seq.store(
            usize::from(event.first_seq),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.last_seq.store(
            usize::from(event.last_seq),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.missing_packets.store(
            usize::from(event.missing_packets),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn receive_frame_dropped(&self, event: ReceiveFrameDroppedEvent) {
        self.frame_drop_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.frame_drop_seq.store(
            event.seq.map_or(usize::MAX, usize::from),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.frame_drop_queued_frames
            .store(event.queued_frames, std::sync::atomic::Ordering::Relaxed);
        self.frame_drop_was_error
            .store(event.dropped_error, std::sync::atomic::Ordering::Relaxed);
    }
}

fn test_pending_media(ssrc: u32, seq: u16) -> PendingMediaPacket<NoRawPackets> {
    PendingMediaPacket {
        raw: (),
        rtp: RtpHeader {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: false,
            payload_type: test_opus_payload_type(),
            seq,
            timestamp: u32::from(seq) * SAMPLES_PER_CHANNEL as u32,
            ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(TEST_DISCORD_ID),
        codec: Codec::Opus,
        encrypted_payload: vec![seq as u8],
        dave: false,
    }
}

fn test_pending_video_media(
    ssrc: u32,
    seq: u16,
    timestamp: u32,
    codec: Codec,
    marker: bool,
    encrypted_payload: Vec<u8>,
) -> PendingMediaPacket<NoRawPackets> {
    PendingMediaPacket {
        raw: (),
        rtp: RtpHeader {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker,
            payload_type: codecs::payload_type(codec),
            seq,
            timestamp,
            ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(TEST_DISCORD_ID),
        codec,
        encrypted_payload,
        dave: false,
    }
}

fn test_pending_raw_media(
    ssrc: u32,
    seq: u16,
    raw: Vec<u8>,
) -> PendingMediaPacket<RawFramePackets> {
    PendingMediaPacket {
        raw: RawFramePackets::capture_packet(&raw, RawUdpPacketInfo::from_bytes(&raw)),
        rtp: RtpHeader {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: false,
            payload_type: test_opus_payload_type(),
            seq,
            timestamp: u32::from(seq) * SAMPLES_PER_CHANNEL as u32,
            ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(TEST_DISCORD_ID),
        codec: Codec::Opus,
        encrypted_payload: vec![seq as u8],
        dave: false,
    }
}

fn test_received_frame(frame: Vec<u8>) -> ReceivedFrame {
    test_received_frame_with_seq(0, frame)
}

fn test_received_frame_with_seq(seq: u16, frame: Vec<u8>) -> ReceivedFrame {
    ReceivedFrame {
        raw: NoRawPackets,
        rtp: test_rtp_header_with_seq(seq, test_opus_payload_type()),
        user_id: Some(1),
        media_type: MediaType::Audio,
        codec: Codec::Opus,
        frame,
    }
}

fn test_received_frame_with_ssrc(ssrc: u32, seq: u16) -> ReceivedFrame {
    let mut frame = test_received_frame_with_seq(seq, vec![seq as u8]);
    frame.rtp.ssrc = ssrc;
    frame
}

fn test_pending_frame(ssrc: u32, seq: u16) -> PendingMediaFrame<NoRawPackets> {
    let mut rtp = test_rtp_header_with_seq(seq, test_opus_payload_type());
    rtp.ssrc = ssrc;
    PendingMediaFrame {
        raw: NoRawPackets,
        rtp,
        user_id: Some(TEST_DISCORD_ID),
        codec: Codec::Opus,
        encrypted_frame: vec![seq as u8],
        dave: true,
        enqueued_at: Instant::now(),
        reason: DavePendingMediaReason::DecryptStatePending,
        was_pending: false,
    }
}

fn test_pending_frame_enqueued(
    ssrc: u32,
    seq: u16,
    enqueued_at: Instant,
    reason: DavePendingMediaReason,
) -> PendingMediaFrame<NoRawPackets> {
    let mut frame = test_pending_frame(ssrc, seq);
    frame.enqueued_at = enqueued_at;
    frame.reason = reason;
    frame
}

fn test_rtp_header(payload_type: RtpPayloadType) -> RtpHeader {
    test_rtp_header_with_seq(0, payload_type)
}

fn test_rtp_header_with_seq(seq: u16, payload_type: RtpPayloadType) -> RtpHeader {
    RtpHeader {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: false,
        payload_type,
        seq,
        timestamp: 0,
        ssrc: 0,
        header_len: 12,
        encrypted_body_offset: 12,
    }
}

struct TestEncryptedRtpPacket {
    bytes: Vec<u8>,
}

impl TestEncryptedRtpPacket {
    fn with_extension(
        mode: &EncryptionMode,
        key: &[u8; 32],
        nonce_suffix: [u8; 4],
        opus: &[u8],
    ) -> Self {
        let mut bytes = build_rtp_header(10, 20, 30, test_opus_payload_type());
        bytes[0] |= 0x10;
        bytes.extend_from_slice(&[0xbe, 0xde, 0x00, 0x01]);

        let aad = bytes.clone();
        let mut encrypted = Vec::from([0xca, 0xfe, 0xba, 0xbe]);
        encrypted.extend_from_slice(opus);

        if mode == &EncryptionMode::aead_aes256_gcm_rtpsize() {
            let cipher = Aes256Gcm::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 12];
            nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut encrypted)
                .unwrap();
            encrypted.extend_from_slice(&tag);
        } else {
            let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 24];
            nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
            let tag = cipher
                .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut encrypted)
                .unwrap();
            encrypted.extend_from_slice(&tag);
        }

        bytes.extend_from_slice(&encrypted);
        bytes.extend_from_slice(&nonce_suffix);
        Self { bytes }
    }

    fn with_padding(
        mode: &EncryptionMode,
        key: &[u8; 32],
        nonce_suffix: [u8; 4],
        opus: &[u8],
    ) -> Self {
        let mut bytes = build_rtp_header(10, 20, 30, test_opus_payload_type());
        bytes[0] |= 0x20;

        let aad = bytes.clone();
        let mut encrypted = opus.to_vec();
        encrypted.extend_from_slice(&[0, 0, 3]);

        if mode == &EncryptionMode::aead_aes256_gcm_rtpsize() {
            let cipher = Aes256Gcm::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 12];
            nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut encrypted)
                .unwrap();
            encrypted.extend_from_slice(&tag);
        } else {
            let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 24];
            nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
            let tag = cipher
                .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut encrypted)
                .unwrap();
            encrypted.extend_from_slice(&tag);
        }

        bytes.extend_from_slice(&encrypted);
        bytes.extend_from_slice(&nonce_suffix);
        Self { bytes }
    }
}

fn assert_dave_gateway_payload_too_short(error: Error, expected_opcode: u8, expected_len: usize) {
    let Error::Dave(DaveError::InvalidGatewayPayload(DaveGatewayPayloadError::PayloadTooShort {
        opcode,
        len,
        min_len,
    })) = error
    else {
        panic!("unexpected error: {error:?}");
    };

    assert_eq!(opcode, expected_opcode);
    assert_eq!(len, expected_len);
    assert_eq!(min_len, 2);
}

#[test]
fn clients_connect_tracks_connected_user_roster() {
    let mut state_tx = test_state_store();

    handle_test_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::ClientsConnect.code(),
            seq: Some(7),
            data: serde_json::from_str(&format!(r#"{{"user_ids":["{TEST_DISCORD_ID_JSON}"]}}"#))
                .unwrap(),
        },
    )
    .unwrap();

    assert!(state_tx.internal().ssrc_users.is_empty());
    assert!(
        state_tx
            .internal()
            .connected_user_ids
            .contains(&TEST_DISCORD_ID)
    );
}

#[test]
fn client_connect_maps_audio_ssrc_to_user() {
    let mut state_tx = test_state_store();

    handle_test_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::ClientConnect.code(),
            seq: None,
            data: serde_json::from_str(&format!(
                r#"{{"user_id":"{TEST_DISCORD_ID_JSON}","audio_ssrc":123,"video_ssrc":456}}"#,
            ))
            .unwrap(),
        },
    )
    .unwrap();

    assert_eq!(
        state_tx.internal().ssrc_users.get(&123),
        Some(&TEST_DISCORD_ID)
    );
    assert!(
        state_tx
            .internal()
            .connected_user_ids
            .contains(&TEST_DISCORD_ID)
    );
}

#[test]
fn client_disconnect_removes_user_from_media_roster_and_ssrcs() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.connected_user_ids_mut().insert(TEST_DISCORD_ID);
        state.ssrc_users_mut().insert(123, TEST_DISCORD_ID);
        state.ssrc_users_mut().insert(456, 1);
        state
    });

    handle_test_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::ClientDisconnect.code(),
            seq: None,
            data: serde_json::from_str(&format!(r#"{{"user_id":"{TEST_DISCORD_ID_JSON}"}}"#))
                .unwrap(),
        },
    )
    .unwrap();

    assert!(
        !state_tx
            .internal()
            .connected_user_ids
            .contains(&TEST_DISCORD_ID)
    );
    assert!(!state_tx.internal().ssrc_users.contains_key(&123));
    assert_eq!(state_tx.internal().ssrc_users.get(&456), Some(&1));
}

#[test]
fn dave_execute_transition_from_transport_requests_plaintext_receive_grace() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.dave.prepare_transition(7, 1);
        state
    });

    let effects = handle_test_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::DaveExecuteTransition.code(),
            seq: None,
            data: serde_json::from_str(r#"{"transition_id":7}"#).unwrap(),
        },
    )
    .unwrap();

    assert!(effects.allow_plaintext_receive_grace);
    assert_eq!(
        state_tx.internal().dave.active_receive_protocol_version(),
        Some(1)
    );
}

#[test]
fn dave_execute_transition_between_dave_protocols_does_not_request_plain_passthrough() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.dave.prepare_transition(6, 1);
        state.dave.execute_transition(6);
        state.dave.prepare_transition(7, 1);
        state
    });

    let effects = handle_test_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::DaveExecuteTransition.code(),
            seq: None,
            data: serde_json::from_str(r#"{"transition_id":7}"#).unwrap(),
        },
    )
    .unwrap();

    assert!(!effects.allow_plaintext_receive_grace);
    assert_eq!(
        state_tx.internal().dave.active_receive_protocol_version(),
        Some(1)
    );
}

#[test]
fn receive_state_prunes_removed_ssrcs() {
    let mut receive = TestReceiveState::default();
    receive.ssrc.insert(123, TestReceiveSsrcState::default());
    receive.ssrc.insert(456, TestReceiveSsrcState::default());
    receive.pending_dave_media.push(test_pending_frame(123, 1));
    receive.pending_dave_media.push(test_pending_frame(456, 2));

    receive.prune_ssrcs(&HashSet::from([123]));

    assert!(!receive.ssrc.contains_key(&123));
    assert!(receive.ssrc.contains_key(&456));
    assert_eq!(receive.pending_dave_media.len(), 1);
    assert_eq!(
        receive.pending_dave_media.iter().next().unwrap().rtp.ssrc,
        456
    );
}

#[test]
fn pending_dave_media_retry_takes_only_selected_buckets() {
    let mut queues = PendingDaveMediaQueues::default();
    let mut missing_user = test_pending_frame(1, 1);
    missing_user.reason = DavePendingMediaReason::MissingUser;
    let mut gateway_pending = test_pending_frame(2, 2);
    gateway_pending.reason = DavePendingMediaReason::GatewayPending;
    queues.push(missing_user);
    queues.push(gateway_pending);

    let mut retry = Vec::new();
    while let Some(media) = queues.pop_retry(DavePendingMediaRetry::missing_user()) {
        retry.push(media);
    }

    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].rtp.ssrc, 1);
    assert_eq!(queues.len(), 1);
    assert_eq!(queues.iter().next().unwrap().rtp.ssrc, 2);
}

#[test]
fn pending_dave_media_deadline_uses_bucket_heads() {
    let now = Instant::now();
    let ttl = ConnectionTuning::default().dave_pending_media_ttl;
    let expired_at = now - ttl - Duration::from_millis(1);
    let mut queues = PendingDaveMediaQueues::default();
    queues.push(test_pending_frame_enqueued(
        1,
        1,
        now,
        DavePendingMediaReason::GatewayPending,
    ));
    queues.push(test_pending_frame_enqueued(
        2,
        2,
        expired_at,
        DavePendingMediaReason::GatewayPending,
    ));

    assert_eq!(queues.deadline(), Some(expired_at + ttl));
    let mut expired = Vec::new();
    while let Some(media) = queues.pop_expired(now) {
        expired.push(media);
    }

    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].rtp.ssrc, 2);
    assert_eq!(queues.len(), 1);
    assert_eq!(queues.iter().next().unwrap().rtp.ssrc, 1);
}

#[test]
fn pending_dave_media_deadline_uses_earliest_bucket_head() {
    let now = Instant::now();
    let older = now - Duration::from_millis(10);
    let ttl = ConnectionTuning::default().dave_pending_media_ttl;
    let mut queues = PendingDaveMediaQueues::default();
    queues.push(test_pending_frame_enqueued(
        1,
        1,
        now,
        DavePendingMediaReason::MissingUser,
    ));
    queues.push(test_pending_frame_enqueued(
        2,
        2,
        older,
        DavePendingMediaReason::GatewayPending,
    ));

    assert_eq!(queues.deadline(), Some(older + ttl));
}

#[test]
fn ready_frame_queue_prunes_removed_ssrcs() {
    let mut queue = TestReadyVoiceFrameQueue::default();
    queue.push(
        &NoopConnectionObserver,
        Ok(test_received_frame_with_ssrc(123, 1)),
    );
    queue.push(
        &NoopConnectionObserver,
        Ok(test_received_frame_with_ssrc(456, 2)),
    );

    queue.prune_ssrcs(&HashSet::from([123]));

    assert_eq!(queue.len(), 1);
    assert_eq!(queue.pop_front().unwrap().unwrap().rtp.ssrc, 456);
}

#[test]
fn hello_accepts_fractional_heartbeat_interval() {
    let hello: HelloData = serde_json::from_str(r#"{"heartbeat_interval":41250.5}"#).unwrap();
    assert_eq!(hello.heartbeat_interval_ms(), 41_251);
}

#[test]
fn dave_binary_parser_rejects_opcode_first_server_frames() {
    assert!(
        BinaryEvent::parse(&[Opcode::DaveMlsExternalSender.byte(), 0xde, 0xad, 0xbe, 0xef,])
            .is_none()
    );
}

#[test]
fn dave_binary_parser_accepts_seq_prefixed_server_frames() {
    let bytes = [0, 7, Opcode::DaveMlsExternalSender.byte(), 0xde, 0xad];
    let event = BinaryEvent::parse(&bytes).unwrap();
    assert_eq!(event.seq, 7);
    assert_eq!(event.opcode, Opcode::DaveMlsExternalSender);
    assert_eq!(event.payload, &[0xde, 0xad]);
}

#[test]
fn dave_binary_parser_rejects_client_only_opcodes_from_server() {
    assert!(BinaryEvent::parse(&[0, 7, Opcode::DaveMlsKeyPackage.byte(), 0xde, 0xad,]).is_none());
    assert!(
        BinaryEvent::parse(&[0, 7, Opcode::DaveMlsCommitWelcome.byte(), 0xde, 0xad,]).is_none()
    );
}

#[test]
fn short_dave_commit_transition_payload_errors() {
    let mut state_tx = test_state_store();
    let error = handle_voice_binary_event(
        &mut state_tx,
        &[0, 7, Opcode::DaveMlsAnnounceCommitTransition.byte(), 0xde],
    )
    .unwrap_err();

    assert_dave_gateway_payload_too_short(error, Opcode::DaveMlsAnnounceCommitTransition.byte(), 1);
}

#[test]
fn short_dave_welcome_payload_errors() {
    let mut state_tx = test_state_store();
    let error =
        handle_voice_binary_event(&mut state_tx, &[0, 7, Opcode::DaveMlsWelcome.byte(), 0xde])
            .unwrap_err();

    assert_dave_gateway_payload_too_short(error, Opcode::DaveMlsWelcome.byte(), 1);
}

#[test]
fn dave_commit_transition_payload_stores_message_identity() {
    let mut state_tx = test_state_store();

    handle_voice_binary_event(
        &mut state_tx,
        &[
            0,
            7,
            Opcode::DaveMlsAnnounceCommitTransition.byte(),
            0,
            8,
            0xad,
        ],
    )
    .unwrap();

    let state = state_tx.internal();
    let commit = state.dave.pending_mls.commit().unwrap();
    assert_eq!(state.last_seq, Some(7));
    assert_eq!(commit.payload, [0xad]);
    assert_eq!(commit.identity.kind, DaveMlsMessageKind::Commit);
    assert_eq!(commit.identity.seq, 7);
    assert_eq!(commit.identity.transition_id, 8);
}

#[test]
fn dave_prepare_epoch_resets_epoch_without_transition_id() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.dave.prepare_transition(8, 1);
        state.dave.prepare_epoch(1, 2);
        state.dave.proposals.push(vec![0xde]);
        state
            .dave
            .pending_mls
            .set_message(test_pending_mls(DaveMlsMessageKind::Commit));
        state
            .dave
            .pending_mls
            .set_message(test_pending_mls(DaveMlsMessageKind::Welcome));
        state
    });

    handle_test_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::DavePrepareEpoch.code(),
            seq: Some(11),
            data: serde_json::from_str(r#"{"protocol_version":1,"epoch":1}"#).unwrap(),
        },
    )
    .unwrap();

    let state = state_tx.internal();
    assert_eq!(state.dave.protocol_version(), Some(1));
    assert_eq!(state.dave.transition_id(), Some(8));
    assert_eq!(state.dave.epoch(), Some(1));
    assert_eq!(state.dave.prepare_epoch_seq(), 2);
    assert!(state.dave.proposals.is_empty());
    assert!(state.dave.pending_mls.is_empty());
}

#[test]
fn dave_repeated_prepare_epoch_events_remain_distinct() {
    let mut state_tx = test_state_store();

    for seq in [11, 12] {
        state_tx.update(|state| {
            state.dave.proposals.push(vec![0xde]);
            state
                .dave
                .pending_mls
                .set_message(test_pending_mls(DaveMlsMessageKind::Commit));
            state
                .dave
                .pending_mls
                .set_message(test_pending_mls(DaveMlsMessageKind::Welcome));
        });

        handle_test_voice_text_event(
            &mut state_tx,
            ParsedVoiceGatewayEvent {
                opcode: Opcode::DavePrepareEpoch.code(),
                seq: Some(seq),
                data: serde_json::from_str(r#"{"protocol_version":1,"epoch":1}"#).unwrap(),
            },
        )
        .unwrap();
    }

    let state = state_tx.internal();
    assert_eq!(state.dave.protocol_version(), Some(1));
    assert_eq!(state.dave.epoch(), Some(1));
    assert_eq!(state.dave.prepare_epoch_seq(), 2);
    assert!(state.dave.proposals.is_empty());
    assert!(state.dave.pending_mls.is_empty());
}

#[test]
fn dave_initial_transition_zero_stays_pending_without_epoch_reset() {
    let mut state = DaveInternalState::default();

    state.prepare_transition(0, 1);

    assert_eq!(state.transition_id(), Some(0));
    assert_eq!(state.epoch(), None);
    assert_eq!(state.protocol_version(), Some(1));
}

#[test]
fn dave_sole_member_reset_transition_zero_executes_immediately() {
    let mut state = DaveInternalState::default();
    state.prepare_epoch(1, 1);
    state.proposals.push(vec![0xde]);
    state
        .pending_mls
        .set_message(test_pending_mls(DaveMlsMessageKind::Commit));
    state
        .pending_mls
        .set_message(test_pending_mls(DaveMlsMessageKind::Welcome));

    state.prepare_transition(0, 1);

    assert_eq!(state.transition_id(), None);
    assert_eq!(state.epoch(), Some(1));
    assert_eq!(state.protocol_version(), Some(1));
    assert!(state.proposals.is_empty());
    assert!(state.pending_mls.is_empty());
}

#[test]
fn dave_transition_zero_media_ready_requires_local_ready_ack() {
    let mut state = DaveInternalState::default();
    state.prepare_transition(0, 1);

    assert!(!state.transition_zero_media_ready(None));
    assert!(state.transition_zero_media_ready(Some(0)));
    assert!(!state.transition_zero_media_ready(Some(1)));

    state.proposals.push(vec![0xde]);
    assert!(state.transition_zero_media_ready(Some(0)));
    state.proposals.clear();

    state
        .pending_mls
        .set_message(test_pending_mls(DaveMlsMessageKind::Welcome));
    assert!(state.transition_zero_media_ready(Some(0)));
}

#[test]
fn dave_send_media_ready_does_not_depend_on_consumed_transition_ack() {
    assert!(DaveMediaStatus::ready_from(false, false, false, false));
    assert!(!DaveMediaStatus::ready_from(true, false, true, true));
    assert!(!DaveMediaStatus::ready_from(true, true, false, true));
    assert!(!DaveMediaStatus::ready_from(true, true, true, false));
    assert!(DaveMediaStatus::ready_from(true, true, true, true));
}

#[test]
fn dave_receive_transform_is_only_active_for_dave_media() {
    let mut state = DaveInternalState::default();
    assert!(!state.receive_transform_active());

    state.set_session_protocol(Some(1));
    assert!(state.receive_transform_active());

    state.prepare_transition(0, 1);
    assert!(state.receive_transform_active());

    let mut state = DaveInternalState::default();
    state.set_session_protocol(Some(1));
    state.prepare_transition(7, 1);
    assert!(state.receive_transform_active());

    state.execute_transition(7);
    assert!(state.receive_transform_active());

    state.prepare_transition(8, 0);
    state.execute_transition(8);
    assert!(!state.receive_transform_active());
}

#[test]
fn dave_active_send_protocol_switches_only_on_execute() {
    let mut state = DaveInternalState::default();

    state.set_session_protocol(Some(1));
    assert_eq!(state.protocol_version(), Some(1));
    assert!(state.send_requires_dave());
    assert_eq!(state.active_send_protocol_version(), None);
    assert_eq!(state.active_receive_protocol_version(), None);

    state.prepare_transition(7, 1);
    assert_eq!(state.protocol_version(), Some(1));
    assert!(state.send_requires_dave());
    assert_eq!(state.active_send_protocol_version(), None);
    assert_eq!(state.active_receive_protocol_version(), None);

    state.execute_transition(7);
    assert_eq!(state.protocol_version(), Some(1));
    assert_eq!(state.active_send_protocol_version(), Some(1));
    assert_eq!(state.active_receive_protocol_version(), Some(1));

    state.set_session_protocol(Some(1));
    assert_eq!(state.protocol_version(), Some(1));
    assert_eq!(state.active_send_protocol_version(), Some(1));
    assert_eq!(state.active_receive_protocol_version(), Some(1));

    state.prepare_transition(7, 0);
    assert_eq!(state.protocol_version(), Some(0));
    assert_eq!(state.active_send_protocol_version(), Some(1));
    assert_eq!(state.active_receive_protocol_version(), Some(1));

    state.execute_transition(7);
    assert_eq!(state.protocol_version(), Some(0));
    assert_eq!(state.active_send_protocol_version(), Some(0));
    assert_eq!(state.active_receive_protocol_version(), Some(0));

    state.set_session_protocol(None);
    assert_eq!(state.protocol_version(), None);
    assert_eq!(state.active_send_protocol_version(), None);
    assert_eq!(state.active_receive_protocol_version(), None);
}

#[test]
fn dave_transport_to_dave_transition_waits_until_execute() {
    let mut state = DaveInternalState::default();

    state.set_session_protocol(Some(0));
    state.prepare_transition(7, 1);

    assert_eq!(state.protocol_version(), Some(1));
    assert!(!state.send_requires_dave());
    assert!(!state.receive_transform_active());
    assert_eq!(state.active_send_protocol_version(), Some(0));
    assert_eq!(state.active_receive_protocol_version(), Some(0));

    state.execute_transition(7);

    assert!(state.send_requires_dave());
    assert!(state.receive_transform_active());
    assert_eq!(state.active_send_protocol_version(), Some(1));
    assert_eq!(state.active_receive_protocol_version(), Some(1));
}

#[test]
fn dave_transition_zero_uses_dave_media_before_execute() {
    let mut state = DaveInternalState::default();

    state.prepare_transition(0, 1);

    assert_eq!(state.protocol_version(), Some(1));
    assert!(state.send_requires_dave());
    assert!(state.receive_transform_active());
    assert_eq!(state.active_send_protocol_version(), None);
    assert_eq!(state.active_receive_protocol_version(), None);
}

#[test]
fn dave_default_identity_is_shared_for_active_user_sessions() {
    let identity = DaveIdentityKey::shared_ephemeral(1);
    let other_connection = DaveIdentityKey::shared_ephemeral(1);
    let other_user = DaveIdentityKey::shared_ephemeral(2);

    assert_eq!(identity, other_connection);
    assert_ne!(identity, other_user);
    assert_eq!(
        identity.persistence(),
        dave::IdentityKeyPersistence::Ephemeral
    );
}

#[test]
fn receive_interarrival_stats_use_bounded_sorted_window() {
    let mut state = TestReceiveSsrcState::default();
    let window = ConnectionTuning::default().receive_interarrival_window;
    for interarrival_us in 0..(window as u64 + 10) {
        state.record_interarrival(interarrival_us);
    }

    assert_eq!(state.interarrival.len(), window);
    assert_eq!(state.interarrival_p95_us(), Some(252));
    assert_eq!(state.interarrival_max_us(), Some(265));
}

#[test]
fn dave_no_valid_cryptor_retries_only_while_state_can_still_change() {
    assert!(!ReceiveDecodeErrorKind::DaveNoValidCryptor.should_retry_dave_decrypt(false));
    assert!(ReceiveDecodeErrorKind::DaveNoValidCryptor.should_retry_dave_decrypt(true));
    assert!(!ReceiveDecodeErrorKind::DaveNoDecryptorForUser.should_retry_dave_decrypt(false));
    assert!(ReceiveDecodeErrorKind::DaveNoDecryptorForUser.should_retry_dave_decrypt(true));
    assert!(
        !ReceiveDecodeErrorKind::DaveUnencryptedWhenPassthroughDisabled
            .should_retry_dave_decrypt(true)
    );
}

#[test]
fn dave_prepared_epoch_scope_includes_prepare_event_seq() {
    let mut first = DaveInternalState::default();
    first.prepare_epoch(1, 1);
    let mut second = first.clone();
    second.prepare_epoch(1, 1);

    assert_ne!(
        DavePreparedEpoch::from_state(&first),
        DavePreparedEpoch::from_state(&second)
    );

    first.prepare_epoch(1, 1);
    assert_eq!(
        DavePreparedEpoch::from_state(&first),
        DavePreparedEpoch::from_state(&second)
    );
}

#[test]
fn state_updates_do_not_require_subscribers() {
    let mut state_tx = test_state_store();
    let state_rx = state_tx.subscribe_public();
    drop(state_rx);
    state_tx.update(|state| state.resumed = true);
    assert!(state_tx.internal().resumed);
}
