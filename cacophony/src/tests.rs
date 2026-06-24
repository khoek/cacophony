use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dave::{DAVE_PROTOCOL_VERSION, DecryptError, FrameDecryptError, MediaType};
use opus_rs::{Application as OpusApplication, OpusEncoder as RawOpusEncoder};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};

use crate::{
    AEAD_TAG_LEN, DAVE_SEND_MEDIA_READY_TIMEOUT, RTP_VERSION, RTPSIZE_NONCE_LEN,
    connection::{
        Connection, ConnectionClose, ConnectionCommand, ConnectionInner, ConnectionStateStore,
        PendingReceive, PlayoutCommand, ReadyFrameQueue, limit_raw_packet_result,
        limit_voice_frame_result, spawn_voice_connection_join_task,
    },
    dave::{
        DaveCoordinator, DavePreparedEpoch, dave_decrypt_failure_should_retry,
        dave_receive_transform_active, dave_send_media_ready, dave_transition_zero_media_ready,
    },
    errors::{
        DaveDecryptError, DaveError, DaveGatewayPayloadError, Error, PayloadKind, RtpError,
        UnsupportedCodecError,
    },
    gateway::{
        BinaryEvent, DaveTransitionReadyCommand, DiscordId, GatewayCommand, GatewayReady,
        HeartbeatCommand, HelloData, Opcode, ParsedVoiceGatewayEvent, SpeakingCommand,
        SpeakingFlags, UdpDiscoveryPacket, handle_voice_binary_event, handle_voice_text_event,
    },
    media::{
        FrameRaw, MediaCodec, NoRawPackets, OutboundEncryptParams, RawFramePackets, RawUdpPacket,
        RawUdpPacketInfo, ReceivedFrame, RtpHeader, build_rtp_header, decrypt_transport_payload,
        detect_rtp_codec, encrypt_transport_payload, ordered_voice_socket_addrs, parse_rtp_header,
        select_encryption_mode, udp_bind_addr_for_remote, update_state, websocket_host_port,
    },
    observer::{
        ConnectionObserver, DavePendingMediaReason, NoopConnectionObserver, ReceiveDecodeErrorKind,
        ReceiveFrameDroppedEvent, ReceiveRtpPacketLossEvent, RtcpHeader,
    },
    opus::{
        Decoder, PayloadCodec as OpusPayloadCodec,
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
    state::{
        ConnectionConfig, ConnectionInternalState, ConnectionTuning, DaveInternalState,
        DavePendingMediaRetry, EncryptionMode, PendingDaveMediaQueues, PendingMediaFrame,
        PendingMediaPacket, ReceiveSsrcState, ReceiveState, SecretKey, SessionDescription,
    },
};

const TEST_DISCORD_ID: u64 = 0xDEADBEEF;
const TEST_DISCORD_ID_JSON: &str = "3735928559";

type TestVoiceConnection = Connection<NoopConnectionObserver, NoRawPackets>;
type TestPendingPacketReceive = PendingReceive<RawUdpPacket>;
type TestReceiveState = ReceiveState<NoRawPackets>;
type TestReceiveSsrcState = ReceiveSsrcState<NoRawPackets>;
type TestReadyVoiceFrameQueue = ReadyFrameQueue<NoRawPackets>;

fn test_state() -> ConnectionInternalState {
    let selected_mode = EncryptionMode::aead_aes256_gcm_rtpsize();
    ConnectionInternalState {
        config: ConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1"),
        heartbeat_interval_ms: 50,
        last_seq: None,
        ready: GatewayReady {
            ssrc: 42,
            ip: "127.0.0.1".to_string(),
            port: 5000,
            modes: vec![selected_mode.clone()],
            heartbeat_interval: None,
        },
        discovery: UdpDiscoveryPacket {
            ssrc: 42,
            address: "127.0.0.1".to_string(),
            port: 5001,
        },
        selected_mode,
        session_description: Some(
            SessionDescription::new(
                EncryptionMode::aead_aes256_gcm_rtpsize(),
                SecretKey::new(vec![0; 32]),
                None,
                Some(1),
            )
            .unwrap(),
        ),
        connected_user_ids: Arc::new(HashSet::new()),
        ssrc_users: Arc::new(HashMap::new()),
        speaking: Arc::new(HashMap::new()),
        dave: DaveInternalState::default(),
        roster_authoritative: false,
        resumed: false,
    }
}

fn test_state_store() -> ConnectionStateStore {
    ConnectionStateStore::new(test_state())
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
    let config = ConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1");

    assert_eq!(
        config.max_dave_protocol_version,
        Some(DAVE_PROTOCOL_VERSION.get())
    );
    assert_eq!(
        config.dave_send_media_ready_timeout,
        DAVE_SEND_MEDIA_READY_TIMEOUT
    );
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
    state.dave.protocol_version = Some(DAVE_PROTOCOL_VERSION.get());
    state.dave.passthrough = false;
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
            .rtp
            .seq,
        7
    );
    assert!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 9))
            .is_none()
    );
    assert_eq!(observer.loss_count(), 0);
    assert_eq!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 8))
            .unwrap()
            .rtp
            .seq,
        8
    );
    assert_eq!(receive.drain_ordered_media(&observer).unwrap().rtp.seq, 9);
    assert_eq!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 10))
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
            .rtp
            .seq,
        7
    );
    assert!(
        receive
            .push_media_packet(&observer, test_pending_media(7, 9))
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

    assert_eq!(receive.drain_ordered_media(&observer).unwrap().rtp.seq, 9);
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
        limit_raw_packet_result(raw, 3, PayloadKind::RawUdpPacket),
        Err(Error::PayloadTooLarge {
            kind: PayloadKind::RawUdpPacket,
            len: 4,
            max_len: 3,
        })
    ));
    assert!(matches!(
        limit_voice_frame_result(Ok(test_received_frame(vec![0xde, 0xad])), 1),
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

    update_state(&mut state, |state| {
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
            .raw,
        NoRawPackets,
    );

    let mut raw_receive = ReceiveState::<RawFramePackets>::default();
    let raw_bytes = build_rtp_header(1, 960, 7, RTP_PAYLOAD_TYPE);
    let frame = raw_receive
        .push_media_packet(&observer, test_pending_raw_media(7, 1, raw_bytes.clone()))
        .unwrap();

    assert_eq!(frame.raw.packets.len(), 1);
    assert_eq!(frame.raw.packets[0].bytes, raw_bytes);
    assert_eq!(frame.raw.packets[0].info.seq, Some(1));
}

#[test]
fn rtp_codec_detection_accepts_only_opus_audio_payloads() {
    let mut session_description = test_state().session_description.unwrap();
    let rtp = test_rtp_header(RTP_PAYLOAD_TYPE);

    assert_eq!(
        detect_rtp_codec(&rtp, &session_description).unwrap(),
        MediaCodec::Opus
    );

    session_description.audio_codec = Some("aac".to_string());
    assert!(matches!(
        detect_rtp_codec(&rtp, &session_description),
        Err(UnsupportedCodecError::UnsupportedAudioCodec { codec }) if codec == "aac"
    ));

    session_description.audio_codec = Some("opus".to_string());
    assert!(matches!(
        detect_rtp_codec(&test_rtp_header(RTP_PAYLOAD_TYPE + 1), &session_description),
        Err(UnsupportedCodecError::UnsupportedRtpPayloadType {
            payload_type,
            expected_payload_type: RTP_PAYLOAD_TYPE,
            codec: MediaCodec::Opus,
        }) if payload_type == RTP_PAYLOAD_TYPE + 1
    ));
}

#[test]
fn missing_dave_user_is_typed_error() {
    let mut dave = DaveCoordinator::new(1, 2).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        dave.decrypt_media_frame_into::<OpusPayloadCodec>(None, b"frame", &mut output)
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
fn websocket_host_port_uses_discord_endpoint_port() {
    assert_eq!(
        websocket_host_port("wss://c-syd05-e6e612f0.discord.media:2053/?v=8").unwrap(),
        ("c-syd05-e6e612f0.discord.media".to_string(), 2053)
    );
}

#[test]
fn websocket_host_port_defaults_wss_to_443() {
    assert_eq!(
        websocket_host_port("wss://example.discord.media/?v=8").unwrap(),
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
        udp_bind_addr_for_remote("127.0.0.1".parse().unwrap()),
        "0.0.0.0:0".parse().unwrap()
    );
    assert_eq!(
        udp_bind_addr_for_remote("::1".parse().unwrap()),
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
fn dave_transition_ready_payload_allows_initial_transition() {
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
    let description = SessionDescription::new(
        EncryptionMode::aead_aes256_gcm_rtpsize(),
        SecretKey::new(vec![0xde; 32]),
        Some("opus".to_string()),
        Some(1),
    )
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
    let config = ConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1");
    let error = select_encryption_mode(
        &config,
        &GatewayReady {
            ssrc: 42,
            ip: "127.0.0.1".to_string(),
            port: 5000,
            modes: vec![EncryptionMode::new("xsalsa20_poly1305_lite")],
            heartbeat_interval: None,
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("supported encryption mode"));
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
    let nonce_suffix = [0xde, 0xad, 0xbe, 0xef];
    let packet = encrypt_transport_payload(
        OutboundEncryptParams {
            seq: 10,
            timestamp: 20,
            ssrc: 30,
            payload_type: RTP_PAYLOAD_TYPE,
            nonce_suffix,
        },
        opus.to_vec(),
        &mode,
        &[7; 32],
    )
    .unwrap();

    assert_eq!(
        packet.len(),
        12 + opus.len() + AEAD_TAG_LEN + RTPSIZE_NONCE_LEN
    );
    assert_eq!(&packet[packet.len() - RTPSIZE_NONCE_LEN..], &nonce_suffix);

    let rtp = parse_rtp_header(&packet).unwrap();
    assert_eq!(
        decrypt_transport_payload(&packet, &rtp, &mode, &[7; 32]).unwrap(),
        opus
    );
}

fn transport_crypto_decrypts_rtp_extensions(mode: EncryptionMode) {
    let opus = b"opus-frame-with-extension";
    let key = [7; 32];
    let nonce_suffix = [0xde, 0xad, 0xbe, 0xef];
    let packet = TestEncryptedRtpPacket::with_extension(&mode, &key, nonce_suffix, opus);
    let rtp = parse_rtp_header(&packet.bytes).unwrap();

    assert!(rtp.extension);
    assert_eq!(rtp.encrypted_body_offset, 16);
    assert_eq!(rtp.header_len, 20);
    assert_eq!(
        decrypt_transport_payload(&packet.bytes, &rtp, &mode, &key).unwrap(),
        opus
    );
}

fn transport_crypto_strips_rtp_padding(mode: EncryptionMode) {
    let opus = b"opus-frame-with-padding";
    let key = [7; 32];
    let nonce_suffix = [0xde, 0xad, 0xbe, 0xef];
    let packet = TestEncryptedRtpPacket::with_padding(&mode, &key, nonce_suffix, opus);
    let rtp = parse_rtp_header(&packet.bytes).unwrap();

    assert!(rtp.padding);
    assert_eq!(
        decrypt_transport_payload(&packet.bytes, &rtp, &mode, &key).unwrap(),
        opus
    );
}

#[test]
fn rtp_parser_rejects_unsupported_version() {
    let mut packet = [0_u8; 12];
    packet[0] = 1 << 6;

    assert_eq!(
        parse_rtp_header(&packet),
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
                payload_type: RTP_PAYLOAD_TYPE,
                seq: 0,
                timestamp: 0,
                ssrc: 0,
                header_len: 12,
                encrypted_body_offset: 12,
            },
            user_id: Some(1),
            media_type: MediaType::Audio,
            codec: MediaCodec::Opus,
            frame: opus.bytes,
        })
        .unwrap();

    assert_eq!(decoded.sample_rate, SAMPLE_RATE_HZ);
    assert_eq!(decoded.channels, CHANNELS);
    assert_eq!(decoded.samples_per_channel, SAMPLES_PER_CHANNEL);
    assert_eq!(decoded.pcm.len(), STEREO_SAMPLES_PER_BLOCK);
}

#[test]
fn opus_encoder_writes_to_caller_buffer() {
    let samples = vec![0.0; STEREO_SAMPLES_PER_BLOCK];
    let frame = PcmBlock::from_48khz::<F32, StereoInterleaved>(&samples).unwrap();
    let mut encoder = PacketEncoder::new(EncodeConfig::default()).unwrap();
    let mut output = Vec::with_capacity(MAX_PACKET_BYTES);

    let duration = encoder.encode_into(&frame, &mut output).unwrap();

    assert_eq!(duration, Duration::from_millis(20));
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
    assert_eq!(packets[0].duration, Duration::from_millis(20));
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

    assert_eq!(decoded.sample_rate, SAMPLE_RATE_HZ);
    assert_eq!(decoded.channels, CHANNELS);
    assert_eq!(decoded.samples_per_channel, SAMPLES_PER_CHANNEL);
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
            payload_type: RTP_PAYLOAD_TYPE,
            seq,
            timestamp: u32::from(seq) * SAMPLES_PER_CHANNEL as u32,
            ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(TEST_DISCORD_ID),
        codec: MediaCodec::Opus,
        encrypted_payload: vec![seq as u8],
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
            payload_type: RTP_PAYLOAD_TYPE,
            seq,
            timestamp: u32::from(seq) * SAMPLES_PER_CHANNEL as u32,
            ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(TEST_DISCORD_ID),
        codec: MediaCodec::Opus,
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
        rtp: test_rtp_header_with_seq(seq, RTP_PAYLOAD_TYPE),
        user_id: Some(1),
        media_type: MediaType::Audio,
        codec: MediaCodec::Opus,
        frame,
    }
}

fn test_received_frame_with_ssrc(ssrc: u32, seq: u16) -> ReceivedFrame {
    let mut frame = test_received_frame_with_seq(seq, vec![seq as u8]);
    frame.rtp.ssrc = ssrc;
    frame
}

fn test_pending_frame(ssrc: u32, seq: u16) -> PendingMediaFrame<NoRawPackets> {
    let mut rtp = test_rtp_header_with_seq(seq, RTP_PAYLOAD_TYPE);
    rtp.ssrc = ssrc;
    PendingMediaFrame {
        raw: NoRawPackets,
        rtp,
        user_id: Some(TEST_DISCORD_ID),
        codec: MediaCodec::Opus,
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

fn test_rtp_header(payload_type: u8) -> RtpHeader {
    test_rtp_header_with_seq(0, payload_type)
}

fn test_rtp_header_with_seq(seq: u16, payload_type: u8) -> RtpHeader {
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
        let mut bytes = build_rtp_header(10, 20, 30, RTP_PAYLOAD_TYPE);
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
        let mut bytes = build_rtp_header(10, 20, 30, RTP_PAYLOAD_TYPE);
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
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::ClientsConnect.code(),
            seq: Some(7),
            data: serde_json::from_str(&format!(r#"{{"user_ids":["{TEST_DISCORD_ID_JSON}"]}}"#))
                .unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopConnectionObserver,
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
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::ClientConnect.code(),
            seq: None,
            data: serde_json::from_str(&format!(
                r#"{{"user_id":"{TEST_DISCORD_ID_JSON}","audio_ssrc":123,"video_ssrc":456}}"#,
            ))
            .unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopConnectionObserver,
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
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::ClientDisconnect.code(),
            seq: None,
            data: serde_json::from_str(&format!(r#"{{"user_id":"{TEST_DISCORD_ID_JSON}"}}"#))
                .unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopConnectionObserver,
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
fn dave_execute_transition_from_transport_requests_receive_passthrough_window() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.dave.prepare_transition(7, 1);
        state
    });
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    let effects = handle_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::DaveExecuteTransition.code(),
            seq: None,
            data: serde_json::from_str(r#"{"transition_id":7}"#).unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopConnectionObserver,
    )
    .unwrap();

    assert!(effects.allow_transition_receive_passthrough);
    assert_eq!(
        state_tx.internal().dave.active_receive_protocol_version,
        Some(1)
    );
}

#[test]
fn dave_execute_transition_between_dave_protocols_does_not_request_plain_passthrough() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.dave.active_receive_protocol_version = Some(1);
        state.dave.prepare_transition(7, 1);
        state
    });
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    let effects = handle_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::DaveExecuteTransition.code(),
            seq: None,
            data: serde_json::from_str(r#"{"transition_id":7}"#).unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopConnectionObserver,
    )
    .unwrap();

    assert!(!effects.allow_transition_receive_passthrough);
    assert_eq!(
        state_tx.internal().dave.active_receive_protocol_version,
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
    assert_eq!(event.seq, Some(7));
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
fn dave_prepare_epoch_resets_epoch_without_transition_id() {
    let mut state_tx = ConnectionStateStore::new({
        let mut state = test_state();
        state.dave.transition_id = Some(8);
        state.dave.epoch = Some(2);
        state.dave.proposals.push(vec![0xde]);
        state.dave.pending_commit = Some(vec![0xad]);
        state.dave.pending_welcome = Some(vec![0xbe]);
        state
    });
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &mut state_tx,
        ParsedVoiceGatewayEvent {
            opcode: Opcode::DavePrepareEpoch.code(),
            seq: Some(11),
            data: serde_json::from_str(r#"{"protocol_version":1,"epoch":1}"#).unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopConnectionObserver,
    )
    .unwrap();

    let state = state_tx.internal();
    assert_eq!(state.dave.protocol_version, Some(1));
    assert_eq!(state.dave.transition_id, Some(8));
    assert_eq!(state.dave.epoch, Some(1));
    assert_eq!(state.dave.prepare_epoch_seq, 1);
    assert!(state.dave.proposals.is_empty());
    assert!(state.dave.pending_commit.is_none());
    assert!(state.dave.pending_welcome.is_none());
}

#[test]
fn dave_repeated_prepare_epoch_events_remain_distinct() {
    let mut state_tx = test_state_store();
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    for seq in [11, 12] {
        update_state(&mut state_tx, |state| {
            state.dave.proposals.push(vec![0xde]);
            state.dave.pending_commit = Some(vec![0xad]);
            state.dave.pending_welcome = Some(vec![0xbe]);
        });

        handle_voice_text_event(
            &mut state_tx,
            ParsedVoiceGatewayEvent {
                opcode: Opcode::DavePrepareEpoch.code(),
                seq: Some(seq),
                data: serde_json::from_str(r#"{"protocol_version":1,"epoch":1}"#).unwrap(),
            },
            &mut ack_pending,
            &mut heartbeat_sent_at,
            &NoopConnectionObserver,
        )
        .unwrap();
    }

    let state = state_tx.internal();
    assert_eq!(state.dave.protocol_version, Some(1));
    assert_eq!(state.dave.epoch, Some(1));
    assert_eq!(state.dave.prepare_epoch_seq, 2);
    assert!(state.dave.proposals.is_empty());
    assert!(state.dave.pending_commit.is_none());
    assert!(state.dave.pending_welcome.is_none());
}

#[test]
fn dave_initial_transition_zero_stays_pending_without_epoch_reset() {
    let mut state = DaveInternalState::default();

    state.prepare_transition(0, 1);

    assert_eq!(state.transition_id, Some(0));
    assert_eq!(state.epoch, None);
    assert_eq!(state.protocol_version, Some(1));
}

#[test]
fn dave_sole_member_reset_transition_zero_executes_immediately() {
    let mut state = DaveInternalState::default();
    state.prepare_epoch(1, 1);
    state.proposals.push(vec![0xde]);
    state.pending_commit = Some(vec![0xad]);
    state.pending_welcome = Some(vec![0xbe]);

    state.prepare_transition(0, 1);

    assert_eq!(state.transition_id, None);
    assert_eq!(state.epoch, Some(1));
    assert_eq!(state.protocol_version, Some(1));
    assert!(state.proposals.is_empty());
    assert!(state.pending_commit.is_none());
    assert!(state.pending_welcome.is_none());
}

#[test]
fn dave_transition_zero_media_ready_requires_local_ready_ack() {
    let mut state = DaveInternalState::default();
    state.prepare_transition(0, 1);

    assert!(!dave_transition_zero_media_ready(&state, None));
    assert!(dave_transition_zero_media_ready(&state, Some(0)));
    assert!(!dave_transition_zero_media_ready(&state, Some(1)));
}

#[test]
fn dave_send_media_ready_does_not_depend_on_consumed_transition_ack() {
    assert!(dave_send_media_ready(false, false, false, false));
    assert!(!dave_send_media_ready(true, false, true, true));
    assert!(!dave_send_media_ready(true, true, false, true));
    assert!(!dave_send_media_ready(true, true, true, false));
    assert!(dave_send_media_ready(true, true, true, true));
}

#[test]
fn dave_receive_transform_is_only_active_for_dave_media() {
    let mut state = DaveInternalState {
        passthrough: true,
        ..DaveInternalState::default()
    };
    assert!(!dave_receive_transform_active(&state));

    state.protocol_version = Some(1);
    assert!(!dave_receive_transform_active(&state));

    state.active_receive_protocol_version = Some(1);
    assert!(dave_receive_transform_active(&state));

    state.active_receive_protocol_version = Some(0);
    assert!(!dave_receive_transform_active(&state));
}

#[test]
fn dave_active_send_protocol_switches_only_on_execute() {
    let mut state = DaveInternalState::default();

    state.set_session_protocol(Some(1));
    assert_eq!(state.protocol_version, Some(1));
    assert_eq!(state.active_send_protocol_version, None);
    assert_eq!(state.active_receive_protocol_version, None);

    state.prepare_transition(7, 1);
    assert_eq!(state.protocol_version, Some(1));
    assert_eq!(state.active_send_protocol_version, None);
    assert_eq!(state.active_receive_protocol_version, None);

    state.execute_transition(7);
    assert_eq!(state.protocol_version, Some(1));
    assert_eq!(state.active_send_protocol_version, Some(1));
    assert_eq!(state.active_receive_protocol_version, Some(1));

    state.set_session_protocol(Some(1));
    assert_eq!(state.protocol_version, Some(1));
    assert_eq!(state.active_send_protocol_version, Some(1));
    assert_eq!(state.active_receive_protocol_version, Some(1));

    state.prepare_transition(7, 0);
    assert_eq!(state.protocol_version, Some(0));
    assert_eq!(state.active_send_protocol_version, Some(1));
    assert_eq!(state.active_receive_protocol_version, Some(1));

    state.execute_transition(7);
    assert_eq!(state.protocol_version, Some(0));
    assert_eq!(state.active_send_protocol_version, Some(0));
    assert_eq!(state.active_receive_protocol_version, Some(0));

    state.set_session_protocol(None);
    assert_eq!(state.protocol_version, None);
    assert_eq!(state.active_send_protocol_version, None);
    assert_eq!(state.active_receive_protocol_version, None);
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
    assert!(!dave_decrypt_failure_should_retry(
        ReceiveDecodeErrorKind::DaveNoValidCryptor,
        false
    ));
    assert!(dave_decrypt_failure_should_retry(
        ReceiveDecodeErrorKind::DaveNoValidCryptor,
        true
    ));
    assert!(!dave_decrypt_failure_should_retry(
        ReceiveDecodeErrorKind::DaveNoDecryptorForUser,
        false
    ));
    assert!(dave_decrypt_failure_should_retry(
        ReceiveDecodeErrorKind::DaveNoDecryptorForUser,
        true
    ));
    assert!(!dave_decrypt_failure_should_retry(
        ReceiveDecodeErrorKind::DaveUnencryptedWhenPassthroughDisabled,
        true
    ));
}

#[test]
fn dave_prepared_epoch_scope_includes_prepare_event_seq() {
    let mut first = DaveInternalState {
        protocol_version: Some(1),
        epoch: Some(1),
        prepare_epoch_seq: 1,
        ..DaveInternalState::default()
    };
    let second = DaveInternalState {
        prepare_epoch_seq: 2,
        ..first.clone()
    };

    assert_ne!(
        DavePreparedEpoch::from_state(&first),
        DavePreparedEpoch::from_state(&second)
    );

    first.prepare_epoch_seq = 2;
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
    update_state(&mut state_tx, |state| state.resumed = true);
    assert!(state_tx.internal().resumed);
}
