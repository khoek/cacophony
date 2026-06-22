use super::*;

const TEST_DISCORD_ID: u64 = 0xDEADBEEF;
const TEST_DISCORD_ID_JSON: &str = "3735928559";

fn test_state() -> VoiceConnectionInternalState {
    let selected_mode = VoiceEncryptionMode::aead_aes256_gcm_rtpsize();
    VoiceConnectionInternalState {
        config: VoiceConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1"),
        heartbeat_interval_ms: 50,
        last_seq: None,
        ready: VoiceGatewayReady {
            ssrc: 42,
            ip: "127.0.0.1".to_string(),
            port: 5000,
            modes: vec![selected_mode.clone()],
            heartbeat_interval: None,
        },
        discovery: VoiceUdpDiscoveryPacket {
            ssrc: 42,
            address: "127.0.0.1".to_string(),
            port: 5001,
        },
        selected_mode,
        session_description: Some(VoiceSessionDescription {
            mode: VoiceEncryptionMode::aead_aes256_gcm_rtpsize(),
            secret_key: VoiceSecretKey(vec![0; 32]),
            audio_codec: None,
            dave_protocol_version: Some(1),
        }),
        connected_user_ids: HashSet::new(),
        ssrc_users: HashMap::new(),
        speaking: HashMap::new(),
        dave: VoiceDaveInternalState::default(),
        roster_authoritative: false,
        resumed: false,
    }
}

fn test_state_channels() -> VoiceConnectionStateChannels {
    VoiceConnectionStateChannels::new(test_state())
}

async fn test_connection_with_state(
    state: VoiceConnectionInternalState,
) -> VoiceConnection<NoopVoiceConnectionObserver> {
    let state = VoiceConnectionStateChannels::new(state);
    let (command_tx, mut command_rx) = mpsc::channel::<VoiceConnectionCommand>(16);
    let close = VoiceConnectionClose::new();
    let task_close = close.clone();
    let task = tokio::spawn(async move {
        let mut commands = VecDeque::new();
        loop {
            tokio::select! {
                command = command_rx.recv() => {
                    match command {
                        Some(command) => commands.push_back(command),
                        None => break,
                    }
                }
                () = task_close.closed() => {
                    while let Ok(command) = command_rx.try_recv() {
                        commands.push_back(command);
                    }
                    while let Some(command) = commands.pop_front() {
                        command.complete_closed();
                    }
                    break;
                }
            }
        }
        Ok(())
    });
    let abort = task.abort_handle();
    let join_tx = spawn_voice_connection_join_task(task);
    VoiceConnection {
        inner: Arc::new(VoiceConnectionInner {
            state_rx: state.subscribe_public(),
            command_tx,
            close,
            join_tx,
            abort,
            observer: NoopVoiceConnectionObserver,
        }),
    }
}

async fn test_connection() -> VoiceConnection<NoopVoiceConnectionObserver> {
    test_connection_with_state(test_state()).await
}

#[test]
fn default_config_uses_davey_protocol_version() {
    assert_eq!(
        VoiceConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1")
            .max_dave_protocol_version,
        Some(DAVE_PROTOCOL_VERSION)
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
    assert!(matches!(result, Err(VoiceError::Closed)));
}

#[tokio::test]
async fn timed_receive_request_expires_without_consuming_future_media() {
    let (response, receive) = oneshot::channel();
    let request = PendingReceive::Frame {
        max_len: 1200,
        deadline: Some(Instant::now() - Duration::from_millis(1)),
        max_wait: Some(Duration::from_millis(1)),
        response,
    };

    assert!(request.is_expired(Instant::now()));
    request.complete_timeout();
    assert!(matches!(
        receive.await.unwrap(),
        Err(VoiceError::Timeout { stage: None, .. })
    ));
}

#[test]
fn abandoned_receive_request_is_inactive() {
    let (response, receive) = oneshot::channel();
    drop(receive);
    let request = PendingReceive::Frame {
        max_len: 1200,
        deadline: None,
        max_wait: None,
        response,
    };

    assert!(request.is_closed());
}

#[tokio::test]
async fn send_returns_closed_after_connection_closes() {
    let connection = test_connection().await;
    assert!(connection.close());
    assert!(matches!(
        connection.set_speaking(VoiceSpeakingFlags::MICROPHONE, 0),
        Err(VoiceError::Closed)
    ));
}

#[tokio::test]
async fn wait_until_media_ready_returns_closed_after_connection_closes() {
    let mut state = test_state();
    state.dave.protocol_version = Some(DAVE_PROTOCOL_VERSION);
    state.dave.passthrough = false;
    let connection = test_connection_with_state(state).await;

    assert!(connection.close());
    assert!(matches!(
        connection
            .wait_until_media_ready(Duration::from_secs(1))
            .await,
        Err(VoiceError::Closed)
    ));
}

#[test]
fn receive_rtp_reorders_adjacent_packets_without_loss() {
    let observer = TestReceiveObserver::default();
    let mut receive = VoiceReceiveState::default();

    assert_eq!(
        receive
            .push_media_frame(&observer, test_pending_media(7, 7))
            .unwrap()
            .rtp
            .seq,
        7
    );
    assert!(
        receive
            .push_media_frame(&observer, test_pending_media(7, 9))
            .is_none()
    );
    assert_eq!(observer.loss_count(), 0);
    assert_eq!(
        receive
            .push_media_frame(&observer, test_pending_media(7, 8))
            .unwrap()
            .rtp
            .seq,
        8
    );
    assert_eq!(receive.drain_ordered_media(&observer).unwrap().rtp.seq, 9);
    assert_eq!(
        receive
            .push_media_frame(&observer, test_pending_media(7, 10))
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
    let mut receive = VoiceReceiveState::default();

    assert_eq!(
        receive
            .push_media_frame(&observer, test_pending_media(7, 7))
            .unwrap()
            .rtp
            .seq,
        7
    );
    assert!(
        receive
            .push_media_frame(&observer, test_pending_media(7, 9))
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
        .detected_at = Instant::now() - RTP_REORDER_TTL - Duration::from_millis(1);

    assert_eq!(receive.drain_ordered_media(&observer).unwrap().rtp.seq, 9);
    assert_eq!(observer.loss_count(), 1);
    assert_eq!(observer.first_seq(), 8);
    assert_eq!(observer.last_seq(), 8);
    assert_eq!(observer.missing_packets(), 1);
}

#[test]
fn missing_dave_user_is_typed_error() {
    let mut session = VoiceDaveySession::discord_default(1, 2).unwrap();
    assert_eq!(
        session.decrypt_frame(None, b"frame").unwrap_err(),
        VoiceDaveDecryptError::MissingUser
    );
}

#[test]
fn dave_no_valid_cryptor_error_preserves_details() {
    let error = VoiceDaveDecryptError::from(DecryptError::DecryptionFailed(
        DecryptorDecryptError::NoValidCryptorFound {
            media_type: MediaType::AUDIO,
            encrypted_size: 12,
            plaintext_size: 8,
            manager_count: 2,
        },
    ));
    assert_eq!(
        error,
        VoiceDaveDecryptError::NoValidCryptor {
            media_type: VoiceDaveMediaType::Audio,
            encrypted_size: 12,
            plaintext_size: 8,
            manager_count: 2,
        }
    );
    assert_eq!(
        error.receive_decode_kind(),
        VoiceReceiveDecodeErrorKind::DaveNoValidCryptor
    );
}

#[test]
fn heartbeat_payload_includes_seq_ack() {
    let payload = VoiceGatewayCommand::Heartbeat(VoiceHeartbeatCommand {
        t: 123,
        seq_ack: Some(456),
    })
    .text_payload()
    .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"t":123,"seq_ack":456}}}}"#,
            VoiceOpcode::Heartbeat.code()
        )
    );
}

#[test]
fn voice_websocket_host_port_uses_discord_endpoint_port() {
    assert_eq!(
        voice_websocket_host_port("wss://c-syd05-e6e612f0.discord.media:2053/?v=8").unwrap(),
        ("c-syd05-e6e612f0.discord.media".to_string(), 2053)
    );
}

#[test]
fn voice_websocket_host_port_defaults_wss_to_443() {
    assert_eq!(
        voice_websocket_host_port("wss://example.discord.media/?v=8").unwrap(),
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
fn voice_udp_bind_addr_matches_remote_ip_family() {
    assert_eq!(
        voice_udp_bind_addr_for_remote("127.0.0.1".parse().unwrap()),
        "0.0.0.0:0".parse().unwrap()
    );
    assert_eq!(
        voice_udp_bind_addr_for_remote("::1".parse().unwrap()),
        "[::]:0".parse().unwrap()
    );
}

#[test]
fn discord_id_exposes_raw_snowflake() {
    assert_eq!(DiscordId::new(TEST_DISCORD_ID).get(), TEST_DISCORD_ID);
}

#[test]
fn dave_transition_ready_payload_contains_transition_id() {
    let payload =
        VoiceGatewayCommand::DaveProtocolTransitionReady(VoiceDaveTransitionReadyCommand {
            transition_id: 7,
        })
        .text_payload()
        .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"transition_id":7}}}}"#,
            VoiceOpcode::DaveTransitionReady.code()
        )
    );
}

#[test]
fn dave_transition_ready_payload_allows_initial_transition() {
    let payload =
        VoiceGatewayCommand::DaveProtocolTransitionReady(VoiceDaveTransitionReadyCommand {
            transition_id: 0,
        })
        .text_payload()
        .unwrap();
    assert_eq!(
        payload,
        format!(
            r#"{{"op":{},"d":{{"transition_id":0}}}}"#,
            VoiceOpcode::DaveTransitionReady.code()
        )
    );
}

#[test]
fn speaking_payload_matches_discord_shape() {
    let payload = VoiceGatewayCommand::Speaking(VoiceSpeakingCommand {
        speaking: VoiceSpeakingFlags::MICROPHONE.bits(),
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
            VoiceOpcode::Speaking.code()
        )
    );
}

#[test]
fn dave_mls_commands_do_not_have_json_fallback_payloads() {
    let error = VoiceGatewayCommand::DaveMlsKeyPackage {
        key_package: vec![0xde, 0xad],
    }
    .text_payload()
    .unwrap_err()
    .to_string();
    assert!(error.contains("binary websocket frames"));
}

#[test]
fn session_description_debug_and_json_do_not_expose_secret_key() {
    let description = VoiceSessionDescription {
        mode: VoiceEncryptionMode::aead_aes256_gcm_rtpsize(),
        secret_key: VoiceSecretKey(vec![0xde, 0xad, 0xbe, 0xef]),
        audio_codec: Some("opus".to_string()),
        dave_protocol_version: Some(1),
    };

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
    let config = VoiceConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1");
    let error = select_encryption_mode(
        &config,
        &VoiceGatewayReady {
            ssrc: 42,
            ip: "127.0.0.1".to_string(),
            port: 5000,
            modes: vec![VoiceEncryptionMode::new("xsalsa20_poly1305_lite")],
            heartbeat_interval: None,
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("supported encryption mode"));
}

#[test]
fn transport_crypto_round_trips_aes_gcm_rtpsize_packets() {
    transport_crypto_round_trips(VoiceEncryptionMode::aead_aes256_gcm_rtpsize());
}

#[test]
fn transport_crypto_round_trips_xchacha_rtpsize_packets() {
    transport_crypto_round_trips(VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize());
}

#[test]
fn transport_crypto_decrypts_packets_with_discord_rtp_extensions() {
    transport_crypto_decrypts_rtp_extensions(VoiceEncryptionMode::aead_aes256_gcm_rtpsize());
    transport_crypto_decrypts_rtp_extensions(VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize());
}

#[test]
fn transport_crypto_strips_rtp_padding_after_decrypt() {
    transport_crypto_strips_rtp_padding(VoiceEncryptionMode::aead_aes256_gcm_rtpsize());
    transport_crypto_strips_rtp_padding(VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize());
}

#[test]
fn raw_udp_packet_parses_rtcp_header() {
    let packet = VoiceRawUdpPacket::from_bytes(vec![0x81, 201, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef]);

    assert!(packet.is_rtcp());
    assert_eq!(
        packet.rtcp_header(),
        Some(VoiceRtcpHeader {
            version: 2,
            padding: false,
            report_count: 1,
            packet_type: 201,
            length_words: 7,
            ssrc: Some(0xdeadbeef),
        })
    );
}

fn transport_crypto_round_trips(mode: VoiceEncryptionMode) {
    let opus = b"opus-frame";
    let nonce_suffix = [0xde, 0xad, 0xbe, 0xef];
    let packet = encrypt_transport_payload(
        VoiceOutboundEncryptParams {
            seq: 10,
            timestamp: 20,
            ssrc: 30,
            payload_type: RTP_PAYLOAD_TYPE_OPUS,
            nonce_suffix,
        },
        opus,
        &mode,
        &[7; 32],
    )
    .unwrap();

    assert_eq!(
        packet.len(),
        12 + opus.len() + VOICE_AEAD_TAG_LEN + VOICE_RTPSIZE_NONCE_LEN
    );
    assert_eq!(
        &packet[packet.len() - VOICE_RTPSIZE_NONCE_LEN..],
        &nonce_suffix
    );

    let rtp = parse_rtp_header(&packet).unwrap();
    assert_eq!(
        decrypt_transport_payload(&packet, &rtp, &mode, &[7; 32]).unwrap(),
        opus
    );
}

fn transport_crypto_decrypts_rtp_extensions(mode: VoiceEncryptionMode) {
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

fn transport_crypto_strips_rtp_padding(mode: VoiceEncryptionMode) {
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
fn opus_round_trip_decodes_one_discord_frame() {
    let samples = (0..DISCORD_OPUS_STEREO_FRAME_SAMPLES)
        .map(|index| {
            let phase = index as f32 / DISCORD_OPUS_SAMPLE_RATE as f32 * std::f32::consts::TAU;
            phase.sin() * 0.1
        })
        .collect::<Vec<_>>();
    let frame = PcmFrame::discord_stereo_20ms(samples).unwrap();
    let opus = VoiceOpusEncoder::discord_music()
        .unwrap()
        .encode_pcm_frame(&frame)
        .unwrap();
    let mut decoder = VoiceOpusDecoder::discord_default().unwrap();
    let decoded = decoder
        .decode_frame(VoiceReceivedFrame {
            raw: VoiceRawUdpPacket::from_bytes(Vec::new()),
            rtp: VoiceRtpHeader {
                version: RTP_VERSION,
                padding: false,
                extension: false,
                marker: false,
                payload_type: RTP_PAYLOAD_TYPE_OPUS,
                seq: 0,
                timestamp: 0,
                ssrc: 0,
                header_len: 12,
                encrypted_body_offset: 12,
            },
            user_id: Some(1),
            media_type: VoiceDaveMediaType::Audio,
            codec: VoiceCodec::Opus,
            frame: opus.bytes,
        })
        .unwrap();

    assert_eq!(decoded.sample_rate, DISCORD_OPUS_SAMPLE_RATE);
    assert_eq!(decoded.channels, DISCORD_OPUS_CHANNELS);
    assert_eq!(
        decoded.samples_per_channel,
        DISCORD_OPUS_SAMPLES_PER_CHANNEL
    );
    assert_eq!(decoded.pcm.len(), DISCORD_OPUS_STEREO_FRAME_SAMPLES);
}

#[test]
fn opus_decoder_accepts_mono_discord_speech_frames() {
    let samples = (0..DISCORD_OPUS_SAMPLES_PER_CHANNEL)
        .map(|index| {
            let phase = index as f32 / DISCORD_OPUS_SAMPLE_RATE as f32 * std::f32::consts::TAU;
            phase.sin() * 0.1
        })
        .collect::<Vec<_>>();
    let mut encoder =
        RawOpusEncoder::new(DISCORD_OPUS_SAMPLE_RATE as i32, 1, OpusApplication::Voip).unwrap();
    let mut opus = vec![0; 4096];
    let written = encoder
        .encode(&samples, DISCORD_OPUS_SAMPLES_PER_CHANNEL, &mut opus)
        .unwrap();
    let mut decoder = VoiceOpusDecoder::discord_default().unwrap();
    let decoded = decoder
        .decode_frame(test_received_frame(opus[..written].to_vec()))
        .unwrap();

    assert_eq!(decoded.sample_rate, DISCORD_OPUS_SAMPLE_RATE);
    assert_eq!(decoded.channels, DISCORD_OPUS_CHANNELS);
    assert_eq!(
        decoded.samples_per_channel,
        DISCORD_OPUS_SAMPLES_PER_CHANNEL
    );
    assert_eq!(decoded.pcm.len(), DISCORD_OPUS_STEREO_FRAME_SAMPLES);
    for frame in decoded.pcm.chunks_exact(DISCORD_OPUS_CHANNELS) {
        assert_eq!(frame[0], frame[1]);
    }
}

#[derive(Clone, Default)]
struct TestReceiveObserver {
    loss_count: Arc<std::sync::atomic::AtomicUsize>,
    first_seq: Arc<std::sync::atomic::AtomicUsize>,
    last_seq: Arc<std::sync::atomic::AtomicUsize>,
    missing_packets: Arc<std::sync::atomic::AtomicUsize>,
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
}

impl VoiceConnectionObserver for TestReceiveObserver {
    const ENABLE_RECEIVE_TELEMETRY: bool = true;

    fn receive_rtp_packet_loss(&self, event: VoiceReceiveRtpPacketLossEvent) {
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
}

fn test_pending_media(ssrc: u32, seq: u16) -> PendingVoiceMediaFrame {
    PendingVoiceMediaFrame {
        raw: VoiceRawUdpPacket::from_bytes(Vec::new()),
        rtp: VoiceRtpHeader {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: false,
            payload_type: RTP_PAYLOAD_TYPE_OPUS,
            seq,
            timestamp: u32::from(seq) * DISCORD_OPUS_SAMPLES_PER_CHANNEL as u32,
            ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(TEST_DISCORD_ID),
        encrypted_frame: vec![seq as u8],
        dave: false,
        enqueued_at: Instant::now(),
        reason: VoiceDavePendingMediaReason::DecryptStatePending,
        was_pending: false,
    }
}

fn test_received_frame(frame: Vec<u8>) -> VoiceReceivedFrame {
    VoiceReceivedFrame {
        raw: VoiceRawUdpPacket::from_bytes(Vec::new()),
        rtp: VoiceRtpHeader {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: false,
            payload_type: RTP_PAYLOAD_TYPE_OPUS,
            seq: 0,
            timestamp: 0,
            ssrc: 0,
            header_len: 12,
            encrypted_body_offset: 12,
        },
        user_id: Some(1),
        media_type: VoiceDaveMediaType::Audio,
        codec: VoiceCodec::Opus,
        frame,
    }
}

struct TestEncryptedRtpPacket {
    bytes: Vec<u8>,
}

impl TestEncryptedRtpPacket {
    fn with_extension(
        mode: &VoiceEncryptionMode,
        key: &[u8; 32],
        nonce_suffix: [u8; 4],
        opus: &[u8],
    ) -> Self {
        let mut bytes = build_rtp_header(10, 20, 30, RTP_PAYLOAD_TYPE_OPUS);
        bytes[0] |= 0x10;
        bytes.extend_from_slice(&[0xbe, 0xde, 0x00, 0x01]);

        let aad = bytes.clone();
        let mut encrypted = Vec::from([0xca, 0xfe, 0xba, 0xbe]);
        encrypted.extend_from_slice(opus);

        if mode == &VoiceEncryptionMode::aead_aes256_gcm_rtpsize() {
            let cipher = Aes256Gcm::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 12];
            nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut encrypted)
                .unwrap();
            encrypted.extend_from_slice(&tag);
        } else {
            let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 24];
            nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
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
        mode: &VoiceEncryptionMode,
        key: &[u8; 32],
        nonce_suffix: [u8; 4],
        opus: &[u8],
    ) -> Self {
        let mut bytes = build_rtp_header(10, 20, 30, RTP_PAYLOAD_TYPE_OPUS);
        bytes[0] |= 0x20;

        let aad = bytes.clone();
        let mut encrypted = opus.to_vec();
        encrypted.extend_from_slice(&[0, 0, 3]);

        if mode == &VoiceEncryptionMode::aead_aes256_gcm_rtpsize() {
            let cipher = Aes256Gcm::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 12];
            nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut encrypted)
                .unwrap();
            encrypted.extend_from_slice(&tag);
        } else {
            let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
            let mut nonce = [0_u8; 24];
            nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&nonce_suffix);
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

#[test]
fn clients_connect_tracks_connected_user_roster() {
    let state_tx = test_state_channels();
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &state_tx,
        ParsedVoiceGatewayEvent {
            opcode: VoiceOpcode::ClientsConnect.code(),
            seq: Some(7),
            data: serde_json::from_str(&format!(r#"{{"user_ids":["{TEST_DISCORD_ID_JSON}"]}}"#))
                .unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopVoiceConnectionObserver,
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
    let state_tx = test_state_channels();
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &state_tx,
        ParsedVoiceGatewayEvent {
            opcode: VoiceOpcode::ClientConnect.code(),
            seq: None,
            data: serde_json::from_str(&format!(
                r#"{{"user_id":"{TEST_DISCORD_ID_JSON}","audio_ssrc":123,"video_ssrc":456}}"#,
            ))
            .unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopVoiceConnectionObserver,
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
    let state_tx = VoiceConnectionStateChannels::new({
        let mut state = test_state();
        state.connected_user_ids.insert(TEST_DISCORD_ID);
        state.ssrc_users.insert(123, TEST_DISCORD_ID);
        state.ssrc_users.insert(456, 1);
        state
    });
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    handle_voice_text_event(
        &state_tx,
        ParsedVoiceGatewayEvent {
            opcode: VoiceOpcode::ClientDisconnect.code(),
            seq: None,
            data: serde_json::from_str(&format!(r#"{{"user_id":"{TEST_DISCORD_ID_JSON}"}}"#))
                .unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopVoiceConnectionObserver,
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
fn hello_accepts_fractional_heartbeat_interval() {
    let hello: VoiceHelloData = serde_json::from_str(r#"{"heartbeat_interval":41250.5}"#).unwrap();
    assert_eq!(hello.heartbeat_interval_ms(), 41_251);
}

#[test]
fn dave_binary_parser_rejects_opcode_first_server_frames() {
    assert!(
        VoiceBinaryEvent::parse(&[
            VoiceOpcode::DaveMlsExternalSender.byte(),
            0xde,
            0xad,
            0xbe,
            0xef,
        ])
        .is_none()
    );
}

#[test]
fn dave_binary_parser_accepts_seq_prefixed_server_frames() {
    let bytes = [0, 7, VoiceOpcode::DaveMlsExternalSender.byte(), 0xde, 0xad];
    let event = VoiceBinaryEvent::parse(&bytes).unwrap();
    assert_eq!(event.seq, Some(7));
    assert_eq!(event.opcode, VoiceOpcode::DaveMlsExternalSender);
    assert_eq!(event.payload, &[0xde, 0xad]);
}

#[test]
fn dave_binary_parser_rejects_client_only_opcodes_from_server() {
    assert!(
        VoiceBinaryEvent::parse(&[0, 7, VoiceOpcode::DaveMlsKeyPackage.byte(), 0xde, 0xad,])
            .is_none()
    );
    assert!(
        VoiceBinaryEvent::parse(&[0, 7, VoiceOpcode::DaveMlsCommitWelcome.byte(), 0xde, 0xad,])
            .is_none()
    );
}

#[test]
fn dave_prepare_epoch_resets_epoch_without_transition_id() {
    let state_tx = VoiceConnectionStateChannels::new({
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
        &state_tx,
        ParsedVoiceGatewayEvent {
            opcode: VoiceOpcode::DavePrepareEpoch.code(),
            seq: Some(11),
            data: serde_json::from_str(r#"{"protocol_version":1,"epoch":1}"#).unwrap(),
        },
        &mut ack_pending,
        &mut heartbeat_sent_at,
        &NoopVoiceConnectionObserver,
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
    let state_tx = test_state_channels();
    let mut ack_pending = false;
    let mut heartbeat_sent_at = None;

    for seq in [11, 12] {
        update_state(&state_tx, |state| {
            state.dave.proposals.push(vec![0xde]);
            state.dave.pending_commit = Some(vec![0xad]);
            state.dave.pending_welcome = Some(vec![0xbe]);
        });

        handle_voice_text_event(
            &state_tx,
            ParsedVoiceGatewayEvent {
                opcode: VoiceOpcode::DavePrepareEpoch.code(),
                seq: Some(seq),
                data: serde_json::from_str(r#"{"protocol_version":1,"epoch":1}"#).unwrap(),
            },
            &mut ack_pending,
            &mut heartbeat_sent_at,
            &NoopVoiceConnectionObserver,
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
    let mut state = VoiceDaveInternalState::default();

    state.prepare_transition(0, 1);

    assert_eq!(state.transition_id, Some(0));
    assert_eq!(state.epoch, None);
    assert_eq!(state.protocol_version, Some(1));
}

#[test]
fn dave_sole_member_reset_transition_zero_executes_immediately() {
    let mut state = VoiceDaveInternalState::default();
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
    let mut state = VoiceDaveInternalState::default();
    state.prepare_transition(0, 1);

    assert!(!voice_dave_transition_zero_media_ready(&state, None));
    assert!(voice_dave_transition_zero_media_ready(&state, Some(0)));
    assert!(!voice_dave_transition_zero_media_ready(&state, Some(1)));
}

#[test]
fn receive_interarrival_stats_use_bounded_sorted_window() {
    let mut state = VoiceReceiveSsrcState::default();
    for interarrival_us in 0..(RECEIVE_INTERARRIVAL_WINDOW as u64 + 10) {
        state.record_interarrival(interarrival_us);
    }

    assert_eq!(state.interarrival_order.len(), RECEIVE_INTERARRIVAL_WINDOW);
    assert_eq!(state.interarrival_sorted.len(), RECEIVE_INTERARRIVAL_WINDOW);
    assert_eq!(state.interarrival_p95_us(), Some(252));
    assert_eq!(state.interarrival_max_us(), Some(265));
}

#[test]
fn dave_no_valid_cryptor_retries_only_while_state_can_still_change() {
    assert!(!voice_dave_decrypt_failure_should_retry(
        VoiceReceiveDecodeErrorKind::DaveNoValidCryptor,
        false
    ));
    assert!(voice_dave_decrypt_failure_should_retry(
        VoiceReceiveDecodeErrorKind::DaveNoValidCryptor,
        true
    ));
    assert!(!voice_dave_decrypt_failure_should_retry(
        VoiceReceiveDecodeErrorKind::DaveNoDecryptorForUser,
        false
    ));
    assert!(voice_dave_decrypt_failure_should_retry(
        VoiceReceiveDecodeErrorKind::DaveNoDecryptorForUser,
        true
    ));
    assert!(!voice_dave_decrypt_failure_should_retry(
        VoiceReceiveDecodeErrorKind::DaveUnencryptedWhenPassthroughDisabled,
        true
    ));
}

#[test]
fn dave_prepared_epoch_scope_includes_prepare_event_seq() {
    let mut first = VoiceDaveInternalState {
        protocol_version: Some(1),
        epoch: Some(1),
        prepare_epoch_seq: 1,
        ..VoiceDaveInternalState::default()
    };
    let second = VoiceDaveInternalState {
        prepare_epoch_seq: 2,
        ..first.clone()
    };

    assert_ne!(
        VoiceDavePreparedEpoch::from_state(&first),
        VoiceDavePreparedEpoch::from_state(&second)
    );

    first.prepare_epoch_seq = 2;
    assert_eq!(
        VoiceDavePreparedEpoch::from_state(&first),
        VoiceDavePreparedEpoch::from_state(&second)
    );
}

#[test]
fn state_updates_do_not_require_subscribers() {
    let state_tx = test_state_channels();
    let state_rx = state_tx.subscribe_public();
    drop(state_rx);
    update_state(&state_tx, |state| state.resumed = true);
    assert!(state_tx.internal().resumed);
}
