use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceRawUdpPacket {
    pub bytes: Vec<u8>,
    pub version: Option<u8>,
    pub raw_payload_type: Option<u8>,
    pub payload_type: Option<u8>,
    pub seq: Option<u16>,
    pub timestamp: Option<u32>,
    pub ssrc: Option<u32>,
}

impl VoiceRawUdpPacket {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let raw_payload_type = bytes.get(1).copied();
        let (version, seq, timestamp, ssrc) = if bytes.len() >= 12 {
            (
                Some(bytes[0] >> 6),
                Some(u16::from_be_bytes([bytes[2], bytes[3]])),
                Some(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])),
                Some(u32::from_be_bytes([
                    bytes[8], bytes[9], bytes[10], bytes[11],
                ])),
            )
        } else {
            (None, None, None, None)
        };

        Self {
            bytes,
            version,
            raw_payload_type,
            payload_type: raw_payload_type.map(|byte| byte & 0x7f),
            seq,
            timestamp,
            ssrc,
        }
    }

    pub fn is_rtcp(&self) -> bool {
        self.raw_payload_type
            .is_some_and(|payload_type| (192..=223).contains(&payload_type))
    }

    pub fn rtcp_header(&self) -> Option<VoiceRtcpHeader> {
        if !self.is_rtcp() || self.bytes.len() < 4 {
            return None;
        }
        Some(VoiceRtcpHeader {
            version: self.bytes[0] >> 6,
            padding: self.bytes[0] & 0x20 != 0,
            report_count: self.bytes[0] & 0x1f,
            packet_type: self.bytes[1],
            length_words: u16::from_be_bytes([self.bytes[2], self.bytes[3]]),
            ssrc: (self.bytes.len() >= 8).then(|| {
                u32::from_be_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]])
            }),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceRtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub marker: bool,
    pub payload_type: u8,
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub header_len: usize,
    pub encrypted_body_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceReceivedFrame {
    pub raw: VoiceRawUdpPacket,
    pub rtp: VoiceRtpHeader,
    pub user_id: Option<u64>,
    pub media_type: VoiceDaveMediaType,
    pub codec: VoiceCodec,
    pub frame: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceDecodedFrame {
    pub frame: VoiceReceivedFrame,
    pub sample_rate: u32,
    pub channels: usize,
    pub samples_per_channel: usize,
    pub pcm: Vec<i16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceCodec {
    Opus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceOpusFrame {
    pub bytes: Vec<u8>,
    pub duration: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcmFrame {
    samples: Vec<f32>,
    sample_rate: u32,
    channels: usize,
    duration: Duration,
}

impl PcmFrame {
    pub fn discord_stereo_20ms(samples: impl Into<Vec<f32>>) -> VoiceResult<Self> {
        let samples = samples.into();
        if samples.len() != DISCORD_OPUS_STEREO_FRAME_SAMPLES {
            return Err(VoiceError::invalid_input(format!(
                "PCM frame must contain {DISCORD_OPUS_STEREO_FRAME_SAMPLES} interleaved f32 samples"
            )));
        }

        Ok(Self {
            samples,
            sample_rate: DISCORD_OPUS_SAMPLE_RATE,
            channels: DISCORD_OPUS_CHANNELS,
            duration: Duration::from_millis(DISCORD_OPUS_FRAME_MS),
        })
    }

    fn samples(&self) -> &[f32] {
        &self.samples
    }

    fn samples_per_channel(&self) -> usize {
        self.samples.len() / self.channels
    }
}

pub struct VoiceOpusEncoder {
    encoder: RawOpusEncoder,
    output: Vec<u8>,
}

impl VoiceOpusEncoder {
    pub fn discord_music() -> VoiceResult<Self> {
        let mut encoder = RawOpusEncoder::new(
            DISCORD_OPUS_SAMPLE_RATE as i32,
            DISCORD_OPUS_CHANNELS,
            OpusApplication::Audio,
        )
        .map_err(|error| VoiceError::opus(format!("failed to create Opus encoder: {error}")))?;
        encoder.bitrate_bps = 128_000;
        encoder.use_cbr = true;

        Ok(Self {
            encoder,
            output: vec![0; 4096],
        })
    }

    pub fn encode_pcm_frame(&mut self, frame: &PcmFrame) -> VoiceResult<VoiceOpusFrame> {
        if frame.sample_rate != DISCORD_OPUS_SAMPLE_RATE
            || frame.channels != DISCORD_OPUS_CHANNELS
            || frame.samples_per_channel() != DISCORD_OPUS_SAMPLES_PER_CHANNEL
            || frame.duration != Duration::from_millis(DISCORD_OPUS_FRAME_MS)
        {
            return Err(VoiceError::invalid_input(
                "Opus encoder requires 48kHz stereo 20ms PCM frames",
            ));
        }

        let written = self
            .encoder
            .encode(
                frame.samples(),
                DISCORD_OPUS_SAMPLES_PER_CHANNEL,
                &mut self.output,
            )
            .map_err(|error| VoiceError::opus(format!("failed to encode Opus frame: {error}")))?;
        Ok(VoiceOpusFrame {
            bytes: self.output[..written].to_vec(),
            duration: frame.duration,
        })
    }
}

pub struct VoiceOpusDecoder {
    mono_decoder: RawOpusDecoder,
    stereo_decoder: RawOpusDecoder,
    decoded_f32: Vec<f32>,
    sample_rate: u32,
    max_samples_per_channel: usize,
}

impl VoiceOpusDecoder {
    pub fn discord_default() -> VoiceResult<Self> {
        let mono_decoder =
            RawOpusDecoder::new(DISCORD_OPUS_SAMPLE_RATE as i32, 1).map_err(|error| {
                VoiceError::opus(format!("failed to create mono Opus decoder: {error}"))
            })?;
        let stereo_decoder =
            RawOpusDecoder::new(DISCORD_OPUS_SAMPLE_RATE as i32, DISCORD_OPUS_CHANNELS).map_err(
                |error| VoiceError::opus(format!("failed to create Opus decoder: {error}")),
            )?;
        Ok(Self {
            max_samples_per_channel: DISCORD_OPUS_SAMPLES_PER_CHANNEL,
            mono_decoder,
            stereo_decoder,
            decoded_f32: Vec::new(),
            sample_rate: DISCORD_OPUS_SAMPLE_RATE,
        })
    }

    pub fn decode_frame(&mut self, frame: VoiceReceivedFrame) -> VoiceResult<VoiceDecodedFrame> {
        let mut pcm = Vec::new();
        let metadata = self.decode_frame_into(frame, &mut pcm)?;
        Ok(VoiceDecodedFrame {
            frame: metadata.frame,
            sample_rate: metadata.sample_rate,
            channels: metadata.channels,
            samples_per_channel: metadata.samples_per_channel,
            pcm,
        })
    }

    pub fn decode_frame_into(
        &mut self,
        frame: VoiceReceivedFrame,
        pcm: &mut Vec<i16>,
    ) -> VoiceResult<VoiceDecodedFrameMetadata> {
        if frame.codec != VoiceCodec::Opus {
            return Err(VoiceError::opus(format!(
                "unsupported voice codec {:?}",
                frame.codec
            )));
        }
        let channels = opus_frame_channels(&frame.frame)?;
        self.decoded_f32
            .resize(self.max_samples_per_channel * channels, 0.0);
        let decoder = match channels {
            1 => &mut self.mono_decoder,
            DISCORD_OPUS_CHANNELS => &mut self.stereo_decoder,
            _ => {
                return Err(VoiceError::opus(format!(
                    "unsupported Opus channel count {channels}"
                )));
            }
        };
        let samples_per_channel = decoder
            .decode(
                &frame.frame,
                self.max_samples_per_channel,
                &mut self.decoded_f32,
            )
            .map_err(|error| VoiceError::opus(format!("failed to decode Opus frame: {error}")))?;
        let decoded_len = samples_per_channel * channels;
        self.decoded_f32.truncate(decoded_len);
        pcm.clear();
        pcm.reserve(samples_per_channel * DISCORD_OPUS_CHANNELS);
        if channels == 1 {
            for sample in &self.decoded_f32 {
                let sample = pcm_f32_to_i16(*sample);
                pcm.extend_from_slice(&[sample, sample]);
            }
        } else {
            pcm.extend(
                self.decoded_f32
                    .iter()
                    .map(|sample| pcm_f32_to_i16(*sample)),
            );
        }

        Ok(VoiceDecodedFrameMetadata {
            frame,
            sample_rate: self.sample_rate,
            channels: DISCORD_OPUS_CHANNELS,
            samples_per_channel,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceDecodedFrameMetadata {
    pub frame: VoiceReceivedFrame,
    pub sample_rate: u32,
    pub channels: usize,
    pub samples_per_channel: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceOutboundPacket {
    pub rtp: VoiceRtpHeader,
    pub nonce_suffix: [u8; 4],
    pub opus_bytes: usize,
    pub packet_bytes: usize,
}

pub(crate) struct VoiceBuiltOutboundPacket {
    pub(crate) metadata: VoiceOutboundPacket,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VoiceOutboundRtpState {
    seq: u16,
    timestamp: u32,
    nonce_suffix: u32,
    ssrc: u32,
    payload_type: u8,
    sample_rate: u32,
}

impl VoiceOutboundRtpState {
    pub(crate) fn new(ssrc: u32) -> Self {
        Self {
            seq: 0,
            timestamp: 0,
            nonce_suffix: initial_voice_heartbeat_nonce() as u32,
            ssrc,
            payload_type: RTP_PAYLOAD_TYPE_OPUS,
            sample_rate: DISCORD_OPUS_SAMPLE_RATE,
        }
    }

    pub(crate) fn build_packet(
        &mut self,
        frame: &[u8],
        duration: Duration,
        mode: &VoiceEncryptionMode,
        secret_key: &[u8],
    ) -> VoiceResult<VoiceBuiltOutboundPacket> {
        if frame.is_empty() {
            return Err(VoiceError::invalid_input("opus frame must not be empty"));
        }

        let seq = self.seq;
        let timestamp = self.timestamp;
        let nonce_suffix = self.nonce_suffix.to_be_bytes();
        let packet = encrypt_transport_payload(
            VoiceOutboundEncryptParams {
                seq,
                timestamp,
                ssrc: self.ssrc,
                payload_type: self.payload_type,
                nonce_suffix,
            },
            frame,
            mode,
            secret_key,
        )?;
        let rtp = parse_rtp_header(&packet)?;

        self.seq = self.seq.wrapping_add(1);
        self.timestamp = self
            .timestamp
            .wrapping_add(timestamp_increment(self.sample_rate, duration));
        self.nonce_suffix = self.nonce_suffix.wrapping_add(1);

        Ok(VoiceBuiltOutboundPacket {
            metadata: VoiceOutboundPacket {
                rtp,
                nonce_suffix,
                opus_bytes: frame.len(),
                packet_bytes: packet.len(),
            },
            bytes: packet,
        })
    }
}

pub(crate) fn decrypted_rtp_payload(
    encrypted: Vec<u8>,
    opus_offset: usize,
    rtp: &VoiceRtpHeader,
) -> Result<Vec<u8>, VoiceRtpError> {
    let mut payload = encrypted
        .get(opus_offset..)
        .map(Vec::from)
        .ok_or(VoiceRtpError::TruncatedEncryptedExtension)?;
    if rtp.padding {
        let padding = usize::from(*payload.last().ok_or(VoiceRtpError::EmptyPaddedPayload)?);
        if padding == 0 || padding > payload.len() {
            return Err(VoiceRtpError::InvalidPadding {
                padding,
                payload_len: payload.len(),
            });
        }
        payload.truncate(payload.len() - padding);
    }
    Ok(payload)
}

pub(crate) fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn parse_rtp_header(bytes: &[u8]) -> Result<VoiceRtpHeader, VoiceRtpError> {
    if bytes.len() < 12 {
        return Err(VoiceRtpError::PacketTooShort { len: bytes.len() });
    }

    let extension = bytes[0] & 0x10 != 0;
    let csrc_count = usize::from(bytes[0] & 0x0f);
    let mut header_len = 12 + csrc_count * 4;
    if bytes.len() < header_len {
        return Err(VoiceRtpError::TruncatedCsrcList {
            len: bytes.len(),
            expected_header_len: header_len,
        });
    }

    let mut encrypted_body_offset = header_len;
    if extension {
        if bytes.len() < header_len + 4 {
            return Err(VoiceRtpError::TruncatedExtensionHeader {
                len: bytes.len(),
                expected_header_len: header_len + 4,
            });
        }
        encrypted_body_offset += 4;
        let extension_words = usize::from(u16::from_be_bytes([
            bytes[header_len + 2],
            bytes[header_len + 3],
        ]));
        header_len += 4 + extension_words * 4;
        if bytes.len() < header_len {
            return Err(VoiceRtpError::TruncatedExtensionPayload {
                len: bytes.len(),
                expected_header_len: header_len,
            });
        }
    }

    Ok(VoiceRtpHeader {
        version: bytes[0] >> 6,
        padding: bytes[0] & 0x20 != 0,
        extension,
        marker: bytes[1] & 0x80 != 0,
        payload_type: bytes[1] & 0x7f,
        seq: u16::from_be_bytes([bytes[2], bytes[3]]),
        timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ssrc: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        header_len,
        encrypted_body_offset,
    })
}

pub(crate) fn decrypt_transport_payload(
    packet: &[u8],
    rtp: &VoiceRtpHeader,
    mode: &VoiceEncryptionMode,
    secret_key: &[u8],
) -> VoiceResult<Vec<u8>> {
    if secret_key.len() != 32 {
        return Err(VoiceTransportCryptoError::InvalidSecretKeyLen {
            len: secret_key.len(),
        }
        .into());
    }
    if packet.len() < rtp.encrypted_body_offset + VOICE_AEAD_TAG_LEN + VOICE_RTPSIZE_NONCE_LEN {
        return Err(VoiceTransportCryptoError::MissingRtpSizeNonce {
            packet_len: packet.len(),
            min_len: rtp.encrypted_body_offset + VOICE_AEAD_TAG_LEN + VOICE_RTPSIZE_NONCE_LEN,
        }
        .into());
    }

    let nonce_suffix_offset = packet.len() - VOICE_RTPSIZE_NONCE_LEN;
    let tag_offset = nonce_suffix_offset - VOICE_AEAD_TAG_LEN;
    let nonce_suffix = &packet[nonce_suffix_offset..];
    let tag = &packet[tag_offset..nonce_suffix_offset];
    let aad = &packet[..rtp.encrypted_body_offset];
    let mut encrypted = packet[rtp.encrypted_body_offset..tag_offset].to_vec();
    let opus_offset = rtp.header_len - rtp.encrypted_body_offset;

    if mode == &VoiceEncryptionMode::aead_aes256_gcm_rtpsize() {
        let cipher = Aes256Gcm::new_from_slice(secret_key)
            .map_err(|_| VoiceTransportCryptoError::InvalidAesGcmKey)?;
        let mut nonce = [0_u8; 12];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(nonce_suffix);
        cipher
            .decrypt_in_place_detached(
                AesNonce::from_slice(&nonce),
                aad,
                &mut encrypted,
                AesTag::from_slice(tag),
            )
            .map_err(|_| VoiceTransportCryptoError::AesGcmDecryptFailed)?;
        return decrypted_rtp_payload(encrypted, opus_offset, rtp).map_err(Into::into);
    }

    if mode == &VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize() {
        let cipher = XChaCha20Poly1305::new_from_slice(secret_key)
            .map_err(|_| VoiceTransportCryptoError::InvalidXChaCha20Poly1305Key)?;
        let mut nonce = [0_u8; 24];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(nonce_suffix);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                aad,
                &mut encrypted,
                XTag::from_slice(tag),
            )
            .map_err(|_| VoiceTransportCryptoError::XChaCha20Poly1305DecryptFailed)?;
        return decrypted_rtp_payload(encrypted, opus_offset, rtp).map_err(Into::into);
    }

    Err(VoiceTransportCryptoError::UnsupportedMode {
        mode: mode.clone(),
        direction: VoiceTransportCryptoDirection::Receive,
    }
    .into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceOutboundEncryptParams {
    pub(crate) seq: u16,
    pub(crate) timestamp: u32,
    pub(crate) ssrc: u32,
    pub(crate) payload_type: u8,
    pub(crate) nonce_suffix: [u8; 4],
}

pub(crate) fn encrypt_transport_payload(
    params: VoiceOutboundEncryptParams,
    frame: &[u8],
    mode: &VoiceEncryptionMode,
    secret_key: &[u8],
) -> VoiceResult<Vec<u8>> {
    if secret_key.len() != 32 {
        return Err(VoiceTransportCryptoError::InvalidSecretKeyLen {
            len: secret_key.len(),
        }
        .into());
    }

    let mut packet = build_rtp_header(
        params.seq,
        params.timestamp,
        params.ssrc,
        params.payload_type,
    );
    let aad = packet.clone();
    let mut encrypted = frame.to_vec();

    if mode == &VoiceEncryptionMode::aead_aes256_gcm_rtpsize() {
        let cipher = Aes256Gcm::new_from_slice(secret_key)
            .map_err(|_| VoiceTransportCryptoError::InvalidAesGcmKey)?;
        let mut nonce = [0_u8; 12];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&params.nonce_suffix);
        let tag = cipher
            .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut encrypted)
            .map_err(|_| VoiceTransportCryptoError::AesGcmEncryptFailed)?;
        encrypted.extend_from_slice(&tag);
    } else if mode == &VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize() {
        let cipher = XChaCha20Poly1305::new_from_slice(secret_key)
            .map_err(|_| VoiceTransportCryptoError::InvalidXChaCha20Poly1305Key)?;
        let mut nonce = [0_u8; 24];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&params.nonce_suffix);
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut encrypted)
            .map_err(|_| VoiceTransportCryptoError::XChaCha20Poly1305EncryptFailed)?;
        encrypted.extend_from_slice(&tag);
    } else {
        return Err(VoiceTransportCryptoError::UnsupportedMode {
            mode: mode.clone(),
            direction: VoiceTransportCryptoDirection::Send,
        }
        .into());
    }

    packet.extend_from_slice(&encrypted);
    packet.extend_from_slice(&params.nonce_suffix);
    Ok(packet)
}

pub(crate) fn build_rtp_header(seq: u16, timestamp: u32, ssrc: u32, payload_type: u8) -> Vec<u8> {
    let mut packet = vec![RTP_VERSION << 6, payload_type & 0x7f];
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet
}

pub(crate) fn timestamp_increment(sample_rate: u32, duration: Duration) -> u32 {
    let samples = (u128::from(sample_rate) * duration.as_nanos()) / 1_000_000_000;
    samples.max(1).min(u128::from(u32::MAX)) as u32
}

pub(crate) fn initial_voice_heartbeat_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64 % JS_MAX_SAFE_INTEGER)
        .unwrap_or(0)
}

pub(crate) fn next_voice_heartbeat_nonce(current: &mut u64) -> u64 {
    *current = current.wrapping_add(1) % JS_MAX_SAFE_INTEGER;
    *current
}

pub(crate) fn select_encryption_mode(
    config: &VoiceConnectionConfig,
    ready: &VoiceGatewayReady,
) -> VoiceResult<VoiceEncryptionMode> {
    if let Some(preferred_mode) = &config.preferred_mode
        && ready.modes.contains(preferred_mode)
    {
        return Ok(preferred_mode.clone());
    }

    for mode in [
        VoiceEncryptionMode::aead_aes256_gcm_rtpsize(),
        VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize(),
    ] {
        if ready.modes.contains(&mode) {
            return Ok(mode);
        }
    }

    if ready.modes.is_empty() {
        return Err(VoiceError::protocol(
            "voice ready payload did not include encryption modes",
        ));
    }
    Err(VoiceError::protocol(format!(
        "voice ready payload did not include a supported encryption mode: {:?}",
        ready.modes
    )))
}

pub(crate) fn update_state(
    channels: &VoiceConnectionStateChannels,
    update: impl FnOnce(&mut VoiceConnectionInternalState),
) {
    channels.update(update);
}

pub(crate) async fn connect_voice_websocket(
    websocket_url: &str,
) -> VoiceResult<VoiceWebSocketConnectResult> {
    let (host, port) = voice_websocket_host_port(websocket_url)?;
    let addresses = ordered_voice_socket_addrs(
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| {
                VoiceError::protocol(format!(
                    "resolve voice websocket endpoint {host}:{port}: {error}",
                ))
            })?,
    );
    if addresses.is_empty() {
        return Err(VoiceError::protocol(format!(
            "voice websocket endpoint {host}:{port} did not resolve to any addresses",
        )));
    }

    let mut attempts = FuturesUnordered::new();
    for (index, address) in addresses.iter().copied().enumerate() {
        let websocket_url = websocket_url.to_string();
        attempts.push(async move {
            if index > 0 {
                sleep(VOICE_WEBSOCKET_ADDRESS_STAGGER.saturating_mul(index as u32)).await;
            }
            match timeout(
                VOICE_WEBSOCKET_ADDRESS_CONNECT_TIMEOUT,
                connect_voice_websocket_address(websocket_url, address),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(VoiceError::protocol(format!(
                    "voice websocket connect to {address} timed out after {:?}",
                    VOICE_WEBSOCKET_ADDRESS_CONNECT_TIMEOUT
                ))),
            }
        });
    }

    let mut errors = Vec::new();
    while let Some(result) = attempts.next().await {
        match result {
            Ok(connection) => return Ok(connection),
            Err(error) => errors.push(error.to_string()),
        }
    }

    Err(VoiceError::protocol(format!(
        "voice websocket connect to {host}:{port} failed across {} resolved addresses: {}",
        addresses.len(),
        errors.join("; ")
    )))
}

pub(crate) async fn connect_voice_websocket_address(
    websocket_url: String,
    address: SocketAddr,
) -> VoiceResult<VoiceWebSocketConnectResult> {
    let socket = TcpStream::connect(address)
        .await
        .map_err(|error| VoiceError::protocol(format!("tcp connect {address}: {error}")))?;
    socket.set_nodelay(true)?;
    client_async_tls_with_config(websocket_url, socket, None, None)
        .await
        .map_err(Into::into)
}

pub(crate) fn voice_websocket_host_port(websocket_url: &str) -> VoiceResult<(String, u16)> {
    let request = websocket_url.into_client_request()?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| VoiceError::protocol("voice websocket URL did not include a host"))?
        .to_string();
    let port = uri
        .port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or_else(|| {
            VoiceError::protocol("voice websocket URL did not include a usable scheme")
        })?;
    Ok((host, port))
}

pub(crate) fn ordered_voice_socket_addrs(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for addr in addrs {
        let bucket = if addr.is_ipv4() { &mut ipv4 } else { &mut ipv6 };
        if !bucket.contains(&addr) {
            bucket.push(addr);
        }
    }
    ipv4.extend(ipv6);
    ipv4
}

pub(crate) fn voice_udp_bind_addr_for_remote(remote: IpAddr) -> SocketAddr {
    SocketAddr::new(
        match remote {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    )
}

pub(crate) async fn bind_voice_udp_socket(remote_ip: &str) -> VoiceResult<UdpSocket> {
    let remote = remote_ip.parse::<IpAddr>().map_err(|error| {
        VoiceError::protocol(format!(
            "invalid Discord voice UDP IP {remote_ip:?}: {error}"
        ))
    })?;
    Ok(UdpSocket::bind(voice_udp_bind_addr_for_remote(remote)).await?)
}

pub(crate) fn opus_frame_channels(frame: &[u8]) -> VoiceResult<usize> {
    let Some(toc) = frame.first() else {
        return Err(VoiceError::opus("Opus frame is empty"));
    };
    Ok(if toc & 0x04 != 0 { 2 } else { 1 })
}

pub(crate) fn pcm_f32_to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)).round() as i16
}
