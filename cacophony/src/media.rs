use std::{
    fmt,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce, Tag as AesTag,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use dave::MediaType;
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};
use tokio_tungstenite::{client_async_tls_with_config, tungstenite::client::IntoClientRequest};
use zeroize::Zeroizing;

use crate::{
    AEAD_TAG_LEN, GatewayWebSocketConnectResult, JS_MAX_SAFE_INTEGER, RTP_VERSION,
    RTPSIZE_NONCE_LEN, WEBSOCKET_ADDRESS_CONNECT_TIMEOUT, WEBSOCKET_ADDRESS_STAGGER,
    connection::ConnectionStateStore,
    errors::{
        Error, InvalidInputError, ProtocolError, Result, RtpError, TransportCryptoDirection,
        TransportCryptoError, UnsupportedCodecError,
    },
    gateway::GatewayReady,
    observer::RtcpHeader,
    state::{ConnectionInternalState, ConnectionOptions, EncryptionMode, SessionDescription},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawUdpPacket {
    pub bytes: Vec<u8>,
    pub info: RawUdpPacketInfo,
}

impl RawUdpPacket {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let info = RawUdpPacketInfo::from_bytes(&bytes);
        Self::from_parts(bytes, info)
    }

    pub fn from_parts(bytes: Vec<u8>, info: RawUdpPacketInfo) -> Self {
        Self { bytes, info }
    }

    pub fn is_rtcp(&self) -> bool {
        self.info.is_rtcp()
    }

    pub fn rtcp_header(&self) -> Option<RtcpHeader> {
        self.info.rtcp_header(&self.bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawUdpPacketInfo {
    pub version: Option<u8>,
    pub raw_payload_type: Option<u8>,
    pub payload_type: Option<u8>,
    pub seq: Option<u16>,
    pub timestamp: Option<u32>,
    pub ssrc: Option<u32>,
}

impl RawUdpPacketInfo {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let raw_payload_type = bytes.get(1).copied();
        if let Some(header) = RtpFixedHeader::parse(bytes) {
            Self {
                version: Some(header.version),
                raw_payload_type,
                payload_type: Some(header.payload_type),
                seq: Some(header.seq),
                timestamp: Some(header.timestamp),
                ssrc: Some(header.ssrc),
            }
        } else {
            Self {
                version: None,
                raw_payload_type,
                payload_type: raw_payload_type.map(|byte| byte & 0x7f),
                seq: None,
                timestamp: None,
                ssrc: None,
            }
        }
    }

    pub fn is_rtcp(self) -> bool {
        self.raw_payload_type
            .is_some_and(|payload_type| (192..=223).contains(&payload_type))
    }

    pub fn rtcp_header(self, bytes: &[u8]) -> Option<RtcpHeader> {
        if !self.is_rtcp() || bytes.len() < 4 {
            return None;
        }
        Some(RtcpHeader {
            version: bytes[0] >> 6,
            padding: bytes[0] & 0x20 != 0,
            report_count: bytes[0] & 0x1f,
            packet_type: bytes[1],
            length_words: u16::from_be_bytes([bytes[2], bytes[3]]),
            ssrc: (bytes.len() >= 8)
                .then(|| u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])),
        })
    }

    pub fn into_raw_packet(self, bytes: &[u8]) -> RawUdpPacket {
        RawUdpPacket::from_parts(bytes.to_vec(), self)
    }
}

pub trait FrameRaw: Send + Sync + 'static {
    type Packet: Send + Sync + 'static;

    fn capture_packet(bytes: &[u8], info: RawUdpPacketInfo) -> Self::Packet;
    fn from_rtp_packet<C>(packet: Self::Packet) -> Self
    where
        C: RtpPayloadCodec;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoRawPackets;

impl FrameRaw for NoRawPackets {
    type Packet = ();

    fn capture_packet(_bytes: &[u8], _info: RawUdpPacketInfo) -> Self::Packet {}

    fn from_rtp_packet<C>(_packet: Self::Packet) -> Self
    where
        C: RtpPayloadCodec,
    {
        Self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawFramePackets {
    pub packets: Vec<RawUdpPacket>,
}

impl FrameRaw for RawFramePackets {
    type Packet = RawUdpPacket;

    fn capture_packet(bytes: &[u8], info: RawUdpPacketInfo) -> Self::Packet {
        info.into_raw_packet(bytes)
    }

    fn from_rtp_packet<C>(packet: Self::Packet) -> Self
    where
        C: RtpPayloadCodec,
    {
        Self {
            packets: vec![packet],
        }
    }
}

pub trait RtpPayloadCodec: Copy + Send + Sync + 'static {
    const CODEC: MediaCodec;
    const DISCORD_PAYLOAD_TYPE: u8;
    const SAMPLE_RATE_HZ: u32;
}

pub trait EncryptedMediaCodec: RtpPayloadCodec {
    type DaveCodec: dave::FrameCodec;
}

pub trait RtpPayload {
    type Codec: RtpPayloadCodec;

    fn bytes(&self) -> &[u8];
    fn duration(&self) -> Duration;
    fn into_bytes(self) -> Vec<u8>
    where
        Self: Sized;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpHeader {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RtpFixedHeader {
    version: u8,
    padding: bool,
    extension: bool,
    marker: bool,
    payload_type: u8,
    csrc_count: u8,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
}

impl RtpFixedHeader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        Some(Self {
            version: bytes[0] >> 6,
            padding: bytes[0] & 0x20 != 0,
            extension: bytes[0] & 0x10 != 0,
            marker: bytes[1] & 0x80 != 0,
            payload_type: bytes[1] & 0x7f,
            csrc_count: bytes[0] & 0x0f,
            seq: u16::from_be_bytes([bytes[2], bytes[3]]),
            timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ssrc: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedFrame<Raw = NoRawPackets>
where
    Raw: FrameRaw,
{
    pub raw: Raw,
    pub rtp: RtpHeader,
    pub user_id: Option<u64>,
    pub media_type: MediaType,
    pub codec: MediaCodec,
    pub frame: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrame<Raw = NoRawPackets>
where
    Raw: FrameRaw,
{
    pub frame: ReceivedFrame<Raw>,
    pub sample_rate: u32,
    pub channels: usize,
    pub samples_per_channel: usize,
    pub pcm: Vec<i16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaCodec {
    Opus,
}

impl MediaCodec {
    pub fn from_discord_audio_name(name: &str) -> Option<Self> {
        name.eq_ignore_ascii_case("opus").then_some(Self::Opus)
    }

    pub(crate) fn default_discord_payload_type(self) -> u8 {
        match self {
            Self::Opus => crate::opus::discord::RTP_PAYLOAD_TYPE,
        }
    }
}

impl fmt::Display for MediaCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opus => f.write_str("Opus"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrameMetadata<Raw = NoRawPackets>
where
    Raw: FrameRaw,
{
    pub frame: ReceivedFrame<Raw>,
    pub sample_rate: u32,
    pub channels: usize,
    pub samples_per_channel: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundPacket {
    pub rtp: RtpHeader,
    pub nonce_suffix: [u8; 4],
    pub payload_bytes: usize,
    pub packet_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundRtpState<C>
where
    C: RtpPayloadCodec,
{
    seq: u16,
    timestamp: u32,
    nonce_suffix: u32,
    ssrc: u32,
    payload_type: u8,
    sample_rate: u32,
    _codec: PhantomData<C>,
}

impl<C> OutboundRtpState<C>
where
    C: RtpPayloadCodec,
{
    pub(crate) fn new(ssrc: u32) -> Self {
        Self {
            seq: 0,
            timestamp: 0,
            nonce_suffix: initial_heartbeat_nonce() as u32,
            ssrc,
            payload_type: C::DISCORD_PAYLOAD_TYPE,
            sample_rate: C::SAMPLE_RATE_HZ,
            _codec: PhantomData,
        }
    }

    pub(crate) fn build_packet(
        &mut self,
        frame: &[u8],
        duration: Duration,
        transport_crypto: &TransportCrypto,
        packet: &mut Vec<u8>,
    ) -> Result<OutboundPacket> {
        if frame.is_empty() {
            return Err(Error::InvalidInput(InvalidInputError::EmptyPayload {
                codec: C::CODEC,
            }));
        }

        let seq = self.seq;
        let timestamp = self.timestamp;
        let nonce_suffix = self.nonce_suffix.to_be_bytes();
        let payload_bytes = frame.len();
        let rtp = transport_crypto.encrypt_payload(
            OutboundEncryptParams {
                seq,
                timestamp,
                ssrc: self.ssrc,
                payload_type: self.payload_type,
                nonce_suffix,
            },
            frame,
            packet,
        )?;

        self.seq = self.seq.wrapping_add(1);
        self.timestamp = self
            .timestamp
            .wrapping_add(timestamp_increment(self.sample_rate, duration));
        self.nonce_suffix = self.nonce_suffix.wrapping_add(1);

        Ok(OutboundPacket {
            rtp,
            nonce_suffix,
            payload_bytes,
            packet_bytes: packet.len(),
        })
    }
}

pub(crate) struct TransportCrypto {
    cipher: TransportCipher,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TransportSecretKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for TransportSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl TransportSecretKey {
    pub(crate) fn from_slice(secret_key: &[u8]) -> Result<Self> {
        secret_key
            .try_into()
            .map(|secret_key| Self(Zeroizing::new(secret_key)))
            .map_err(|_| TransportCryptoError::InvalidSecretKeyLen {
                len: secret_key.len(),
            })
            .map_err(Into::into)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportMode {
    AeadAes256GcmRtpSize,
    AeadXChaCha20Poly1305RtpSize,
}

impl TransportMode {
    pub(crate) fn from_encryption_mode(mode: &EncryptionMode) -> Result<Self> {
        match mode.as_str() {
            "aead_aes256_gcm_rtpsize" => Ok(Self::AeadAes256GcmRtpSize),
            "aead_xchacha20_poly1305_rtpsize" => Ok(Self::AeadXChaCha20Poly1305RtpSize),
            _ => Err(TransportCryptoError::UnsupportedMode {
                mode: mode.clone(),
                direction: TransportCryptoDirection::Session,
            }
            .into()),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TransportCryptoConfig {
    mode: TransportMode,
    secret_key: TransportSecretKey,
}

impl fmt::Debug for TransportCryptoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportCryptoConfig")
            .field("mode", &self.mode)
            .field("secret_key", &self.secret_key)
            .finish()
    }
}

impl TransportCryptoConfig {
    pub(crate) fn new(mode: &EncryptionMode, secret_key: &[u8]) -> Result<Self> {
        Ok(Self {
            mode: TransportMode::from_encryption_mode(mode)?,
            secret_key: TransportSecretKey::from_slice(secret_key)?,
        })
    }
}

enum TransportCipher {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl TransportCrypto {
    pub(crate) fn from_config(config: &TransportCryptoConfig) -> Result<Self> {
        let cipher = match config.mode {
            TransportMode::AeadAes256GcmRtpSize => TransportCipher::Aes256Gcm(Box::new(
                Aes256Gcm::new_from_slice(config.secret_key.as_slice())
                    .map_err(|_| TransportCryptoError::InvalidAesGcmKey)?,
            )),
            TransportMode::AeadXChaCha20Poly1305RtpSize => TransportCipher::XChaCha20Poly1305(
                XChaCha20Poly1305::new_from_slice(config.secret_key.as_slice())
                    .map_err(|_| TransportCryptoError::InvalidXChaCha20Poly1305Key)?,
            ),
        };

        Ok(Self { cipher })
    }

    pub(crate) fn decrypt_payload_into(
        &self,
        packet: &[u8],
        rtp: &RtpHeader,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        if packet.len() < rtp.encrypted_body_offset + AEAD_TAG_LEN + RTPSIZE_NONCE_LEN {
            return Err(TransportCryptoError::MissingRtpSizeNonce {
                packet_len: packet.len(),
                min_len: rtp.encrypted_body_offset + AEAD_TAG_LEN + RTPSIZE_NONCE_LEN,
            }
            .into());
        }

        let nonce_suffix_offset = packet.len() - RTPSIZE_NONCE_LEN;
        let tag_offset = nonce_suffix_offset - AEAD_TAG_LEN;
        let nonce_suffix = &packet[nonce_suffix_offset..];
        let tag = &packet[tag_offset..nonce_suffix_offset];
        let aad = &packet[..rtp.encrypted_body_offset];
        output.clear();
        output.extend_from_slice(&packet[rtp.encrypted_body_offset..tag_offset]);
        let opus_offset = rtp.header_len - rtp.encrypted_body_offset;

        match &self.cipher {
            TransportCipher::Aes256Gcm(cipher) => {
                let mut nonce = [0_u8; 12];
                nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(nonce_suffix);
                cipher
                    .decrypt_in_place_detached(
                        AesNonce::from_slice(&nonce),
                        aad,
                        output,
                        AesTag::from_slice(tag),
                    )
                    .map_err(|_| TransportCryptoError::AesGcmDecryptFailed)?;
            }
            TransportCipher::XChaCha20Poly1305(cipher) => {
                let mut nonce = [0_u8; 24];
                nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(nonce_suffix);
                cipher
                    .decrypt_in_place_detached(
                        XNonce::from_slice(&nonce),
                        aad,
                        output,
                        XTag::from_slice(tag),
                    )
                    .map_err(|_| TransportCryptoError::XChaCha20Poly1305DecryptFailed)?;
            }
        }

        strip_decrypted_rtp_payload(output, opus_offset, rtp).map_err(Into::into)
    }

    pub(crate) fn encrypt_payload(
        &self,
        params: OutboundEncryptParams,
        frame: &[u8],
        packet: &mut Vec<u8>,
    ) -> Result<RtpHeader> {
        packet.clear();
        packet.reserve(12 + frame.len() + AEAD_TAG_LEN + RTPSIZE_NONCE_LEN);
        let rtp = write_rtp_header(
            packet,
            params.seq,
            params.timestamp,
            params.ssrc,
            params.payload_type,
        );
        let payload_offset = packet.len();
        packet.extend_from_slice(frame);

        match &self.cipher {
            TransportCipher::Aes256Gcm(cipher) => {
                let mut nonce = [0_u8; 12];
                nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&params.nonce_suffix);
                let (aad, payload) = packet.split_at_mut(payload_offset);
                let tag = cipher
                    .encrypt_in_place_detached(AesNonce::from_slice(&nonce), aad, payload)
                    .map_err(|_| TransportCryptoError::AesGcmEncryptFailed)?;
                packet.extend_from_slice(&tag);
            }
            TransportCipher::XChaCha20Poly1305(cipher) => {
                let mut nonce = [0_u8; 24];
                nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&params.nonce_suffix);
                let (aad, payload) = packet.split_at_mut(payload_offset);
                let tag = cipher
                    .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, payload)
                    .map_err(|_| TransportCryptoError::XChaCha20Poly1305EncryptFailed)?;
                packet.extend_from_slice(&tag);
            }
        }

        packet.extend_from_slice(&params.nonce_suffix);
        Ok(rtp)
    }
}

fn strip_decrypted_rtp_payload(
    payload: &mut Vec<u8>,
    opus_offset: usize,
    rtp: &RtpHeader,
) -> std::result::Result<(), RtpError> {
    if opus_offset > payload.len() {
        return Err(RtpError::TruncatedEncryptedExtension);
    }
    if opus_offset > 0 {
        payload.drain(..opus_offset);
    }
    if rtp.padding {
        let padding = usize::from(*payload.last().ok_or(RtpError::EmptyPaddedPayload)?);
        if padding == 0 || padding > payload.len() {
            return Err(RtpError::InvalidPadding {
                padding,
                payload_len: payload.len(),
            });
        }
        payload.truncate(payload.len() - padding);
    }
    Ok(())
}

pub(crate) fn detect_rtp_codec(
    rtp: &RtpHeader,
    session_description: &SessionDescription,
) -> std::result::Result<MediaCodec, UnsupportedCodecError> {
    let codec =
        session_description
            .audio_codec
            .as_deref()
            .map_or(Ok(MediaCodec::Opus), |codec| {
                MediaCodec::from_discord_audio_name(codec).ok_or_else(|| {
                    UnsupportedCodecError::UnsupportedAudioCodec {
                        codec: codec.to_string(),
                    }
                })
            })?;
    let expected_payload_type = codec.default_discord_payload_type();
    if rtp.payload_type != expected_payload_type {
        return Err(UnsupportedCodecError::UnsupportedRtpPayloadType {
            payload_type: rtp.payload_type,
            expected_payload_type,
            codec,
        });
    }
    Ok(codec)
}

pub(crate) fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn parse_rtp_header(bytes: &[u8]) -> std::result::Result<RtpHeader, RtpError> {
    let fixed =
        RtpFixedHeader::parse(bytes).ok_or(RtpError::PacketTooShort { len: bytes.len() })?;
    if fixed.version != RTP_VERSION {
        return Err(RtpError::UnsupportedVersion {
            version: fixed.version,
        });
    }

    let csrc_count = usize::from(fixed.csrc_count);
    let mut header_len = 12 + csrc_count * 4;
    if bytes.len() < header_len {
        return Err(RtpError::TruncatedCsrcList {
            len: bytes.len(),
            expected_header_len: header_len,
        });
    }

    let mut encrypted_body_offset = header_len;
    if fixed.extension {
        if bytes.len() < header_len + 4 {
            return Err(RtpError::TruncatedExtensionHeader {
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
            return Err(RtpError::TruncatedExtensionPayload {
                len: bytes.len(),
                expected_header_len: header_len,
            });
        }
    }

    Ok(RtpHeader {
        version: fixed.version,
        padding: fixed.padding,
        extension: fixed.extension,
        marker: fixed.marker,
        payload_type: fixed.payload_type,
        seq: fixed.seq,
        timestamp: fixed.timestamp,
        ssrc: fixed.ssrc,
        header_len,
        encrypted_body_offset,
    })
}

#[cfg(test)]
pub(crate) fn decrypt_transport_payload(
    packet: &[u8],
    rtp: &RtpHeader,
    mode: &EncryptionMode,
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let transport_crypto =
        TransportCrypto::from_config(&TransportCryptoConfig::new(mode, secret_key)?)?;
    let mut output = Vec::new();
    transport_crypto.decrypt_payload_into(packet, rtp, &mut output)?;
    Ok(output)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundEncryptParams {
    pub(crate) seq: u16,
    pub(crate) timestamp: u32,
    pub(crate) ssrc: u32,
    pub(crate) payload_type: u8,
    pub(crate) nonce_suffix: [u8; 4],
}

#[cfg(test)]
pub(crate) fn encrypt_transport_payload(
    params: OutboundEncryptParams,
    frame: Vec<u8>,
    mode: &EncryptionMode,
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let transport_crypto =
        TransportCrypto::from_config(&TransportCryptoConfig::new(mode, secret_key)?)?;
    let mut packet = Vec::new();
    transport_crypto.encrypt_payload(params, &frame, &mut packet)?;
    Ok(packet)
}

#[cfg(test)]
pub(crate) fn build_rtp_header(seq: u16, timestamp: u32, ssrc: u32, payload_type: u8) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12);
    write_rtp_header(&mut packet, seq, timestamp, ssrc, payload_type);
    packet
}

pub(crate) fn write_rtp_header(
    packet: &mut Vec<u8>,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
) -> RtpHeader {
    let payload_type = payload_type & 0x7f;
    packet.extend_from_slice(&[RTP_VERSION << 6, payload_type]);
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    RtpHeader {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: false,
        payload_type,
        seq,
        timestamp,
        ssrc,
        header_len: 12,
        encrypted_body_offset: 12,
    }
}

pub(crate) fn timestamp_increment(sample_rate: u32, duration: Duration) -> u32 {
    let samples = (u128::from(sample_rate) * duration.as_nanos()) / 1_000_000_000;
    samples.max(1).min(u128::from(u32::MAX)) as u32
}

pub(crate) fn initial_heartbeat_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64 % JS_MAX_SAFE_INTEGER)
        .unwrap_or(0)
}

pub(crate) fn next_heartbeat_nonce(current: &mut u64) -> u64 {
    *current = current.wrapping_add(1) % JS_MAX_SAFE_INTEGER;
    *current
}

pub(crate) fn select_encryption_mode(
    options: &ConnectionOptions,
    ready: &GatewayReady,
) -> Result<EncryptionMode> {
    if let Some(preferred_mode) = &options.preferred_mode
        && ready.modes.contains(preferred_mode)
    {
        return Ok(preferred_mode.clone());
    }

    for mode in [
        EncryptionMode::aead_aes256_gcm_rtpsize(),
        EncryptionMode::aead_xchacha20_poly1305_rtpsize(),
    ] {
        if ready.modes.contains(&mode) {
            return Ok(mode);
        }
    }

    if ready.modes.is_empty() {
        return Err(Error::Protocol(ProtocolError::ReadyMissingEncryptionModes));
    }
    Err(Error::Protocol(
        ProtocolError::ReadyMissingSupportedEncryptionMode {
            modes: ready.modes.clone(),
        },
    ))
}

pub(crate) fn update_state(
    state: &mut ConnectionStateStore,
    update: impl FnOnce(&mut ConnectionInternalState),
) {
    state.update(update);
}

pub(crate) async fn connect_websocket(
    websocket_url: &str,
) -> Result<GatewayWebSocketConnectResult> {
    let (host, port) = websocket_host_port(websocket_url)?;
    let addresses = ordered_voice_socket_addrs(
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|source| {
                Error::Protocol(ProtocolError::ResolveWebSocketEndpoint {
                    host: host.clone(),
                    port,
                    source,
                })
            })?,
    );
    if addresses.is_empty() {
        return Err(Error::Protocol(
            ProtocolError::WebSocketEndpointNoAddresses { host, port },
        ));
    }

    let mut attempts = FuturesUnordered::new();
    for (index, address) in addresses.iter().copied().enumerate() {
        let websocket_url = websocket_url.to_string();
        attempts.push(async move {
            if index > 0 {
                sleep(WEBSOCKET_ADDRESS_STAGGER.saturating_mul(index as u32)).await;
            }
            match timeout(
                WEBSOCKET_ADDRESS_CONNECT_TIMEOUT,
                connect_websocket_address(websocket_url, address),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(Error::Protocol(
                    ProtocolError::WebSocketAddressConnectTimeout {
                        address,
                        duration: WEBSOCKET_ADDRESS_CONNECT_TIMEOUT,
                    },
                )),
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

    Err(Error::Protocol(
        ProtocolError::WebSocketAllAddressesFailed {
            host,
            port,
            address_count: addresses.len(),
            errors,
        },
    ))
}

pub(crate) async fn connect_websocket_address(
    websocket_url: String,
    address: SocketAddr,
) -> Result<GatewayWebSocketConnectResult> {
    let socket = TcpStream::connect(address)
        .await
        .map_err(|source| Error::Protocol(ProtocolError::TcpConnect { address, source }))?;
    socket.set_nodelay(true)?;
    client_async_tls_with_config(websocket_url, socket, None, None)
        .await
        .map_err(Into::into)
}

pub(crate) fn websocket_host_port(websocket_url: &str) -> Result<(String, u16)> {
    let request = websocket_url.into_client_request()?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or(Error::Protocol(ProtocolError::WebSocketUrlMissingHost))?
        .to_string();
    let port = uri
        .port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(Error::Protocol(
            ProtocolError::WebSocketUrlMissingUsableScheme,
        ))?;
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

pub(crate) fn udp_bind_addr_for_remote(remote: IpAddr) -> SocketAddr {
    SocketAddr::new(
        match remote {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    )
}

pub(crate) async fn bind_udp_socket(remote_ip: &str) -> Result<UdpSocket> {
    let remote = remote_ip.parse::<IpAddr>().map_err(|source| {
        Error::Protocol(ProtocolError::InvalidDiscordVoiceUdpIp {
            remote_ip: remote_ip.to_string(),
            source,
        })
    })?;
    Ok(UdpSocket::bind(udp_bind_addr_for_remote(remote)).await?)
}
