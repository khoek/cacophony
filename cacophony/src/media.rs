use std::{
    collections::VecDeque,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce, Tag as AesTag,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use dave::{Codec, MediaType};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};
use tokio_tungstenite::{client_async_tls_with_config, tungstenite::client::IntoClientRequest};

use crate::{
    AEAD_TAG_LEN, GatewayWebSocketConnectResult, RTP_VERSION, RTPSIZE_NONCE_LEN,
    WEBSOCKET_ADDRESS_CONNECT_TIMEOUT, WEBSOCKET_ADDRESS_STAGGER,
    codecs::{self, DiscordCodecDescriptor},
    errors::{
        Error, InvalidInputError, PayloadKind, ProtocolError, Result, RtpError,
        TransportCryptoError,
    },
    observer::{DavePendingMediaReason, RtcpHeader},
    rtp::RtpPayloadType,
    rtp_payload::ParsedRtpPayload,
    secrets::RedactedSecret,
    state::{EncryptionMode, PendingMediaFrame, PendingMediaPacket},
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

    pub(crate) fn ensure_len_at_most(self, max_len: usize, kind: PayloadKind) -> Result<Self> {
        if self.bytes.len() > max_len {
            Err(Error::PayloadTooLarge {
                kind,
                len: self.bytes.len(),
                max_len,
            })
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawUdpPacketInfo {
    pub version: Option<u8>,
    pub raw_payload_type: Option<u8>,
    pub payload_type: Option<RtpPayloadType>,
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
                payload_type: raw_payload_type.map(RtpPayloadType::from_marker_byte),
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
    fn from_rtp_packets(packets: Vec<Self::Packet>) -> Self;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoRawPackets;

impl FrameRaw for NoRawPackets {
    type Packet = ();

    fn capture_packet(_bytes: &[u8], _info: RawUdpPacketInfo) -> Self::Packet {}

    fn from_rtp_packets(_packets: Vec<Self::Packet>) -> Self {
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

    fn from_rtp_packets(packets: Vec<Self::Packet>) -> Self {
        Self { packets }
    }
}

pub(crate) struct RtpFrameAssembler<Raw>
where
    Raw: FrameRaw,
{
    partial: Option<PartialRtpFrame<Raw>>,
    completed: VecDeque<PendingMediaFrame<Raw>>,
}

impl<Raw> Default for RtpFrameAssembler<Raw>
where
    Raw: FrameRaw,
{
    fn default() -> Self {
        Self {
            partial: None,
            completed: VecDeque::new(),
        }
    }
}

pub(crate) struct PartialRtpFrame<Raw>
where
    Raw: FrameRaw,
{
    raw_packets: Vec<Raw::Packet>,
    rtp: RtpHeader,
    user_id: Option<u64>,
    codec: Codec,
    encrypted_frame: Vec<u8>,
    dave: bool,
    last_seq: u16,
}

impl<Raw> PartialRtpFrame<Raw>
where
    Raw: FrameRaw,
{
    fn new(packet: &PendingMediaPacket<Raw>) -> Self {
        Self {
            raw_packets: Vec::new(),
            rtp: packet.rtp.clone(),
            user_id: packet.user_id,
            codec: packet.codec,
            encrypted_frame: Vec::new(),
            dave: packet.dave,
            last_seq: packet.rtp.seq,
        }
    }

    fn matches_context(&self, packet: &PendingMediaPacket<Raw>) -> bool {
        self.rtp.ssrc == packet.rtp.ssrc && self.codec == packet.codec && self.dave == packet.dave
    }

    fn accepts_next(&self, packet: &PendingMediaPacket<Raw>) -> bool {
        self.matches_context(packet) && packet.rtp.seq == self.last_seq.wrapping_add(1)
    }

    fn should_complete_before(&self, packet: &PendingMediaPacket<Raw>) -> bool {
        self.codec == Codec::Av1
            && self.matches_context(packet)
            && self.rtp.timestamp != packet.rtp.timestamp
    }

    fn append_payload(&mut self, seq: u16, payload: ParsedRtpPayload<'_>) -> Result<()> {
        payload.append_depacketized(&mut self.encrypted_frame)?;
        self.last_seq = seq;
        Ok(())
    }

    fn push_raw_packet(&mut self, packet: Raw::Packet) {
        self.raw_packets.push(packet);
    }

    fn into_pending(self) -> PendingMediaFrame<Raw> {
        PendingMediaFrame {
            raw: Raw::from_rtp_packets(self.raw_packets),
            rtp: self.rtp,
            user_id: self.user_id,
            codec: self.codec,
            encrypted_frame: self.encrypted_frame,
            dave: self.dave,
            enqueued_at: tokio::time::Instant::now(),
            reason: DavePendingMediaReason::DecryptStatePending,
            was_pending: false,
        }
    }
}

impl<Raw> RtpFrameAssembler<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn push_packet(
        &mut self,
        packet: PendingMediaPacket<Raw>,
    ) -> Result<Option<PendingMediaFrame<Raw>>> {
        if self.partial_should_complete_before(&packet)
            && let Some(partial) = self.partial.take()
        {
            self.completed.push_back(partial.into_pending());
        }

        let continues_partial = self.has_contiguous_partial(&packet);
        if !continues_partial && self.has_matching_partial(&packet) {
            self.partial = None;
        }
        let payload = ParsedRtpPayload::parse(
            packet.codec,
            &packet.encrypted_payload,
            packet.rtp.marker,
            continues_partial,
        )?;
        let boundary = payload.boundary();
        if !continues_partial && !boundary.starts_frame {
            return Ok(self.completed.pop_front());
        }
        let mut partial = if continues_partial && !boundary.starts_frame {
            self.partial.take().expect("partial frame exists")
        } else {
            PartialRtpFrame::new(&packet)
        };

        partial.append_payload(packet.rtp.seq, payload)?;
        partial.push_raw_packet(packet.raw);

        if boundary.completes_frame {
            self.completed.push_back(partial.into_pending());
        } else {
            self.partial = Some(partial);
        }
        Ok(self.completed.pop_front())
    }

    pub(crate) fn pop_completed(&mut self) -> Option<PendingMediaFrame<Raw>> {
        self.completed.pop_front()
    }

    pub(crate) fn has_completed_frame(&self) -> bool {
        !self.completed.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.partial = None;
        self.completed.clear();
    }

    fn has_matching_partial(&self, packet: &PendingMediaPacket<Raw>) -> bool {
        self.partial
            .as_ref()
            .is_some_and(|partial| partial.matches_context(packet))
    }

    fn has_contiguous_partial(&self, packet: &PendingMediaPacket<Raw>) -> bool {
        self.partial
            .as_ref()
            .is_some_and(|partial| partial.accepts_next(packet))
    }

    fn partial_should_complete_before(&self, packet: &PendingMediaPacket<Raw>) -> bool {
        self.partial
            .as_ref()
            .is_some_and(|partial| partial.should_complete_before(packet))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub marker: bool,
    pub payload_type: RtpPayloadType,
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub header_len: usize,
    pub encrypted_body_offset: usize,
}

impl RtpHeader {
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, RtpError> {
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

        Ok(Self {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RtpFixedHeader {
    version: u8,
    padding: bool,
    extension: bool,
    marker: bool,
    payload_type: RtpPayloadType,
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
            payload_type: RtpPayloadType::from_marker_byte(bytes[1]),
            csrc_count: bytes[0] & 0x0f,
            seq: u16::from_be_bytes([bytes[2], bytes[3]]),
            timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ssrc: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RtpHeaderFields {
    pub(crate) seq: u16,
    pub(crate) timestamp: u32,
    pub(crate) ssrc: u32,
    pub(crate) payload_type: RtpPayloadType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RtpHeaderBuilder {
    fields: RtpHeaderFields,
    marker: bool,
}

impl RtpHeaderBuilder {
    pub(crate) fn new(fields: RtpHeaderFields) -> Self {
        Self {
            fields,
            marker: false,
        }
    }

    pub(crate) fn marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }

    pub(crate) fn write_to(self, packet: &mut Vec<u8>) -> RtpHeader {
        packet.extend_from_slice(&[
            RTP_VERSION << 6,
            self.fields.payload_type.marker_byte(self.marker),
        ]);
        packet.extend_from_slice(&self.fields.seq.to_be_bytes());
        packet.extend_from_slice(&self.fields.timestamp.to_be_bytes());
        packet.extend_from_slice(&self.fields.ssrc.to_be_bytes());
        RtpHeader {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: self.marker,
            payload_type: self.fields.payload_type,
            seq: self.fields.seq,
            timestamp: self.fields.timestamp,
            ssrc: self.fields.ssrc,
            header_len: 12,
            encrypted_body_offset: 12,
        }
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
    pub codec: Codec,
    pub frame: Vec<u8>,
}

impl<Raw> ReceivedFrame<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn ensure_len_at_most(self, max_len: usize) -> Result<Self> {
        if self.frame.len() > max_len {
            Err(Error::PayloadTooLarge {
                kind: PayloadKind::Frame,
                len: self.frame.len(),
                max_len,
            })
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrame<Raw = NoRawPackets>
where
    Raw: FrameRaw,
{
    pub frame: ReceivedFrame<Raw>,
    pub pcm_layout: DecodedPcmLayout,
    pub pcm: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrameMetadata<Raw = NoRawPackets>
where
    Raw: FrameRaw,
{
    pub frame: ReceivedFrame<Raw>,
    pub pcm_layout: DecodedPcmLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedPcmLayout {
    pub sample_rate_hz: u32,
    pub channels: usize,
    pub samples_per_channel: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundPacket {
    pub rtp: RtpHeader,
    pub nonce_suffix: RtpSizeNonceSuffix,
    pub payload_bytes: usize,
    pub packet_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtpSizeNonceSuffix(u32);

impl RtpSizeNonceSuffix {
    pub const fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    fn initial() -> Result<Self> {
        let mut bytes = [0; RTPSIZE_NONCE_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|_| TransportCryptoError::NonceRandomnessUnavailable)?;
        Ok(Self::from_be_bytes(bytes))
    }

    fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundCodecBinding {
    ssrc: u32,
    descriptor: DiscordCodecDescriptor,
}

impl OutboundCodecBinding {
    pub(crate) fn new(codec: Codec, ssrc: u32) -> Self {
        Self {
            ssrc,
            descriptor: codecs::descriptor(codec),
        }
    }

    pub(crate) fn codec(self) -> Codec {
        self.descriptor.codec
    }

    pub(crate) fn media_type(self) -> MediaType {
        self.descriptor.media_type()
    }

    pub(crate) fn payload_type(self) -> RtpPayloadType {
        self.descriptor.payload_type
    }

    pub(crate) fn sample_rate(self) -> u32 {
        self.descriptor.clock_rate_hz
    }

    pub(crate) fn ssrc(self) -> u32 {
        self.ssrc
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundRtpState {
    seq: u16,
    timestamp: u32,
    nonce_suffix: RtpSizeNonceSuffix,
    binding: OutboundCodecBinding,
}

impl OutboundRtpState {
    pub(crate) fn new(binding: OutboundCodecBinding) -> Result<Self> {
        Ok(Self {
            seq: 0,
            timestamp: 0,
            nonce_suffix: RtpSizeNonceSuffix::initial()?,
            binding,
        })
    }

    pub(crate) fn codec(&self) -> Codec {
        self.binding.codec()
    }

    pub(crate) fn ssrc(&self) -> u32 {
        self.binding.ssrc()
    }

    pub(crate) fn update_binding(&mut self, binding: OutboundCodecBinding) {
        self.binding = binding;
    }

    pub(crate) fn build_packet(
        &mut self,
        frame: &[u8],
        marker: bool,
        duration: Duration,
        transport_crypto: &TransportCrypto,
        packet: &mut Vec<u8>,
    ) -> Result<OutboundPacket> {
        if frame.is_empty() {
            return Err(Error::InvalidInput(InvalidInputError::EmptyPayload {
                codec: self.binding.codec(),
            }));
        }

        let seq = self.seq;
        let timestamp = self.timestamp;
        let payload_bytes = frame.len();
        let rtp = transport_crypto.encrypt_payload(
            OutboundEncryptParams {
                header: RtpHeaderFields {
                    seq,
                    timestamp,
                    ssrc: self.binding.ssrc(),
                    payload_type: self.binding.payload_type(),
                },
                marker,
                nonce_suffix: self.nonce_suffix,
            },
            frame,
            packet,
        )?;

        self.seq = self.seq.wrapping_add(1);
        if self.binding.media_type() == MediaType::Audio || marker {
            self.timestamp = self
                .timestamp
                .wrapping_add(timestamp_increment(self.binding.sample_rate(), duration));
        }
        let nonce_suffix = self.nonce_suffix;
        self.nonce_suffix.increment();

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

type TransportSecretKey = RedactedSecret<[u8; 32]>;

fn transport_secret_key_from_slice(secret_key: &[u8]) -> Result<TransportSecretKey> {
    secret_key
        .try_into()
        .map(TransportSecretKey::new)
        .map_err(|_| TransportCryptoError::InvalidSecretKeyLen {
            len: secret_key.len(),
        })
        .map_err(Into::into)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TransportCryptoConfig {
    mode: EncryptionMode,
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
    pub(crate) fn new(mode: EncryptionMode, secret_key: &[u8]) -> Result<Self> {
        Ok(Self {
            mode,
            secret_key: transport_secret_key_from_slice(secret_key)?,
        })
    }
}

enum TransportCipher {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl TransportCipher {
    fn decrypt_in_place_detached(
        &self,
        nonce_suffix: RtpSizeNonceSuffix,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8],
    ) -> std::result::Result<(), TransportCryptoError> {
        match self {
            Self::Aes256Gcm(cipher) => cipher
                .decrypt_in_place_detached(
                    AesNonce::from_slice(&rtpsize_nonce::<12>(nonce_suffix)),
                    aad,
                    payload,
                    AesTag::from_slice(tag),
                )
                .map_err(|_| TransportCryptoError::AesGcmDecryptFailed),
            Self::XChaCha20Poly1305(cipher) => cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(&rtpsize_nonce::<24>(nonce_suffix)),
                    aad,
                    payload,
                    XTag::from_slice(tag),
                )
                .map_err(|_| TransportCryptoError::XChaCha20Poly1305DecryptFailed),
        }
    }

    fn encrypt_in_place_detached(
        &self,
        nonce_suffix: RtpSizeNonceSuffix,
        aad: &[u8],
        payload: &mut [u8],
    ) -> std::result::Result<[u8; AEAD_TAG_LEN], TransportCryptoError> {
        let tag = match self {
            Self::Aes256Gcm(cipher) => cipher
                .encrypt_in_place_detached(
                    AesNonce::from_slice(&rtpsize_nonce::<12>(nonce_suffix)),
                    aad,
                    payload,
                )
                .map_err(|_| TransportCryptoError::AesGcmEncryptFailed)?,
            Self::XChaCha20Poly1305(cipher) => cipher
                .encrypt_in_place_detached(
                    XNonce::from_slice(&rtpsize_nonce::<24>(nonce_suffix)),
                    aad,
                    payload,
                )
                .map_err(|_| TransportCryptoError::XChaCha20Poly1305EncryptFailed)?,
        };
        let mut bytes = [0; AEAD_TAG_LEN];
        bytes.copy_from_slice(&tag);
        Ok(bytes)
    }
}

fn rtpsize_nonce<const N: usize>(suffix: RtpSizeNonceSuffix) -> [u8; N] {
    let mut nonce = [0_u8; N];
    nonce[..RTPSIZE_NONCE_LEN].copy_from_slice(&suffix.to_be_bytes());
    nonce
}

impl TransportCrypto {
    pub(crate) fn from_config(config: &TransportCryptoConfig) -> Result<Self> {
        let cipher = match config.mode {
            EncryptionMode::AeadAes256GcmRtpSize => TransportCipher::Aes256Gcm(Box::new(
                Aes256Gcm::new_from_slice(config.secret_key.as_slice())
                    .map_err(|_| TransportCryptoError::InvalidAesGcmKey)?,
            )),
            EncryptionMode::AeadXChaCha20Poly1305RtpSize => TransportCipher::XChaCha20Poly1305(
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
        let mut nonce_suffix = [0; 4];
        nonce_suffix.copy_from_slice(&packet[nonce_suffix_offset..]);
        let nonce_suffix = RtpSizeNonceSuffix::from_be_bytes(nonce_suffix);
        let tag = &packet[tag_offset..nonce_suffix_offset];
        let aad = &packet[..rtp.encrypted_body_offset];
        output.clear();
        output.extend_from_slice(&packet[rtp.encrypted_body_offset..tag_offset]);
        let opus_offset = rtp.header_len - rtp.encrypted_body_offset;

        self.cipher
            .decrypt_in_place_detached(nonce_suffix, aad, output, tag)?;
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
        let rtp = RtpHeaderBuilder::new(params.header)
            .marker(params.marker)
            .write_to(packet);
        let payload_offset = packet.len();
        packet.extend_from_slice(frame);

        let (aad, payload) = packet.split_at_mut(payload_offset);
        let tag = self
            .cipher
            .encrypt_in_place_detached(params.nonce_suffix, aad, payload)?;
        packet.extend_from_slice(&tag);

        packet.extend_from_slice(&params.nonce_suffix.to_be_bytes());
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

pub(crate) fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

pub(crate) fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
pub(crate) fn decrypt_transport_payload(
    packet: &[u8],
    rtp: &RtpHeader,
    mode: EncryptionMode,
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
    pub(crate) header: RtpHeaderFields,
    pub(crate) marker: bool,
    pub(crate) nonce_suffix: RtpSizeNonceSuffix,
}

#[cfg(test)]
pub(crate) fn encrypt_transport_payload(
    params: OutboundEncryptParams,
    frame: Vec<u8>,
    mode: EncryptionMode,
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let transport_crypto =
        TransportCrypto::from_config(&TransportCryptoConfig::new(mode, secret_key)?)?;
    let mut packet = Vec::new();
    transport_crypto.encrypt_payload(params, &frame, &mut packet)?;
    Ok(packet)
}

#[cfg(test)]
pub(crate) fn build_rtp_header(
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: RtpPayloadType,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12);
    RtpHeaderBuilder::new(RtpHeaderFields {
        seq,
        timestamp,
        ssrc,
        payload_type,
    })
    .write_to(&mut packet);
    packet
}

pub(crate) fn timestamp_increment(sample_rate: u32, duration: Duration) -> u32 {
    let samples = (u128::from(sample_rate) * duration.as_nanos()) / 1_000_000_000;
    samples.max(1).min(u128::from(u32::MAX)) as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeartbeatNonce(u64);

impl HeartbeatNonce {
    pub(crate) fn initial() -> Result<Self> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes)
            .map_err(|_| TransportCryptoError::NonceRandomnessUnavailable)?;
        Ok(Self(u64::from_be_bytes(bytes) % crate::JS_MAX_SAFE_INTEGER))
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(1) % crate::JS_MAX_SAFE_INTEGER;
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceEndpoint<'a> {
    websocket_url: &'a str,
}

impl<'a> VoiceEndpoint<'a> {
    pub(crate) const fn new(websocket_url: &'a str) -> Self {
        Self { websocket_url }
    }

    pub(crate) async fn connect_websocket(self) -> Result<GatewayWebSocketConnectResult> {
        let (host, port) = self.host_port()?;
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
            attempts.push(async move {
                if index > 0 {
                    sleep(WEBSOCKET_ADDRESS_STAGGER.saturating_mul(index as u32)).await;
                }
                match timeout(
                    WEBSOCKET_ADDRESS_CONNECT_TIMEOUT,
                    self.connect_websocket_address(address),
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

    async fn connect_websocket_address(
        self,
        address: SocketAddr,
    ) -> Result<GatewayWebSocketConnectResult> {
        let socket = TcpStream::connect(address)
            .await
            .map_err(|source| Error::Protocol(ProtocolError::TcpConnect { address, source }))?;
        socket.set_nodelay(true)?;
        client_async_tls_with_config(self.websocket_url, socket, None, None)
            .await
            .map_err(Into::into)
    }

    pub(crate) fn host_port(self) -> Result<(String, u16)> {
        let request = self.websocket_url.into_client_request()?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceUdpRemote {
    ip: IpAddr,
}

impl VoiceUdpRemote {
    pub(crate) const fn new(ip: IpAddr) -> Self {
        Self { ip }
    }

    pub(crate) fn parse(remote_ip: &str) -> Result<Self> {
        Ok(Self::new(remote_ip.parse::<IpAddr>().map_err(
            |source| {
                Error::Protocol(ProtocolError::InvalidDiscordVoiceUdpIp {
                    remote_ip: remote_ip.to_string(),
                    source,
                })
            },
        )?))
    }

    pub(crate) fn bind_addr(self) -> SocketAddr {
        SocketAddr::new(
            match self.ip {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            0,
        )
    }

    pub(crate) async fn bind_socket(self) -> Result<UdpSocket> {
        Ok(UdpSocket::bind(self.bind_addr()).await?)
    }
}
