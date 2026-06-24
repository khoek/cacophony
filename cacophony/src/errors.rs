use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    str::Utf8Error,
    time::Duration,
};

use dave::{
    CreateKeyPackageError, DecryptError, EncryptError, FrameDecryptError, InitError,
    ProcessCommitError, ProcessProposalsError, ProcessWelcomeError, SetExternalSenderError,
};

use crate::{
    media::Codec,
    observer::{ConnectStage, ReceiveDecodeErrorKind},
    state::EncryptionMode,
};

#[derive(Debug)]
pub enum Error {
    InvalidInput(InvalidInputError),
    Pcm(PcmError),
    Protocol(ProtocolError),
    Timeout {
        stage: Option<ConnectStage>,
        duration: Duration,
    },
    Io(std::io::Error),
    Json(serde_json::Error),
    WebSocket(tokio_tungstenite::tungstenite::Error),
    Opus(OpusError),
    UnsupportedCodec(UnsupportedCodecError),
    Dave(DaveError),
    Rtp(RtpError),
    TransportCrypto(TransportCryptoError),
    PayloadTooLarge {
        kind: PayloadKind,
        len: usize,
        max_len: usize,
    },
    Backpressure(BackpressureError),
    Closed,
    Join(ConnectionJoinError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(error) => write!(f, "{error}"),
            Self::Pcm(error) => write!(f, "{error}"),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Timeout { stage, duration } => {
                if let Some(stage) = stage {
                    write!(f, "voice {} timed out after {duration:?}", stage.label())
                } else {
                    write!(f, "voice operation timed out after {duration:?}")
                }
            }
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            Self::WebSocket(error) => write!(f, "{error}"),
            Self::Opus(error) => write!(f, "{error}"),
            Self::UnsupportedCodec(error) => write!(f, "{error}"),
            Self::Dave(error) => write!(f, "{error}"),
            Self::Rtp(error) => write!(f, "{error}"),
            Self::TransportCrypto(error) => write!(f, "{error}"),
            Self::PayloadTooLarge { kind, len, max_len } => {
                write!(
                    f,
                    "voice {kind} is {len} bytes, exceeding requested max_len {max_len}"
                )
            }
            Self::Backpressure(error) => write!(f, "{error}"),
            Self::Closed => f.write_str("voice connection is closed"),
            Self::Join(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pcm(error) => Some(error),
            Self::Protocol(error) => error.source(),
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::WebSocket(error) => Some(error),
            Self::UnsupportedCodec(error) => Some(error),
            Self::Dave(error) => Some(error),
            Self::Rtp(error) => Some(error),
            Self::TransportCrypto(error) => Some(error),
            Self::Join(error) => error.source(),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(error)
    }
}

impl From<DaveError> for Error {
    fn from(error: DaveError) -> Self {
        Self::Dave(error)
    }
}

impl From<UnsupportedCodecError> for Error {
    fn from(error: UnsupportedCodecError) -> Self {
        Self::UnsupportedCodec(error)
    }
}

impl From<PcmError> for Error {
    fn from(error: PcmError) -> Self {
        Self::Pcm(error)
    }
}

impl From<RtpError> for Error {
    fn from(error: RtpError) -> Self {
        Self::Rtp(error)
    }
}

impl From<TransportCryptoError> for Error {
    fn from(error: TransportCryptoError) -> Self {
        Self::TransportCrypto(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcmError {
    SampleRateZero,
    ChannelCountZero,
    SampleAlignment {
        encoding: &'static str,
        byte_len: usize,
        sample_bytes: usize,
    },
    ChannelAlignment {
        channels: usize,
        samples: usize,
    },
    UnsupportedEncoding(String),
    ResamplerChunkFramesZero,
    ResamplerNotInitialized,
    Resampler(String),
}

impl fmt::Display for PcmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SampleRateZero => f.write_str("PCM sample rate must be greater than zero"),
            Self::ChannelCountZero => f.write_str("PCM channel count must be greater than zero"),
            Self::SampleAlignment {
                encoding,
                byte_len,
                sample_bytes,
            } => write!(
                f,
                "{encoding} PCM byte length {byte_len} is not aligned to {sample_bytes}-byte samples",
            ),
            Self::ChannelAlignment { channels, samples } => write!(
                f,
                "PCM sample count {samples} is not aligned to {channels} channels",
            ),
            Self::UnsupportedEncoding(encoding) => {
                write!(f, "PCM encoding `{encoding}` is not supported")
            }
            Self::ResamplerChunkFramesZero => {
                f.write_str("PCM resampler chunk frame count must be greater than zero")
            }
            Self::ResamplerNotInitialized => f.write_str("PCM resampler is not initialized"),
            Self::Resampler(reason) => write!(f, "PCM resampler error: {reason}"),
        }
    }
}

impl std::error::Error for PcmError {}

#[derive(Debug)]
pub enum InvalidInputError {
    ConnectionTuningZero {
        field: &'static str,
    },
    ConnectionTuningTooSmall {
        field: &'static str,
        min: usize,
        actual: usize,
    },
    ConnectionTuningDurationZero {
        field: &'static str,
    },
    UnsupportedGatewayVersion {
        version: u8,
    },
    ZeroMaxLen,
    EmptyPayload {
        codec: Codec,
    },
    PcmBlockSampleCount {
        expected: usize,
        actual: usize,
    },
    PcmBlockFrameCount {
        expected: usize,
        actual: usize,
    },
    PcmSampleAlignment {
        encoding: &'static str,
        byte_len: usize,
        sample_bytes: usize,
    },
    PcmChannelAlignment {
        channels: usize,
        samples: usize,
    },
    PcmChannelCountZero,
    PcmResamplerChunkFramesZero,
    PcmArchiveEmpty,
    OggOpusVendorEmpty,
    OggOpusUnsupportedSampleRate {
        sample_rate_hz: u32,
    },
    DiscordPcmMixedSampleRates {
        existing: u32,
        actual: u32,
    },
    DiscordPcmMixedChannelCounts {
        existing: usize,
        actual: usize,
    },
    DiscordPcmMixedEncoding,
    DiscordPcmEncoderUninitialized,
    OpusBitrateTooLarge {
        bitrate_bps: u32,
    },
    OpusOutputBufferTooSmall {
        min_len: usize,
        len: usize,
    },
}

impl fmt::Display for InvalidInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionTuningZero { field } => {
                write!(
                    f,
                    "connection tuning field {field} must be greater than zero"
                )
            }
            Self::ConnectionTuningTooSmall { field, min, actual } => write!(
                f,
                "connection tuning field {field} must be at least {min}, got {actual}",
            ),
            Self::ConnectionTuningDurationZero { field } => {
                write!(f, "connection tuning duration {field} must be nonzero")
            }
            Self::UnsupportedGatewayVersion { version } => {
                write!(f, "Discord voice gateway version {version} is unsupported")
            }
            Self::ZeroMaxLen => f.write_str("max_len must be greater than zero"),
            Self::EmptyPayload { codec } => write!(f, "{codec} frame must not be empty"),
            Self::PcmBlockSampleCount { expected, actual } => write!(
                f,
                "Discord PCM block must contain {expected} interleaved f32 samples, got {actual}",
            ),
            Self::PcmBlockFrameCount { expected, actual } => write!(
                f,
                "Discord PCM block must contain {expected} samples per channel, got {actual}",
            ),
            Self::PcmSampleAlignment {
                encoding,
                byte_len,
                sample_bytes,
            } => write!(
                f,
                "{encoding} PCM byte length {byte_len} is not aligned to {sample_bytes}-byte samples",
            ),
            Self::PcmChannelAlignment { channels, samples } => write!(
                f,
                "PCM sample count {samples} is not aligned to {channels} channels",
            ),
            Self::PcmChannelCountZero => f.write_str("PCM channel count must be greater than zero"),
            Self::PcmResamplerChunkFramesZero => {
                f.write_str("PCM resampler chunk frame count must be greater than zero")
            }
            Self::PcmArchiveEmpty => f.write_str("captured PCM audio must not be empty"),
            Self::OggOpusVendorEmpty => f.write_str("Ogg Opus vendor must not be empty"),
            Self::OggOpusUnsupportedSampleRate { sample_rate_hz } => write!(
                f,
                "Ogg Opus archive encoding does not support {sample_rate_hz} Hz captured audio"
            ),
            Self::DiscordPcmMixedSampleRates { existing, actual } => write!(
                f,
                "Discord PCM playback received mixed sample rates: {existing} and {actual}"
            ),
            Self::DiscordPcmMixedChannelCounts { existing, actual } => write!(
                f,
                "Discord PCM playback received mixed channel counts: {existing} and {actual}"
            ),
            Self::DiscordPcmMixedEncoding => {
                f.write_str("Discord PCM playback received mixed PCM encodings")
            }
            Self::DiscordPcmEncoderUninitialized => {
                f.write_str("Discord PCM encoder was not initialized")
            }
            Self::OpusBitrateTooLarge { bitrate_bps } => write!(
                f,
                "Opus bitrate {bitrate_bps} bps exceeds the encoder limit",
            ),
            Self::OpusOutputBufferTooSmall { min_len, len } => write!(
                f,
                "Opus output buffer must be at least {min_len} bytes, got {len}",
            ),
        }
    }
}

impl std::error::Error for InvalidInputError {}

#[derive(Debug)]
pub enum ProtocolError {
    TextPayloadRequiresBinaryDaveMlsCommand,
    UdpDiscoveryPacketTooShort {
        len: usize,
        min_len: usize,
    },
    UnexpectedUdpDiscoveryPacketType {
        packet_type: u16,
        expected_packet_type: u16,
    },
    UnexpectedUdpDiscoveryPacketLen {
        packet_len: u16,
        expected_packet_len: u16,
    },
    InvalidUdpDiscoveryIp(Utf8Error),
    ReadyMissingEncryptionModes,
    ReadyMissingSupportedEncryptionMode {
        modes: Vec<EncryptionMode>,
    },
    ResolveWebSocketEndpoint {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    WebSocketEndpointNoAddresses {
        host: String,
        port: u16,
    },
    WebSocketAddressConnectTimeout {
        address: SocketAddr,
        duration: Duration,
    },
    WebSocketAllAddressesFailed {
        host: String,
        port: u16,
        address_count: usize,
        errors: Vec<String>,
    },
    TcpConnect {
        address: SocketAddr,
        source: std::io::Error,
    },
    WebSocketUrlMissingHost,
    WebSocketUrlMissingUsableScheme,
    InvalidDiscordVoiceUdpIp {
        remote_ip: String,
        source: AddrParseError,
    },
    HeartbeatAckTimeout,
    MissingSessionDescription,
}

impl ProtocolError {
    fn source_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUdpDiscoveryIp(error) => Some(error),
            Self::ResolveWebSocketEndpoint { source, .. } => Some(source),
            Self::TcpConnect { source, .. } => Some(source),
            Self::InvalidDiscordVoiceUdpIp { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextPayloadRequiresBinaryDaveMlsCommand => {
                f.write_str("DAVE MLS key package and commit/welcome use binary websocket frames")
            }
            Self::UdpDiscoveryPacketTooShort { len, min_len } => write!(
                f,
                "voice discovery packet must be at least {min_len} bytes, got {len}",
            ),
            Self::UnexpectedUdpDiscoveryPacketType {
                packet_type,
                expected_packet_type,
            } => write!(
                f,
                "unexpected voice discovery packet type {packet_type}; expected {expected_packet_type}",
            ),
            Self::UnexpectedUdpDiscoveryPacketLen {
                packet_len,
                expected_packet_len,
            } => write!(
                f,
                "unexpected voice discovery packet length {packet_len}; expected {expected_packet_len}",
            ),
            Self::InvalidUdpDiscoveryIp(error) => {
                write!(f, "invalid voice discovery ip: {error}")
            }
            Self::ReadyMissingEncryptionModes => {
                f.write_str("voice ready payload did not include encryption modes")
            }
            Self::ReadyMissingSupportedEncryptionMode { modes } => write!(
                f,
                "voice ready payload did not include a supported encryption mode: {modes:?}",
            ),
            Self::ResolveWebSocketEndpoint { host, port, source } => {
                write!(
                    f,
                    "resolve voice websocket endpoint {host}:{port}: {source}"
                )
            }
            Self::WebSocketEndpointNoAddresses { host, port } => write!(
                f,
                "voice websocket endpoint {host}:{port} did not resolve to any addresses",
            ),
            Self::WebSocketAddressConnectTimeout { address, duration } => {
                write!(
                    f,
                    "voice websocket connect to {address} timed out after {duration:?}"
                )
            }
            Self::WebSocketAllAddressesFailed {
                host,
                port,
                address_count,
                errors,
            } => write!(
                f,
                "voice websocket connect to {host}:{port} failed across {address_count} \
                 resolved addresses: {}",
                errors.join("; "),
            ),
            Self::TcpConnect { address, source } => write!(f, "tcp connect {address}: {source}"),
            Self::WebSocketUrlMissingHost => {
                f.write_str("voice websocket URL did not include a host")
            }
            Self::WebSocketUrlMissingUsableScheme => {
                f.write_str("voice websocket URL did not include a usable scheme")
            }
            Self::InvalidDiscordVoiceUdpIp { remote_ip, source } => {
                write!(f, "invalid Discord voice UDP IP {remote_ip:?}: {source}")
            }
            Self::HeartbeatAckTimeout => f.write_str("voice heartbeat ACK timed out"),
            Self::MissingSessionDescription => f.write_str("missing voice session description"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source_error()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpusOperation {
    CreateEncoder,
    EncodeFrame,
    CreateMonoDecoder,
    CreateDecoder,
    DecodeFrame,
}

impl fmt::Display for OpusOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateEncoder => f.write_str("create Opus encoder"),
            Self::EncodeFrame => f.write_str("encode Opus frame"),
            Self::CreateMonoDecoder => f.write_str("create mono Opus decoder"),
            Self::CreateDecoder => f.write_str("create Opus decoder"),
            Self::DecodeFrame => f.write_str("decode Opus frame"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpusError {
    OperationFailed {
        operation: OpusOperation,
        reason: &'static str,
    },
    UnsupportedVoiceCodec {
        codec: Codec,
    },
    UnsupportedChannelCount {
        channels: usize,
    },
    ResamplerNotInitialized,
    Resampler(String),
    EmptyFrame,
}

impl fmt::Display for OpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationFailed { operation, reason } => {
                write!(f, "failed to {operation}: {reason}")
            }
            Self::UnsupportedVoiceCodec { codec } => {
                write!(f, "unsupported voice codec {codec:?}")
            }
            Self::UnsupportedChannelCount { channels } => {
                write!(f, "unsupported Opus channel count {channels}")
            }
            Self::ResamplerNotInitialized => f.write_str("Opus resampler is not initialized"),
            Self::Resampler(reason) => write!(f, "Opus resampler error: {reason}"),
            Self::EmptyFrame => f.write_str("Opus frame is empty"),
        }
    }
}

impl std::error::Error for OpusError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureError {
    CommandQueueFull,
    MediaQueueFull,
    ActiveOpusPlayout,
}

impl fmt::Display for BackpressureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandQueueFull => f.write_str("voice connection command queue is full"),
            Self::MediaQueueFull => f.write_str("voice connection media queue is full"),
            Self::ActiveOpusPlayout => {
                f.write_str("voice connection already has an active Opus playout")
            }
        }
    }
}

impl std::error::Error for BackpressureError {}

#[derive(Debug)]
pub enum ConnectionJoinError {
    ControlTaskJoinFailed(tokio::task::JoinError),
    JoinTaskClosed,
    JoinTaskStoppedBeforeReply,
}

impl fmt::Display for ConnectionJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControlTaskJoinFailed(error) => {
                write!(f, "voice control task join failed: {error}")
            }
            Self::JoinTaskClosed => f.write_str("voice join task is closed"),
            Self::JoinTaskStoppedBeforeReply => {
                f.write_str("voice join task stopped before replying")
            }
        }
    }
}

impl std::error::Error for ConnectionJoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ControlTaskJoinFailed(error) => Some(error),
            Self::JoinTaskClosed | Self::JoinTaskStoppedBeforeReply => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    RawUdpPacket,
    RtpPacket,
    Frame,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsupportedCodecError {
    UnsupportedAudioCodec {
        codec: String,
    },
    UnsupportedRtpPayloadType {
        payload_type: u8,
        expected_payload_type: u8,
        codec: Codec,
    },
}

impl fmt::Display for UnsupportedCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAudioCodec { codec } => {
                write!(
                    f,
                    "unsupported Discord voice audio codec {codec:?}; only Opus is supported"
                )
            }
            Self::UnsupportedRtpPayloadType {
                payload_type,
                expected_payload_type,
                codec,
            } => write!(
                f,
                "unsupported Discord voice RTP payload type {payload_type} for {codec}; \
                 expected {expected_payload_type}",
            ),
        }
    }
}

impl std::error::Error for UnsupportedCodecError {}

impl fmt::Display for PayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawUdpPacket => f.write_str("raw UDP packet"),
            Self::RtpPacket => f.write_str("RTP packet"),
            Self::Frame => f.write_str("voice frame"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RtpError {
    PacketTooShort {
        len: usize,
    },
    UnsupportedVersion {
        version: u8,
    },
    TruncatedCsrcList {
        len: usize,
        expected_header_len: usize,
    },
    TruncatedExtensionHeader {
        len: usize,
        expected_header_len: usize,
    },
    TruncatedExtensionPayload {
        len: usize,
        expected_header_len: usize,
    },
    TruncatedEncryptedExtension,
    EmptyPaddedPayload,
    InvalidPadding {
        padding: usize,
        payload_len: usize,
    },
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { len } => {
                write!(f, "voice RTP packet is shorter than 12 bytes: {len}")
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported voice RTP version {version}; expected 2")
            }
            Self::TruncatedCsrcList {
                len,
                expected_header_len,
            } => write!(
                f,
                "voice RTP packet has truncated CSRC list: {len} bytes for {expected_header_len} byte header",
            ),
            Self::TruncatedExtensionHeader {
                len,
                expected_header_len,
            } => write!(
                f,
                "voice RTP packet has truncated extension header: {len} bytes for {expected_header_len} byte header",
            ),
            Self::TruncatedExtensionPayload {
                len,
                expected_header_len,
            } => write!(
                f,
                "voice RTP packet has truncated extension payload: {len} bytes for {expected_header_len} byte header",
            ),
            Self::TruncatedEncryptedExtension => {
                f.write_str("voice RTP packet has truncated encrypted extension")
            }
            Self::EmptyPaddedPayload => f.write_str("voice RTP packet has empty padded payload"),
            Self::InvalidPadding {
                padding,
                payload_len,
            } => write!(
                f,
                "voice RTP packet has invalid padding length {padding} for payload length {payload_len}",
            ),
        }
    }
}

impl std::error::Error for RtpError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportCryptoError {
    InvalidSecretKeyLen {
        len: usize,
    },
    MissingRtpSizeNonce {
        packet_len: usize,
        min_len: usize,
    },
    InvalidAesGcmKey,
    InvalidXChaCha20Poly1305Key,
    AesGcmDecryptFailed,
    AesGcmEncryptFailed,
    XChaCha20Poly1305DecryptFailed,
    XChaCha20Poly1305EncryptFailed,
    UnsupportedMode {
        mode: EncryptionMode,
        direction: TransportCryptoDirection,
    },
}

impl fmt::Display for TransportCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKeyLen { len } => {
                write!(f, "voice secret_key must be 32 bytes, got {len}")
            }
            Self::MissingRtpSizeNonce {
                packet_len,
                min_len,
            } => write!(
                f,
                "voice RTP packet is missing the RTP-size nonce suffix: {packet_len} bytes for minimum {min_len}",
            ),
            Self::InvalidAesGcmKey => f.write_str("invalid AES-GCM voice secret key"),
            Self::InvalidXChaCha20Poly1305Key => {
                f.write_str("invalid XChaCha20-Poly1305 voice secret key")
            }
            Self::AesGcmDecryptFailed => f.write_str("failed to decrypt AES-GCM voice packet"),
            Self::AesGcmEncryptFailed => f.write_str("failed to encrypt AES-GCM voice packet"),
            Self::XChaCha20Poly1305DecryptFailed => {
                f.write_str("failed to decrypt XChaCha20-Poly1305 voice packet")
            }
            Self::XChaCha20Poly1305EncryptFailed => {
                f.write_str("failed to encrypt XChaCha20-Poly1305 voice packet")
            }
            Self::UnsupportedMode { mode, direction } => {
                write!(
                    f,
                    "unsupported voice encryption mode for {direction}: {mode:?}"
                )
            }
        }
    }
}

impl std::error::Error for TransportCryptoError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportCryptoDirection {
    Session,
    Send,
    Receive,
}

impl fmt::Display for TransportCryptoDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session => f.write_str("session"),
            Self::Send => f.write_str("send"),
            Self::Receive => f.write_str("receive"),
        }
    }
}

#[derive(Debug)]
pub enum DaveError {
    InvalidProtocolVersion {
        version: u16,
    },
    CreateSession(InitError),
    SetExternalSender(SetExternalSenderError),
    CreateKeyPackage(CreateKeyPackageError),
    ProcessProposals(ProcessProposalsError),
    ProcessWelcome(ProcessWelcomeError),
    ProcessCommit(ProcessCommitError),
    RecoverInvalidGroup {
        operation: &'static str,
        original: Box<DaveError>,
        recovery: Box<Error>,
    },
    InvalidGatewayPayload(DaveGatewayPayloadError),
    InvalidProposalsPayload(DaveProposalsPayloadError),
    Encrypt(EncryptError),
    Decrypt(DaveDecryptError),
}

impl fmt::Display for DaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolVersion { version } => {
                write!(f, "unsupported DAVE protocol version {version}")
            }
            Self::CreateSession(error) => write!(f, "failed to create DAVE session: {error}"),
            Self::SetExternalSender(error) => {
                write!(f, "failed to set DAVE external sender: {error}")
            }
            Self::CreateKeyPackage(error) => {
                write!(f, "failed to create DAVE key package: {error}")
            }
            Self::ProcessProposals(error) => {
                write!(f, "failed to process DAVE proposals: {error}")
            }
            Self::ProcessWelcome(error) => {
                write!(f, "failed to process DAVE welcome: {error}")
            }
            Self::ProcessCommit(error) => write!(f, "failed to process DAVE commit: {error}"),
            Self::RecoverInvalidGroup {
                operation,
                original,
                recovery,
            } => {
                write!(
                    f,
                    "failed to recover invalid DAVE group after {operation} error ({original}): {recovery}",
                )
            }
            Self::InvalidGatewayPayload(error) => {
                write!(f, "invalid DAVE gateway payload: {error}")
            }
            Self::InvalidProposalsPayload(error) => {
                write!(f, "invalid DAVE proposals payload: {error}")
            }
            Self::Encrypt(error) => write!(f, "{error}"),
            Self::Decrypt(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateSession(error) => Some(error),
            Self::SetExternalSender(error) => Some(error),
            Self::CreateKeyPackage(error) => Some(error),
            Self::ProcessProposals(error) => Some(error),
            Self::ProcessWelcome(error) => Some(error),
            Self::ProcessCommit(error) => Some(error),
            Self::RecoverInvalidGroup { original, .. } => Some(original.as_ref()),
            Self::InvalidGatewayPayload(error) => Some(error),
            Self::InvalidProposalsPayload(error) => Some(error),
            Self::Encrypt(error) => Some(error),
            Self::Decrypt(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaveGatewayPayloadError {
    PayloadTooShort {
        opcode: u8,
        len: usize,
        min_len: usize,
    },
}

impl fmt::Display for DaveGatewayPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooShort {
                opcode,
                len,
                min_len,
            } => write!(
                f,
                "opcode {opcode} payload is {len} bytes, expected at least {min_len}",
            ),
        }
    }
}

impl std::error::Error for DaveGatewayPayloadError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaveProposalsPayloadError {
    MissingOperation,
    InvalidOperation { operation: u8 },
}

impl fmt::Display for DaveProposalsPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOperation => f.write_str("missing proposals operation byte"),
            Self::InvalidOperation { operation } => {
                write!(f, "invalid proposals operation byte {operation}")
            }
        }
    }
}

impl std::error::Error for DaveProposalsPayloadError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaveDecryptError {
    MissingUser,
    Source(DecryptError),
}

impl DaveDecryptError {
    pub(crate) fn receive_decode_kind(&self) -> ReceiveDecodeErrorKind {
        match self {
            Self::MissingUser => ReceiveDecodeErrorKind::MissingDaveUser,
            Self::Source(DecryptError::NoDecryptorForUser { .. }) => {
                ReceiveDecodeErrorKind::DaveNoDecryptorForUser
            }
            Self::Source(DecryptError::Frame(FrameDecryptError::NoValidCryptor { .. })) => {
                ReceiveDecodeErrorKind::DaveNoValidCryptor
            }
            Self::Source(DecryptError::Frame(FrameDecryptError::PassthroughDisabled)) => {
                ReceiveDecodeErrorKind::DaveUnencryptedWhenPassthroughDisabled
            }
            Self::Source(DecryptError::Frame(
                FrameDecryptError::MalformedFrame
                | FrameDecryptError::ReplayedNonce
                | FrameDecryptError::MissingCryptor { .. }
                | FrameDecryptError::Aead { .. }
                | FrameDecryptError::OutputTooSmall { .. }
                | FrameDecryptError::InvalidKey,
            )) => ReceiveDecodeErrorKind::DaveOtherDecryptError,
        }
    }

    pub(crate) fn is_no_valid_cryptor(&self) -> bool {
        matches!(
            self,
            Self::Source(DecryptError::Frame(
                FrameDecryptError::NoValidCryptor { .. }
            ))
        )
    }
}

impl fmt::Display for DaveDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUser => f.write_str("DAVE frame decrypt requires mapped user_id"),
            Self::Source(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DaveDecryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingUser => None,
            Self::Source(error) => Some(error),
        }
    }
}

impl From<DecryptError> for DaveDecryptError {
    fn from(error: DecryptError) -> Self {
        Self::Source(error)
    }
}
