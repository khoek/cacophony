use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    str::Utf8Error,
    time::Duration,
};

use dave::{
    Codec, CreateKeyPackageError, DecryptError, EncryptError, FrameDecryptError, InitError,
    ProcessCommitError, ProcessProposalsError, ProcessWelcomeError, SetExternalSenderError,
    UpdateRatchetsError,
};
use thiserror::Error as ThisError;

use crate::{
    observer::{ConnectStage, ReceiveDecodeErrorKind},
    rtp::RtpPayloadType,
    state::{EncryptionMode, OfferedEncryptionMode},
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

impl Error {
    pub fn receive_decode_kind(&self) -> Option<ReceiveDecodeErrorKind> {
        match self {
            Self::Rtp(_) => Some(ReceiveDecodeErrorKind::MalformedRtp),
            Self::UnsupportedCodec(_) => Some(ReceiveDecodeErrorKind::UnsupportedCodec),
            Self::TransportCrypto(_) => Some(ReceiveDecodeErrorKind::TransportDecryptFailed),
            Self::Dave(DaveError::Decrypt(error)) => Some(error.receive_decode_kind()),
            Self::Opus(_) => Some(ReceiveDecodeErrorKind::OpusDecodeFailed),
            _ => None,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum PcmError {
    #[error("PCM sample rate must be greater than zero")]
    SampleRateZero,
    #[error("PCM channel count must be greater than zero")]
    ChannelCountZero,
    #[error("{encoding} PCM byte length {byte_len} is not aligned to {sample_bytes}-byte samples")]
    SampleAlignment {
        encoding: &'static str,
        byte_len: usize,
        sample_bytes: usize,
    },
    #[error("PCM sample count {samples} is not aligned to {channels} channels")]
    ChannelAlignment { channels: usize, samples: usize },
    #[error("PCM encoding `{0}` is not supported")]
    UnsupportedEncoding(String),
    #[error("PCM resampler chunk frame count must be greater than zero")]
    ResamplerChunkFramesZero,
    #[error("PCM resampler is not initialized")]
    ResamplerNotInitialized,
    #[error("PCM resampler error: {0}")]
    Resampler(String),
}

#[derive(Debug, ThisError)]
pub enum InvalidInputError {
    #[error("connection tuning field {field} must be greater than zero")]
    ConnectionTuningZero { field: &'static str },
    #[error("connection tuning field {field} must be at least {min}, got {actual}")]
    ConnectionTuningTooSmall {
        field: &'static str,
        min: usize,
        actual: usize,
    },
    #[error("connection tuning duration {field} must be nonzero")]
    ConnectionTuningDurationZero { field: &'static str },
    #[error("Discord voice gateway version {version} is unsupported")]
    UnsupportedGatewayVersion { version: u8 },
    #[error("{} cannot be configured as a Discord video codec", codec.as_str())]
    VideoCodecPreferenceNotVideo { codec: Codec },
    #[error("{} appears more than once in Discord video codec preferences", codec.as_str())]
    DuplicateVideoCodecPreference { codec: Codec },
    #[error("max_len must be greater than zero")]
    ZeroMaxLen,
    #[error("{} frame must not be empty", codec.as_str())]
    EmptyPayload { codec: Codec },
    #[error("Discord PCM block must contain {expected} interleaved f32 samples, got {actual}")]
    PcmBlockSampleCount { expected: usize, actual: usize },
    #[error("Discord PCM block must contain {expected} samples per channel, got {actual}")]
    PcmBlockFrameCount { expected: usize, actual: usize },
    #[error("captured PCM audio must not be empty")]
    PcmArchiveEmpty,
    #[error("Ogg Opus vendor must not be empty")]
    OggOpusVendorEmpty,
    #[error("Ogg Opus archive encoding does not support {sample_rate_hz} Hz captured audio")]
    OggOpusUnsupportedSampleRate { sample_rate_hz: u32 },
    #[error("Discord PCM playback received mixed sample rates: {existing} and {actual}")]
    DiscordPcmMixedSampleRates { existing: u32, actual: u32 },
    #[error("Discord PCM playback received mixed channel counts: {existing} and {actual}")]
    DiscordPcmMixedChannelCounts { existing: usize, actual: usize },
    #[error("Discord PCM playback received mixed PCM encodings")]
    DiscordPcmMixedEncoding,
    #[error("Discord PCM encoder was not initialized")]
    DiscordPcmEncoderUninitialized,
    #[error("Opus bitrate {bitrate_bps} bps exceeds the encoder limit")]
    OpusBitrateTooLarge { bitrate_bps: u32 },
    #[error("Opus output buffer must be at least {min_len} bytes, got {len}")]
    OpusOutputBufferTooSmall { min_len: usize, len: usize },
}

#[derive(Debug, ThisError)]
pub enum ProtocolError {
    #[error("DAVE MLS key package and commit/welcome use binary websocket frames")]
    TextPayloadRequiresBinaryDaveMlsCommand,
    #[error("voice discovery packet must be at least {min_len} bytes, got {len}")]
    UdpDiscoveryPacketTooShort { len: usize, min_len: usize },
    #[error(
        "unexpected voice discovery packet type {packet_type}; expected {expected_packet_type}"
    )]
    UnexpectedUdpDiscoveryPacketType {
        packet_type: u16,
        expected_packet_type: u16,
    },
    #[error(
        "unexpected voice discovery packet length {packet_len}; expected {expected_packet_len}"
    )]
    UnexpectedUdpDiscoveryPacketLen {
        packet_len: u16,
        expected_packet_len: u16,
    },
    #[error("invalid voice discovery ip: {0}")]
    InvalidUdpDiscoveryIp(#[source] Utf8Error),
    #[error("voice ready payload did not include encryption modes")]
    ReadyMissingEncryptionModes,
    #[error("required voice encryption mode {required_mode} was not offered: {modes:?}")]
    RequiredEncryptionModeUnavailable {
        required_mode: EncryptionMode,
        modes: Vec<OfferedEncryptionMode>,
    },
    #[error("voice ready payload did not include a supported encryption mode: {modes:?}")]
    ReadyMissingSupportedEncryptionMode { modes: Vec<OfferedEncryptionMode> },
    #[error("resolve voice websocket endpoint {host}:{port}: {source}")]
    ResolveWebSocketEndpoint {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("voice websocket endpoint {host}:{port} did not resolve to any addresses")]
    WebSocketEndpointNoAddresses { host: String, port: u16 },
    #[error("voice websocket connect to {address} timed out after {duration:?}")]
    WebSocketAddressConnectTimeout {
        address: SocketAddr,
        duration: Duration,
    },
    #[error(
        "voice websocket connect to {host}:{port} failed across {address_count} resolved addresses: {}",
        errors.join("; ")
    )]
    WebSocketAllAddressesFailed {
        host: String,
        port: u16,
        address_count: usize,
        errors: Vec<String>,
    },
    #[error("tcp connect {address}: {source}")]
    TcpConnect {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("voice websocket URL did not include a host")]
    WebSocketUrlMissingHost,
    #[error("voice websocket URL did not include a usable scheme")]
    WebSocketUrlMissingUsableScheme,
    #[error("invalid Discord voice UDP IP {remote_ip:?}: {source}")]
    InvalidDiscordVoiceUdpIp {
        remote_ip: String,
        #[source]
        source: AddrParseError,
    },
    #[error("voice heartbeat ACK timed out")]
    HeartbeatAckTimeout,
    #[error("missing voice session description")]
    MissingSessionDescription,
    #[error("Discord voice session did not negotiate {} transmission; negotiated {negotiated_codec:?}", codec.as_str())]
    MediaCodecNotNegotiated {
        codec: Codec,
        negotiated_codec: Option<Codec>,
    },
    #[error("Discord voice ready payload did not include a video SSRC for {}", codec.as_str())]
    MissingVideoSsrc { codec: Codec },
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

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum OpusError {
    #[error("failed to {operation}: {reason}")]
    OperationFailed {
        operation: OpusOperation,
        reason: &'static str,
    },
    #[error("unsupported voice codec {}", codec.as_str())]
    UnsupportedVoiceCodec { codec: Codec },
    #[error("unsupported Opus channel count {channels}")]
    UnsupportedChannelCount { channels: usize },
    #[error("invalid Opus packet: {reason}")]
    InvalidPacket { reason: &'static str },
    #[error(
        "Discord Opus packet must contain {expected_samples_per_channel} samples per channel, got {actual_samples_per_channel}"
    )]
    UnsupportedDiscordPacketDuration {
        expected_samples_per_channel: usize,
        actual_samples_per_channel: usize,
    },
    #[error("Opus resampler is not initialized")]
    ResamplerNotInitialized,
    #[error("Opus resampler error: {0}")]
    Resampler(String),
    #[error("Opus frame is empty")]
    EmptyFrame,
    #[error("Ogg Opus asset is empty")]
    OggOpusEmpty,
    #[error("failed to read Ogg Opus packet: {0}")]
    OggOpusRead(String),
    #[error("Ogg Opus asset contains no packets")]
    OggOpusNoPackets,
    #[error("first Ogg Opus packet is not marked as the start of stream")]
    OggOpusHeaderNotStart,
    #[error("Ogg stream is not Opus")]
    OggOpusMissingHead,
    #[error("unsupported OpusHead version {version}")]
    OggOpusUnsupportedVersion { version: u8 },
    #[error("Ogg Opus channel count must be 1 or 2, got {channels}")]
    OggOpusUnsupportedChannelCount { channels: u8 },
    #[error("Ogg Opus mapping family must be 0, got {mapping_family}")]
    OggOpusUnsupportedMappingFamily { mapping_family: u8 },
    #[error("Ogg Opus asset is missing OpusTags packet")]
    OggOpusMissingTags,
    #[error("Ogg Opus asset contains multiple logical streams")]
    OggOpusMultipleLogicalStreams,
    #[error("Ogg Opus asset contains no audio packets")]
    OggOpusNoAudioPackets,
    #[error("Ogg Opus asset contains no audio after pre-skip")]
    OggOpusNoAudioAfterPreSkip,
    #[error("Ogg Opus asset decoded to empty audio")]
    OggOpusDecodedEmpty,
    #[error("Ogg Opus output sample rate {sample_rate_hz} exceeds the decoder limit")]
    OggOpusOutputSampleRateTooLarge { sample_rate_hz: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ThisError)]
pub enum BackpressureError {
    #[error("voice connection command queue is full")]
    CommandQueueFull,
    #[error("voice connection media queue is full")]
    MediaQueueFull,
    #[error("voice connection already has an active Opus playout")]
    ActiveOpusPlayout,
    #[error("voice connection already has an active media frame stream")]
    ActiveFrameStream,
}

#[derive(Debug, ThisError)]
pub enum ConnectionJoinError {
    #[error("voice control task join failed: {0}")]
    ControlTaskJoinFailed(#[source] tokio::task::JoinError),
    #[error("voice join task is closed")]
    JoinTaskClosed,
    #[error("voice join task stopped before replying")]
    JoinTaskStoppedBeforeReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    RawUdpPacket,
    RtpPacket,
    Frame,
}

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum UnsupportedCodecError {
    #[error("unsupported Discord voice audio codec {codec:?}; only Opus is supported")]
    UnsupportedAudioCodec { codec: String },
    #[error("unsupported Discord voice video codec {codec:?}")]
    UnsupportedVideoCodec { codec: String },
    #[error(
        "unsupported Discord voice RTP payload type {payload_type}; expected one of {expected_payload_types:?}"
    )]
    UnsupportedRtpPayloadType {
        payload_type: RtpPayloadType,
        expected_payload_types: Vec<RtpPayloadType>,
    },
    #[error(
        "Discord voice RTP payload type {payload_type} is {}; negotiated payload types are {expected_payload_types:?}",
        codec.as_str()
    )]
    UnexpectedRtpPayloadCodec {
        payload_type: RtpPayloadType,
        codec: Codec,
        expected_payload_types: Vec<RtpPayloadType>,
    },
}

impl fmt::Display for PayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawUdpPacket => f.write_str("raw UDP packet"),
            Self::RtpPacket => f.write_str("RTP packet"),
            Self::Frame => f.write_str("voice frame"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum RtpError {
    #[error("voice RTP packet is shorter than 12 bytes: {len}")]
    PacketTooShort { len: usize },
    #[error("unsupported voice RTP version {version}; expected 2")]
    UnsupportedVersion { version: u8 },
    #[error(
        "voice RTP packet has truncated CSRC list: {len} bytes for {expected_header_len} byte header"
    )]
    TruncatedCsrcList {
        len: usize,
        expected_header_len: usize,
    },
    #[error(
        "voice RTP packet has truncated extension header: {len} bytes for {expected_header_len} byte header"
    )]
    TruncatedExtensionHeader {
        len: usize,
        expected_header_len: usize,
    },
    #[error(
        "voice RTP packet has truncated extension payload: {len} bytes for {expected_header_len} byte header"
    )]
    TruncatedExtensionPayload {
        len: usize,
        expected_header_len: usize,
    },
    #[error("voice RTP packet has truncated encrypted extension")]
    TruncatedEncryptedExtension,
    #[error("voice RTP packet has empty padded payload")]
    EmptyPaddedPayload,
    #[error(
        "voice RTP packet has invalid padding length {padding} for payload length {payload_len}"
    )]
    InvalidPadding { padding: usize, payload_len: usize },
    #[error(
        "{} RTP payload is {payload_len} bytes, exceeding the per-packet media payload limit {max_payload_len}",
        codec.as_str()
    )]
    PayloadTooLarge {
        codec: Codec,
        payload_len: usize,
        max_payload_len: usize,
    },
    #[error("malformed {} RTP payload: {reason}", codec.as_str())]
    MalformedPayload { codec: Codec, reason: &'static str },
}

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum TransportCryptoError {
    #[error("voice secret_key must be 32 bytes, got {len}")]
    InvalidSecretKeyLen { len: usize },
    #[error(
        "voice RTP packet is missing the RTP-size nonce suffix: {packet_len} bytes for minimum {min_len}"
    )]
    MissingRtpSizeNonce { packet_len: usize, min_len: usize },
    #[error("failed to initialize voice nonce from OS randomness")]
    NonceRandomnessUnavailable,
    #[error("invalid AES-GCM voice secret key")]
    InvalidAesGcmKey,
    #[error("invalid XChaCha20-Poly1305 voice secret key")]
    InvalidXChaCha20Poly1305Key,
    #[error("failed to decrypt AES-GCM voice packet")]
    AesGcmDecryptFailed,
    #[error("failed to encrypt AES-GCM voice packet")]
    AesGcmEncryptFailed,
    #[error("failed to decrypt XChaCha20-Poly1305 voice packet")]
    XChaCha20Poly1305DecryptFailed,
    #[error("failed to encrypt XChaCha20-Poly1305 voice packet")]
    XChaCha20Poly1305EncryptFailed,
}

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

#[derive(Debug, ThisError)]
pub enum DaveError {
    #[error("unsupported DAVE protocol version {version}")]
    InvalidProtocolVersion { version: u16 },
    #[error("failed to create DAVE session: {0}")]
    CreateSession(#[source] InitError),
    #[error("failed to set DAVE external sender: {0}")]
    SetExternalSender(#[source] SetExternalSenderError),
    #[error("failed to create DAVE key package: {0}")]
    CreateKeyPackage(#[source] CreateKeyPackageError),
    #[error("failed to process DAVE proposals: {0}")]
    ProcessProposals(#[source] ProcessProposalsError),
    #[error("failed to process DAVE welcome: {0}")]
    ProcessWelcome(#[source] ProcessWelcomeError),
    #[error("failed to process DAVE commit: {0}")]
    ProcessCommit(#[source] ProcessCommitError),
    #[error("failed to update DAVE media ratchets: {0}")]
    UpdateRatchets(#[source] UpdateRatchetsError),
    #[error(
        "failed to recover invalid DAVE group after {operation} error ({original}): {recovery}"
    )]
    RecoverInvalidGroup {
        operation: &'static str,
        #[source]
        original: Box<DaveError>,
        recovery: Box<Error>,
    },
    #[error("invalid DAVE gateway payload: {0}")]
    InvalidGatewayPayload(#[source] DaveGatewayPayloadError),
    #[error("invalid DAVE proposals payload: {0}")]
    InvalidProposalsPayload(#[source] DaveProposalsPayloadError),
    #[error("{0}")]
    Encrypt(#[source] EncryptError),
    #[error("{0}")]
    Decrypt(#[source] DaveDecryptError),
}

impl DaveError {
    pub(crate) fn recover_invalid_group(
        operation: &'static str,
        original: Self,
        recovery: Error,
    ) -> Error {
        match recovery {
            Error::Dave(_) => Self::RecoverInvalidGroup {
                operation,
                original: Box::new(original),
                recovery: Box::new(recovery),
            }
            .into(),
            _ => recovery,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum DaveGatewayPayloadError {
    #[error("opcode {opcode} payload is {len} bytes, expected at least {min_len}")]
    PayloadTooShort {
        opcode: u8,
        len: usize,
        min_len: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum DaveProposalsPayloadError {
    #[error("missing proposals operation byte")]
    MissingOperation,
    #[error("invalid proposals operation byte {operation}")]
    InvalidOperation { operation: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
pub enum DaveDecryptError {
    #[error("DAVE frame decrypt requires mapped user_id")]
    MissingUser,
    #[error("{0}")]
    Source(#[source] DecryptError),
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

impl From<DecryptError> for DaveDecryptError {
    fn from(error: DecryptError) -> Self {
        Self::Source(error)
    }
}
