use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    future::Future,
    net::SocketAddr,
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce, Tag as AesTag,
    aead::{AeadInPlace, KeyInit},
};
use anyhow::Context as _;
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use davey::{
    DAVE_PROTOCOL_VERSION, DaveSession, MediaType, ProposalsOperationType,
    errors::{DecryptError, DecryptorDecryptError, EncryptError},
};
use futures_util::{
    SinkExt, StreamExt,
    stream::{FuturesUnordered, SplitSink, SplitStream},
};
use opus_rs::{
    Application as OpusApplication, OpusDecoder as RawOpusDecoder, OpusEncoder as RawOpusEncoder,
};
use parking_lot::Mutex as SyncMutex;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};
use serde_json::Value;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{Mutex, Notify, mpsc, watch},
    task::JoinHandle,
    time::{Instant, interval, sleep, timeout},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{
        Message as WsMessage,
        client::IntoClientRequest,
        handshake::client::Response as WebSocketResponse,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum VoiceOpcode {
    Identify = 0,
    SelectProtocol = 1,
    Ready = 2,
    Heartbeat = 3,
    SessionDescription = 4,
    Speaking = 5,
    HeartbeatAck = 6,
    Resume = 7,
    Hello = 8,
    Resumed = 9,
    ClientsConnect = 11,
    ClientConnect = 12,
    ClientDisconnect = 13,
    DavePrepareTransition = 21,
    DaveExecuteTransition = 22,
    DaveTransitionReady = 23,
    DavePrepareEpoch = 24,
    DaveMlsExternalSender = 25,
    DaveMlsKeyPackage = 26,
    DaveMlsProposals = 27,
    DaveMlsCommitWelcome = 28,
    DaveMlsAnnounceCommitTransition = 29,
    DaveMlsWelcome = 30,
    DaveMlsInvalidCommitWelcome = 31,
}

impl VoiceOpcode {
    const ALL: [Self; 24] = [
        Self::Identify,
        Self::SelectProtocol,
        Self::Ready,
        Self::Heartbeat,
        Self::SessionDescription,
        Self::Speaking,
        Self::HeartbeatAck,
        Self::Resume,
        Self::Hello,
        Self::Resumed,
        Self::ClientsConnect,
        Self::ClientConnect,
        Self::ClientDisconnect,
        Self::DavePrepareTransition,
        Self::DaveExecuteTransition,
        Self::DaveTransitionReady,
        Self::DavePrepareEpoch,
        Self::DaveMlsExternalSender,
        Self::DaveMlsKeyPackage,
        Self::DaveMlsProposals,
        Self::DaveMlsCommitWelcome,
        Self::DaveMlsAnnounceCommitTransition,
        Self::DaveMlsWelcome,
        Self::DaveMlsInvalidCommitWelcome,
    ];

    const fn code(self) -> u64 {
        self as u8 as u64
    }

    const fn byte(self) -> u8 {
        self as u8
    }

    fn from_code(code: u64) -> Option<Self> {
        let byte = u8::try_from(code).ok()?;
        Self::from_byte(byte)
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|opcode| opcode.byte() == byte)
    }

    fn from_server_binary(byte: u8) -> Option<Self> {
        Self::from_byte(byte).filter(|opcode| opcode.is_server_binary())
    }

    const fn is_server_binary(self) -> bool {
        matches!(
            self,
            Self::DaveMlsExternalSender
                | Self::DaveMlsProposals
                | Self::DaveMlsAnnounceCommitTransition
                | Self::DaveMlsWelcome
        )
    }
}
const VOICE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const VOICE_WEBSOCKET_ADDRESS_STAGGER: Duration = Duration::from_millis(125);
const VOICE_WEBSOCKET_ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const VOICE_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const VOICE_READY_TIMEOUT: Duration = Duration::from_secs(10);
const VOICE_UDP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const VOICE_SESSION_DESCRIPTION_TIMEOUT: Duration = Duration::from_secs(10);
const DAVE_SEND_MEDIA_READY_TIMEOUT: Duration = Duration::from_secs(20);
const VOICE_AEAD_TAG_LEN: usize = 16;
const VOICE_RTPSIZE_NONCE_LEN: usize = 4;
const RTP_VERSION: u8 = 2;
const RTP_PAYLOAD_TYPE_OPUS: u8 = 120;
const DISCORD_OPUS_SAMPLE_RATE: u32 = 48_000;
const DISCORD_OPUS_CHANNELS: usize = 2;
const DISCORD_OPUS_SAMPLES_PER_CHANNEL: usize = 960;
const DISCORD_OPUS_STEREO_FRAME_SAMPLES: usize =
    DISCORD_OPUS_CHANNELS * DISCORD_OPUS_SAMPLES_PER_CHANNEL;
const DISCORD_OPUS_FRAME_MS: u64 = 20;
const JS_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const DAVE_PENDING_MEDIA_TTL: Duration = Duration::from_secs(10);
const RECEIVE_INTERARRIVAL_WINDOW: usize = 256;

type VoiceWebSocketStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type VoiceWebSocketConnectResult = (VoiceWebSocketStream, WebSocketResponse);
type VoiceWebSocketRead = SplitStream<VoiceWebSocketStream>;
type VoiceWebSocketWrite = SplitSink<VoiceWebSocketStream, WsMessage>;

#[derive(Debug)]
pub enum VoiceError {
    InvalidInput(String),
    Protocol(String),
    Timeout {
        stage: Option<VoiceConnectStage>,
        duration: Duration,
    },
    Io(std::io::Error),
    Json(serde_json::Error),
    WebSocket(tokio_tungstenite::tungstenite::Error),
    Opus(String),
    Dave(VoiceDaveError),
    Backpressure(String),
    Closed,
    Join(String),
    Internal(String),
}

impl VoiceError {
    fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    fn opus(message: impl Into<String>) -> Self {
        Self::Opus(message.into())
    }
}

impl fmt::Display for VoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => f.write_str(message),
            Self::Protocol(message) => f.write_str(message),
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
            Self::Opus(message) => f.write_str(message),
            Self::Dave(error) => write!(f, "{error}"),
            Self::Backpressure(message) => f.write_str(message),
            Self::Closed => f.write_str("voice connection is closed"),
            Self::Join(message) => f.write_str(message),
            Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for VoiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::WebSocket(error) => Some(error),
            Self::Dave(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VoiceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for VoiceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for VoiceError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(error)
    }
}

impl From<VoiceDaveError> for VoiceError {
    fn from(error: VoiceDaveError) -> Self {
        Self::Dave(error)
    }
}

impl From<anyhow::Error> for VoiceError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

pub type VoiceResult<T> = Result<T, VoiceError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceDaveError {
    InvalidProtocolVersion { version: u16 },
    CreateSession { detail: String },
    SetExternalSender { detail: String },
    CreateKeyPackage { detail: String },
    ProcessProposals { detail: String },
    ProcessWelcome { detail: String },
    ProcessCommit { detail: String },
    RecoverInvalidGroup { detail: String },
    InvalidProposalsPayload { detail: String },
    Encrypt(VoiceDaveEncryptError),
    Decrypt(VoiceDaveDecryptError),
}

impl fmt::Display for VoiceDaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolVersion { version } => {
                write!(f, "unsupported DAVE protocol version {version}")
            }
            Self::CreateSession { detail } => write!(f, "failed to create DAVE session: {detail}"),
            Self::SetExternalSender { detail } => {
                write!(f, "failed to set DAVE external sender: {detail}")
            }
            Self::CreateKeyPackage { detail } => {
                write!(f, "failed to create DAVE key package: {detail}")
            }
            Self::ProcessProposals { detail } => {
                write!(f, "failed to process DAVE proposals: {detail}")
            }
            Self::ProcessWelcome { detail } => {
                write!(f, "failed to process DAVE welcome: {detail}")
            }
            Self::ProcessCommit { detail } => write!(f, "failed to process DAVE commit: {detail}"),
            Self::RecoverInvalidGroup { detail } => {
                write!(f, "failed to recover invalid DAVE group: {detail}")
            }
            Self::InvalidProposalsPayload { detail } => {
                write!(f, "invalid DAVE proposals payload: {detail}")
            }
            Self::Encrypt(error) => write!(f, "{error}"),
            Self::Decrypt(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for VoiceDaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encrypt(error) => Some(error),
            Self::Decrypt(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceDaveEncryptError {
    NotReady,
    EncryptionFailed,
}

impl fmt::Display for VoiceDaveEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => f.write_str("DAVE session is not ready to encrypt packets"),
            Self::EncryptionFailed => f.write_str("DAVE packet encryption failed"),
        }
    }
}

impl std::error::Error for VoiceDaveEncryptError {}

impl From<EncryptError> for VoiceDaveEncryptError {
    fn from(error: EncryptError) -> Self {
        match error {
            EncryptError::NotReady => Self::NotReady,
            EncryptError::EncryptionFailed => Self::EncryptionFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceDaveMediaType {
    Audio,
    Video,
}

impl fmt::Display for VoiceDaveMediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audio => f.write_str("audio"),
            Self::Video => f.write_str("video"),
        }
    }
}

impl From<MediaType> for VoiceDaveMediaType {
    fn from(media_type: MediaType) -> Self {
        match media_type {
            MediaType::AUDIO => Self::Audio,
            MediaType::VIDEO => Self::Video,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceDaveDecryptError {
    MissingUser,
    NoDecryptorForUser,
    NoValidCryptor {
        media_type: VoiceDaveMediaType,
        encrypted_size: usize,
        plaintext_size: usize,
        manager_count: usize,
    },
    UnencryptedWhenPassthroughDisabled,
}

impl VoiceDaveDecryptError {
    fn receive_decode_kind(&self) -> VoiceReceiveDecodeErrorKind {
        match self {
            Self::MissingUser => VoiceReceiveDecodeErrorKind::MissingDaveUser,
            Self::NoDecryptorForUser => VoiceReceiveDecodeErrorKind::DaveNoDecryptorForUser,
            Self::NoValidCryptor { .. } => VoiceReceiveDecodeErrorKind::DaveNoValidCryptor,
            Self::UnencryptedWhenPassthroughDisabled => {
                VoiceReceiveDecodeErrorKind::DaveUnencryptedWhenPassthroughDisabled
            }
        }
    }
}

impl fmt::Display for VoiceDaveDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUser => f.write_str("DAVE frame decrypt requires mapped user_id"),
            Self::NoDecryptorForUser => f.write_str("DAVE user has no decryptor"),
            Self::NoValidCryptor {
                media_type,
                encrypted_size,
                plaintext_size,
                manager_count,
            } => write!(
                f,
                "no valid DAVE cryptor found for {media_type}, encrypted size {encrypted_size}, \
                 plaintext size {plaintext_size}, manager count {manager_count}",
            ),
            Self::UnencryptedWhenPassthroughDisabled => {
                f.write_str("DAVE frame was unencrypted while passthrough was disabled")
            }
        }
    }
}

impl std::error::Error for VoiceDaveDecryptError {}

impl From<DecryptError> for VoiceDaveDecryptError {
    fn from(error: DecryptError) -> Self {
        match error {
            DecryptError::NoDecryptorForUser => Self::NoDecryptorForUser,
            DecryptError::DecryptionFailed(
                DecryptorDecryptError::UnencryptedWhenPassthroughDisabled,
            ) => Self::UnencryptedWhenPassthroughDisabled,
            DecryptError::DecryptionFailed(DecryptorDecryptError::NoValidCryptorFound {
                media_type,
                encrypted_size,
                plaintext_size,
                manager_count,
            }) => Self::NoValidCryptor {
                media_type: media_type.into(),
                encrypted_size,
                plaintext_size,
                manager_count,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopVoiceConnectionObserver;

pub trait VoiceConnectionObserver: Clone + Send + Sync + 'static {
    const ENABLE_TIMING: bool = false;
    const ENABLE_RECEIVE_TELEMETRY: bool = false;
    const ENABLE_RTCP: bool = false;

    fn connection_dropped(&self, _event: VoiceConnectionEvent<'_>) {}

    fn connect_stage_completed(&self, _event: VoiceConnectStageCompletedEvent<'_>) {}

    fn connect_stage_failed(&self, _event: VoiceConnectStageFailedEvent<'_>) {}

    fn control_task_failed(&self, _event: VoiceConnectionErrorEvent<'_>) {}

    fn websocket_command_failed(&self, _event: VoiceWebSocketCommandFailedEvent<'_>) {}

    fn websocket_text_event(&self, _event: VoiceWebSocketTextEvent<'_>) {}

    fn websocket_binary_event(&self, _event: VoiceWebSocketBinaryEvent<'_>) {}

    fn websocket_closed(&self, _event: VoiceWebSocketClosedEvent<'_>) {}

    fn websocket_read_failed(&self, _event: VoiceConnectionErrorEvent<'_>) {}

    fn websocket_stream_ended(&self, _event: VoiceConnectionEvent<'_>) {}

    fn udp_packet_received(&self, _event: VoiceUdpPacketReceivedEvent<'_>) {}

    fn udp_packet_sent(&self, _event: VoiceUdpPacketSentEvent<'_>) {}

    fn rtcp_packet_received(&self, _event: VoiceRtcpPacketEvent<'_>) {}

    fn clients_connected(&self, _event: VoiceClientsConnectedEvent<'_>) {}

    fn dave_gateway_state(&self, _event: VoiceDaveGatewayStateEvent) {}

    fn dave_external_sender_set(&self, _event: VoiceDaveKeyPackageEvent) {}

    fn dave_key_package_sent(&self, _event: VoiceDaveKeyPackageEvent) {}

    fn dave_proposals_processed(&self, _event: VoiceDaveProposalsEvent) {}

    fn dave_proposals_ignored(&self, _event: VoiceDaveIgnoredProposalsEvent) {}

    fn dave_transition_ready_sent(&self, _event: VoiceDaveTransitionEvent) {}

    fn receive_rtp_packet(&self, _event: VoiceReceiveRtpPacketEvent) {}

    fn receive_rtp_sequence_gap(&self, _event: VoiceReceiveRtpSequenceGapEvent) {}

    fn receive_decode_error(&self, _event: VoiceReceiveDecodeErrorEvent) {}

    fn dave_pending_media_enqueued(&self, _event: VoiceDavePendingMediaEvent) {}

    fn dave_pending_media_drained(&self, _event: VoiceDavePendingMediaEvent) {}

    fn dave_pending_media_dropped(&self, _event: VoiceDavePendingMediaEvent) {}
}

impl VoiceConnectionObserver for NoopVoiceConnectionObserver {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceConnectionEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
}

#[derive(Debug)]
pub struct VoiceConnectionErrorEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub error: &'a dyn fmt::Debug,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceWebSocketFrameKind {
    Text,
    Binary,
}

#[derive(Debug)]
pub struct VoiceWebSocketCommandFailedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub opcode: u64,
    pub frame_kind: VoiceWebSocketFrameKind,
    pub error: &'a dyn fmt::Debug,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceWebSocketTextEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub opcode: u64,
    pub sequence: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceWebSocketBinaryEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub bytes: usize,
    pub first_byte: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceWebSocketClosedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub frame: Option<VoiceWebSocketCloseFrame>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceWebSocketCloseFrame {
    pub code: String,
    pub reason: String,
    pub discord_call_terminated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceClientsConnectedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub user_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceConnectStage {
    WebSocketConnect,
    Hello,
    Ready,
    UdpDiscovery,
    SessionDescription,
}

impl VoiceConnectStage {
    fn label(self) -> &'static str {
        match self {
            Self::WebSocketConnect => "websocket connect",
            Self::Hello => "hello",
            Self::Ready => "ready",
            Self::UdpDiscovery => "UDP discovery",
            Self::SessionDescription => "session description",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceConnectStageCompletedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub stage: VoiceConnectStage,
    pub elapsed: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct VoiceConnectStageFailedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub stage: VoiceConnectStage,
    pub elapsed: Duration,
    pub error: &'a VoiceError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceUdpPacketReceivedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub bytes: usize,
    pub elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceUdpPacketSentEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub dave: bool,
    pub opus_bytes: usize,
    pub packet_bytes: usize,
    pub build_elapsed: Duration,
    pub send_elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceRtcpHeader {
    pub version: u8,
    pub padding: bool,
    pub report_count: u8,
    pub packet_type: u8,
    pub length_words: u16,
    pub ssrc: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceRtcpPacketEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub bytes: &'a [u8],
    pub header: Option<VoiceRtcpHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceReceiveRtpPacketEvent {
    pub ssrc: u32,
    pub user_id: Option<u64>,
    pub sequence: u16,
    pub timestamp: u32,
    pub payload_bytes: usize,
    pub interarrival_us: Option<u64>,
    pub interarrival_p95_us: Option<u64>,
    pub interarrival_max_us: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceReceiveRtpSequenceGapEvent {
    pub ssrc: u32,
    pub user_id: Option<u64>,
    pub expected_sequence: u16,
    pub received_sequence: u16,
    pub missing_packets: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceReceiveDecodeStage {
    Rtp,
    Transport,
    DaveFrame,
    DaveDecrypt,
    Opus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceReceiveDecodeErrorKind {
    MalformedRtp,
    TransportDecryptFailed,
    MalformedDaveFrame,
    MissingDaveUser,
    DaveSessionNotReady,
    DaveGatewayPending,
    DaveNoDecryptorForUser,
    DaveNoValidCryptor,
    DaveUnencryptedWhenPassthroughDisabled,
    DaveOtherDecryptError,
    OpusDecodeFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceReceiveDecodeErrorEvent {
    pub stage: VoiceReceiveDecodeStage,
    pub kind: VoiceReceiveDecodeErrorKind,
    pub ssrc: Option<u32>,
    pub user_id: Option<u64>,
    pub sequence: Option<u16>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceDavePendingMediaReason {
    MissingUser,
    SessionNotReady,
    GatewayPending,
    DecryptStatePending,
    NoValidCryptorPending,
    StableDecryptFailure,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDavePendingMediaEvent {
    pub reason: VoiceDavePendingMediaReason,
    pub ssrc: u32,
    pub user_id: Option<u64>,
    pub sequence: u16,
    pub pending_packets: usize,
    pub age_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VoiceConnectionConfig {
    pub server_id: u64,
    pub channel_id: u64,
    pub user_id: u64,
    pub session_id: String,
    pub token: String,
    pub endpoint: String,
    pub gateway_version: u8,
    pub preferred_mode: Option<VoiceEncryptionMode>,
    pub max_dave_protocol_version: Option<u16>,
}

impl fmt::Debug for VoiceConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoiceConnectionConfig")
            .field("server_id", &self.server_id)
            .field("channel_id", &self.channel_id)
            .field("user_id", &self.user_id)
            .field("session_id", &"<redacted>")
            .field("token", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("gateway_version", &self.gateway_version)
            .field("preferred_mode", &self.preferred_mode)
            .field("max_dave_protocol_version", &self.max_dave_protocol_version)
            .finish()
    }
}

impl VoiceConnectionConfig {
    pub fn new(
        server_id: u64,
        channel_id: u64,
        user_id: u64,
        session_id: impl Into<String>,
        token: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            server_id,
            channel_id,
            user_id,
            session_id: session_id.into(),
            token: token.into(),
            endpoint: endpoint.into(),
            gateway_version: 8,
            preferred_mode: Some(VoiceEncryptionMode::aead_aes256_gcm_rtpsize()),
            max_dave_protocol_version: Some(DAVE_PROTOCOL_VERSION),
        }
    }

    fn public_info(&self) -> VoiceConnectionInfo {
        VoiceConnectionInfo {
            server_id: self.server_id,
            channel_id: self.channel_id,
            user_id: self.user_id,
            endpoint: self.endpoint.clone(),
            gateway_version: self.gateway_version,
            max_dave_protocol_version: self.max_dave_protocol_version,
        }
    }

    fn websocket_url(&self) -> VoiceResult<String> {
        if self.gateway_version < 4 {
            return Err(VoiceError::invalid_input(format!(
                "Discord voice gateway version {} is unsupported",
                self.gateway_version
            )));
        }

        let mut endpoint = if self.endpoint.contains("://") {
            self.endpoint.clone()
        } else {
            format!("wss://{}", self.endpoint)
        };

        if !endpoint.contains("?v=") {
            let separator = if endpoint.contains('?') { "&" } else { "/?" };
            endpoint.push_str(separator);
            endpoint.push_str(&format!("v={}", self.gateway_version));
        }

        Ok(endpoint)
    }
}

impl VoiceWebSocketCloseFrame {
    fn from_frame(frame: &CloseFrame) -> Self {
        Self {
            code: format!("{:?}", frame.code),
            reason: frame.reason.to_string(),
            discord_call_terminated: matches!(frame.code, CloseCode::Library(4022)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VoiceEncryptionMode(String);

impl VoiceEncryptionMode {
    pub fn new(mode: impl Into<String>) -> Self {
        Self(mode.into())
    }

    pub fn aead_aes256_gcm_rtpsize() -> Self {
        Self::new("aead_aes256_gcm_rtpsize")
    }

    pub fn aead_xchacha20_poly1305_rtpsize() -> Self {
        Self::new("aead_xchacha20_poly1305_rtpsize")
    }
}

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct VoiceSessionDescription {
    pub mode: VoiceEncryptionMode,
    #[serde(default, skip_serializing)]
    secret_key: VoiceSecretKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_codec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dave_protocol_version: Option<u16>,
}

impl fmt::Debug for VoiceSessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoiceSessionDescription")
            .field("mode", &self.mode)
            .field("secret_key", &self.secret_key)
            .field("audio_codec", &self.audio_codec)
            .field("dave_protocol_version", &self.dave_protocol_version)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
struct VoiceSecretKey(Vec<u8>);

impl VoiceSecretKey {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for VoiceSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceConnectionInfo {
    pub server_id: u64,
    pub channel_id: u64,
    pub user_id: u64,
    pub endpoint: String,
    pub gateway_version: u8,
    pub max_dave_protocol_version: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceSessionState {
    pub mode: VoiceEncryptionMode,
    pub audio_codec: Option<String>,
    pub dave_protocol_version: Option<u16>,
}

impl From<&VoiceSessionDescription> for VoiceSessionState {
    fn from(description: &VoiceSessionDescription) -> Self {
        Self {
            mode: description.mode.clone(),
            audio_codec: description.audio_codec.clone(),
            dave_protocol_version: description.dave_protocol_version,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VoiceDaveState {
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub epoch: Option<u64>,
    pub prepare_epoch_sequence: u64,
    pub passthrough: bool,
    pub mls: VoiceDaveMlsState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VoiceDaveMlsState {
    pub external_sender: bool,
    pub pending: VoiceDavePendingMlsState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VoiceDavePendingMlsState {
    pub proposals: usize,
    pub commit: bool,
    pub welcome: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
struct VoiceDaveInternalState {
    protocol_version: Option<u16>,
    transition_id: Option<u16>,
    epoch: Option<u64>,
    #[serde(default)]
    prepare_epoch_sequence: u64,
    passthrough: bool,
    #[serde(default)]
    external_sender: Option<Vec<u8>>,
    #[serde(default)]
    proposals: Vec<Vec<u8>>,
    #[serde(default)]
    pending_commit: Option<Vec<u8>>,
    #[serde(default)]
    pending_welcome: Option<Vec<u8>>,
}

impl VoiceDaveInternalState {
    fn mls_state(&self) -> VoiceDaveMlsState {
        VoiceDaveMlsState {
            external_sender: self.external_sender.is_some(),
            pending: VoiceDavePendingMlsState {
                proposals: self.proposals.len(),
                commit: self.pending_commit.is_some(),
                welcome: self.pending_welcome.is_some(),
            },
        }
    }

    fn public_state(&self) -> VoiceDaveState {
        VoiceDaveState {
            protocol_version: self.protocol_version,
            transition_id: self.transition_id,
            epoch: self.epoch,
            prepare_epoch_sequence: self.prepare_epoch_sequence,
            passthrough: self.passthrough,
            mls: self.mls_state(),
        }
    }

    fn set_session_protocol(&mut self, protocol_version: Option<u16>) {
        if self.protocol_version != protocol_version {
            self.clear_pending_mls();
        }
        self.protocol_version = protocol_version;
        self.passthrough = protocol_version.unwrap_or(0) == 0;
    }

    fn prepare_transition(&mut self, transition_id: u16, protocol_version: u16) {
        if self.transition_id != Some(transition_id) {
            self.clear_pending_mls();
        }
        self.transition_id = Some(transition_id);
        self.protocol_version = Some(protocol_version);
        self.passthrough = protocol_version == 0;
        if self.epoch == Some(1) && transition_id == 0 && protocol_version > 0 {
            self.execute_transition(transition_id);
        }
    }

    fn prepare_epoch(&mut self, protocol_version: u16, epoch: u64) {
        self.prepare_epoch_sequence = self.prepare_epoch_sequence.saturating_add(1);
        if epoch == 1 || self.epoch != Some(epoch) {
            self.clear_pending_mls();
        }
        self.epoch = Some(epoch);
        self.protocol_version = Some(protocol_version);
        self.passthrough = protocol_version == 0;
    }

    fn execute_transition(&mut self, transition_id: u16) {
        if self.transition_id == Some(transition_id) {
            self.transition_id = None;
        }
        self.clear_pending_mls();
    }

    fn clear_pending_mls(&mut self) {
        self.proposals.clear();
        self.pending_commit = None;
        self.pending_welcome = None;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceConnectionState {
    pub connection: VoiceConnectionInfo,
    pub heartbeat_interval_ms: u64,
    pub last_sequence: Option<i64>,
    pub ready: VoiceGatewayReady,
    pub discovery: VoiceUdpDiscoveryPacket,
    pub selected_mode: VoiceEncryptionMode,
    pub session: Option<VoiceSessionState>,
    pub connected_user_ids: HashSet<u64>,
    pub ssrc_users: HashMap<u32, u64>,
    pub speaking: HashMap<u32, VoiceSpeakingUpdate>,
    pub dave: VoiceDaveState,
    pub resumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VoiceConnectionInternalState {
    config: VoiceConnectionConfig,
    heartbeat_interval_ms: u64,
    last_sequence: Option<i64>,
    ready: VoiceGatewayReady,
    discovery: VoiceUdpDiscoveryPacket,
    selected_mode: VoiceEncryptionMode,
    session_description: Option<VoiceSessionDescription>,
    connected_user_ids: HashSet<u64>,
    ssrc_users: HashMap<u32, u64>,
    speaking: HashMap<u32, VoiceSpeakingUpdate>,
    dave: VoiceDaveInternalState,
    roster_authoritative: bool,
    resumed: bool,
}

impl VoiceConnectionInternalState {
    fn public_state(&self) -> VoiceConnectionState {
        VoiceConnectionState {
            connection: self.config.public_info(),
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            last_sequence: self.last_sequence,
            ready: self.ready.clone(),
            discovery: self.discovery.clone(),
            selected_mode: self.selected_mode.clone(),
            session: self
                .session_description
                .as_ref()
                .map(VoiceSessionState::from),
            connected_user_ids: self.connected_user_ids.clone(),
            ssrc_users: self.ssrc_users.clone(),
            speaking: self.speaking.clone(),
            dave: self.dave.public_state(),
            resumed: self.resumed,
        }
    }

    fn connection_event(&self) -> VoiceConnectionEvent<'_> {
        VoiceConnectionEvent {
            endpoint: &self.config.endpoint,
            guild_id: self.config.server_id,
            user_id: self.config.user_id,
        }
    }
}

#[derive(Default)]
struct VoiceReceiveState {
    pending_dave_media: VecDeque<PendingVoiceMediaPacket>,
    ssrc: HashMap<u32, VoiceReceiveSsrcState>,
}

impl VoiceReceiveState {
    fn record_rtp_packet<O>(
        &mut self,
        observer: &O,
        rtp: &VoiceRtpHeader,
        user_id: Option<u64>,
        payload_bytes: usize,
    ) where
        O: VoiceConnectionObserver,
    {
        if !O::ENABLE_RECEIVE_TELEMETRY {
            return;
        }
        let now = Instant::now();
        let state = self.ssrc.entry(rtp.ssrc).or_default();
        let interarrival = state.last_arrival.map(|last| now.duration_since(last));
        if let Some(previous) = state.last_sequence {
            let expected = previous.wrapping_add(1);
            let missing = rtp.sequence.wrapping_sub(expected);
            if missing > 0 && missing < 0x8000 {
                observer.receive_rtp_sequence_gap(VoiceReceiveRtpSequenceGapEvent {
                    ssrc: rtp.ssrc,
                    user_id,
                    expected_sequence: expected,
                    received_sequence: rtp.sequence,
                    missing_packets: missing,
                });
            }
        }
        let interarrival_us = interarrival.map(duration_us);
        if let Some(interarrival_us) = interarrival_us {
            state.record_interarrival(interarrival_us);
        }
        state.last_arrival = Some(now);
        state.last_sequence = Some(rtp.sequence);
        observer.receive_rtp_packet(VoiceReceiveRtpPacketEvent {
            ssrc: rtp.ssrc,
            user_id,
            sequence: rtp.sequence,
            timestamp: rtp.timestamp,
            payload_bytes,
            interarrival_us,
            interarrival_p95_us: state.interarrival_p95_us(),
            interarrival_max_us: state.interarrival_max_us(),
        });
    }
}

#[derive(Default)]
struct VoiceReceiveSsrcState {
    last_arrival: Option<Instant>,
    last_sequence: Option<u16>,
    interarrival_order: VecDeque<u64>,
    interarrival_sorted: Vec<u64>,
}

impl VoiceReceiveSsrcState {
    fn record_interarrival(&mut self, interarrival_us: u64) {
        if self.interarrival_order.len() == RECEIVE_INTERARRIVAL_WINDOW
            && let Some(removed) = self.interarrival_order.pop_front()
            && let Ok(index) = self.interarrival_sorted.binary_search(&removed)
        {
            self.interarrival_sorted.remove(index);
        }
        let index = self
            .interarrival_sorted
            .partition_point(|value| *value <= interarrival_us);
        self.interarrival_sorted.insert(index, interarrival_us);
        self.interarrival_order.push_back(interarrival_us);
    }

    fn interarrival_p95_us(&self) -> Option<u64> {
        self.interarrival_sorted
            .get(((self.interarrival_sorted.len().saturating_sub(1)) * 95) / 100)
            .copied()
    }

    fn interarrival_max_us(&self) -> Option<u64> {
        self.interarrival_sorted.last().copied()
    }
}

struct PendingVoiceMediaPacket {
    raw: VoiceRawUdpPacket,
    rtp: VoiceRtpHeader,
    user_id: Option<u64>,
    transport_frame: Vec<u8>,
    enqueued_at: Instant,
    reason: VoiceDavePendingMediaReason,
    was_pending: bool,
}

impl PendingVoiceMediaPacket {
    fn event(
        &self,
        pending_packets: usize,
        reason: VoiceDavePendingMediaReason,
    ) -> VoiceDavePendingMediaEvent {
        VoiceDavePendingMediaEvent {
            reason,
            ssrc: self.rtp.ssrc,
            user_id: self.user_id,
            sequence: self.rtp.sequence,
            pending_packets,
            age_ms: duration_ms(self.enqueued_at.elapsed()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceRawUdpPacket {
    pub bytes: Vec<u8>,
    pub version: Option<u8>,
    pub raw_payload_type: Option<u8>,
    pub payload_type: Option<u8>,
    pub sequence: Option<u16>,
    pub timestamp: Option<u32>,
    pub ssrc: Option<u32>,
}

impl VoiceRawUdpPacket {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let raw_payload_type = bytes.get(1).copied();
        let (version, sequence, timestamp, ssrc) = if bytes.len() >= 12 {
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
            sequence,
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
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub header_len: usize,
    pub encrypted_body_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceReceivedPacket {
    pub raw: VoiceRawUdpPacket,
    pub rtp: VoiceRtpHeader,
    pub user_id: Option<u64>,
    pub opus_frame: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceDecodedPacket {
    pub packet: VoiceReceivedPacket,
    pub sample_rate: u32,
    pub channels: usize,
    pub samples_per_channel: usize,
    pub pcm: Vec<i16>,
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
            sample_rate: DISCORD_OPUS_SAMPLE_RATE,
        })
    }

    pub fn decode_packet(
        &mut self,
        packet: VoiceReceivedPacket,
    ) -> VoiceResult<VoiceDecodedPacket> {
        let channels = opus_packet_channels(&packet.opus_frame)?;
        let mut decoded = vec![0.0_f32; self.max_samples_per_channel * channels];
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
                &packet.opus_frame,
                self.max_samples_per_channel,
                &mut decoded,
            )
            .map_err(|error| VoiceError::opus(format!("failed to decode Opus frame: {error}")))?;
        decoded.truncate(samples_per_channel * channels);
        if channels == 1 {
            decoded = decoded
                .into_iter()
                .flat_map(|sample| [sample, sample])
                .collect();
        }
        let pcm = decoded
            .into_iter()
            .map(|sample| (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)).round() as i16)
            .collect();
        Ok(VoiceDecodedPacket {
            packet,
            sample_rate: self.sample_rate,
            channels: DISCORD_OPUS_CHANNELS,
            samples_per_channel,
            pcm,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceOutboundPacket {
    pub rtp: VoiceRtpHeader,
    pub nonce_suffix: [u8; 4],
    pub opus_frame: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VoiceOutboundRtpState {
    sequence: u16,
    timestamp: u32,
    nonce_suffix: u32,
    ssrc: u32,
    payload_type: u8,
    sample_rate: u32,
}

impl VoiceOutboundRtpState {
    fn new(ssrc: u32) -> Self {
        Self {
            sequence: 0,
            timestamp: 0,
            nonce_suffix: initial_voice_heartbeat_nonce() as u32,
            ssrc,
            payload_type: RTP_PAYLOAD_TYPE_OPUS,
            sample_rate: DISCORD_OPUS_SAMPLE_RATE,
        }
    }

    fn build_packet(
        &mut self,
        opus_frame: &[u8],
        duration: Duration,
        mode: &VoiceEncryptionMode,
        secret_key: &[u8],
    ) -> anyhow::Result<VoiceOutboundPacket> {
        if opus_frame.is_empty() {
            anyhow::bail!("opus frame must not be empty");
        }

        let sequence = self.sequence;
        let timestamp = self.timestamp;
        let nonce_suffix = self.nonce_suffix.to_be_bytes();
        let packet = encrypt_transport_payload(
            VoiceOutboundEncryptParams {
                sequence,
                timestamp,
                ssrc: self.ssrc,
                payload_type: self.payload_type,
                nonce_suffix,
            },
            opus_frame,
            mode,
            secret_key,
        )?;
        let rtp = parse_rtp_header(&packet)?;

        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp = self
            .timestamp
            .wrapping_add(timestamp_increment(self.sample_rate, duration));
        self.nonce_suffix = self.nonce_suffix.wrapping_add(1);

        Ok(VoiceOutboundPacket {
            rtp,
            nonce_suffix,
            opus_frame: opus_frame.to_vec(),
            bytes: packet,
        })
    }
}

#[derive(Clone)]
pub struct VoiceConnection<O: VoiceConnectionObserver = NoopVoiceConnectionObserver> {
    inner: Arc<VoiceConnectionInner<O>>,
}

#[derive(Clone)]
struct VoiceConnectionStateChannels {
    internal_tx: watch::Sender<VoiceConnectionInternalState>,
    public_tx: watch::Sender<VoiceConnectionState>,
}

impl VoiceConnectionStateChannels {
    fn new(initial: VoiceConnectionInternalState) -> Self {
        let public = initial.public_state();
        let (internal_tx, _) = watch::channel(initial);
        let (public_tx, _) = watch::channel(public);
        Self {
            internal_tx,
            public_tx,
        }
    }

    fn internal(&self) -> watch::Ref<'_, VoiceConnectionInternalState> {
        self.internal_tx.borrow()
    }

    fn public(&self) -> watch::Ref<'_, VoiceConnectionState> {
        self.public_tx.borrow()
    }

    fn subscribe_internal(&self) -> watch::Receiver<VoiceConnectionInternalState> {
        self.internal_tx.subscribe()
    }

    fn subscribe_public(&self) -> watch::Receiver<VoiceConnectionState> {
        self.public_tx.subscribe()
    }

    fn update(&self, update: impl FnOnce(&mut VoiceConnectionInternalState)) {
        self.internal_tx.send_modify(update);
        self.public_tx
            .send_replace(self.internal_tx.borrow().public_state());
    }
}

#[derive(Clone, Debug)]
struct VoiceConnectionClose {
    inner: Arc<VoiceConnectionCloseInner>,
}

#[derive(Debug)]
struct VoiceConnectionCloseInner {
    closed: AtomicBool,
    notify: Notify,
}

impl VoiceConnectionClose {
    fn new() -> Self {
        Self {
            inner: Arc::new(VoiceConnectionCloseInner {
                closed: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    fn close(&self) -> bool {
        let open = !self.inner.closed.swap(true, Ordering::AcqRel);
        if open {
            self.inner.notify.notify_waiters();
        }
        open
    }

    fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    async fn closed(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }
}

struct VoiceConnectionInner<O: VoiceConnectionObserver> {
    state: VoiceConnectionStateChannels,
    command_tx: mpsc::Sender<VoiceGatewayCommand>,
    close: VoiceConnectionClose,
    task: SyncMutex<Option<JoinHandle<VoiceResult<()>>>>,
    udp_socket: Arc<UdpSocket>,
    outbound_rtp: Arc<Mutex<VoiceOutboundRtpState>>,
    dave: Mutex<VoiceDaveCoordinator>,
    receive: Mutex<VoiceReceiveState>,
    observer: O,
}

impl<O: VoiceConnectionObserver> Drop for VoiceConnectionInner<O> {
    fn drop(&mut self) {
        let state = self.state.internal();
        self.observer.connection_dropped(state.connection_event());
        self.close.close();
        if let Some(task) = self.task.lock().take() {
            task.abort();
        }
    }
}

impl<O: VoiceConnectionObserver> VoiceConnection<O> {
    pub fn state(&self) -> VoiceConnectionState {
        self.inner.state.public().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<VoiceConnectionState> {
        self.inner.state.subscribe_public()
    }

    pub fn running(&self) -> bool {
        self.inner
            .task
            .lock()
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    fn internal_state(&self) -> VoiceConnectionInternalState {
        self.inner.state.internal().clone()
    }

    pub fn close(&self) -> bool {
        self.inner.close.close()
    }

    pub async fn close_and_wait(&self) -> VoiceResult<()> {
        self.close();
        let task = self.inner.task.lock().take();
        let Some(task) = task else {
            return Ok(());
        };
        task.await
            .map_err(|error| VoiceError::Join(format!("voice control task join failed: {error}")))?
    }

    fn ensure_open(&self) -> VoiceResult<()> {
        if self.inner.close.is_closed() {
            Err(VoiceError::Closed)
        } else {
            Ok(())
        }
    }

    pub async fn dave_media_status(&self) -> VoiceDaveMediaStatus {
        let state = self.internal_state();
        let dave = self.inner.dave.lock().await;
        let active = state.dave.protocol_version.unwrap_or(0) > 0;
        let gateway_ready = voice_dave_gateway_media_ready(&state.dave);
        let session_ready = dave.ready();
        let transition_ready = dave.transition_ready();
        let mls = state.dave.mls_state();
        let transition_zero_ready =
            voice_dave_transition_zero_media_ready(&state.dave, transition_ready);
        VoiceDaveMediaStatus {
            active,
            media_ready: !active
                || (session_ready && transition_zero_ready)
                || (session_ready && transition_ready.is_some() && gateway_ready),
            session_ready,
            transition_ready,
            protocol_version: state.dave.protocol_version,
            transition_id: state.dave.transition_id,
            mls,
        }
    }

    pub async fn wait_until_media_ready(
        &self,
        max_wait: Duration,
    ) -> VoiceResult<VoiceDaveMediaStatus> {
        self.ensure_open()?;
        let started = Instant::now();
        let mut state_rx = self.inner.state.subscribe_internal();
        loop {
            self.pump_dave().await?;
            let status = self.dave_media_status().await;
            if status.media_ready || started.elapsed() >= max_wait {
                if status.media_ready {
                    return Ok(status);
                }
                return Err(VoiceError::Timeout {
                    stage: None,
                    duration: max_wait,
                });
            }
            tokio::select! {
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        return Err(VoiceError::Closed);
                    }
                }
                () = self.inner.close.closed() => return Err(VoiceError::Closed),
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    }

    fn dave_active(&self) -> bool {
        self.inner
            .state
            .internal()
            .dave
            .protocol_version
            .unwrap_or(0)
            > 0
    }

    async fn pump_dave(&self) -> VoiceResult<()> {
        let state = self.internal_state();
        self.inner.dave.lock().await.pump(
            &self.inner.command_tx,
            &state.dave,
            &state.connected_user_ids,
            state.roster_authoritative,
            &self.inner.observer,
        )
    }

    pub async fn recv_raw_udp_packet(&self, max_len: usize) -> VoiceResult<VoiceRawUdpPacket> {
        if max_len == 0 {
            return Err(VoiceError::invalid_input(
                "max_len must be greater than zero",
            ));
        }
        self.ensure_open()?;

        let started = O::ENABLE_TIMING.then(Instant::now);
        let mut buffer = vec![0_u8; max_len];
        let received = tokio::select! {
            received = self.inner.udp_socket.recv(&mut buffer) => received?,
            () = self.inner.close.closed() => return Err(VoiceError::Closed),
        };
        buffer.truncate(received);
        if let Some(started) = started {
            let state = self.internal_state();
            self.inner
                .observer
                .udp_packet_received(VoiceUdpPacketReceivedEvent {
                    endpoint: &state.config.endpoint,
                    guild_id: state.config.server_id,
                    user_id: state.config.user_id,
                    bytes: received,
                    elapsed: started.elapsed(),
                });
        }
        Ok(VoiceRawUdpPacket::from_bytes(buffer))
    }

    pub async fn recv_rtp_udp_packet(&self, max_len: usize) -> VoiceResult<VoiceRawUdpPacket> {
        loop {
            let raw = self.recv_raw_udp_packet(max_len).await?;
            if !raw.is_rtcp() {
                return Ok(raw);
            }
            self.observe_rtcp_packet(&raw);
        }
    }

    pub async fn recv_voice_packet(&self, max_len: usize) -> VoiceResult<VoiceReceivedPacket> {
        loop {
            self.pump_dave().await?;
            if let Some(packet) = self.drain_pending_dave_media().await? {
                return Ok(packet);
            }
            if let Some(packet) = self
                .decode_received_voice_packet(self.recv_rtp_udp_packet(max_len).await?)
                .await?
            {
                return Ok(packet);
            }
        }
    }

    pub async fn recv_decoded_voice_packet(
        &self,
        decoder: &mut VoiceOpusDecoder,
        max_len: usize,
    ) -> VoiceResult<VoiceDecodedPacket> {
        let packet = self.recv_voice_packet(max_len).await?;
        let ssrc = packet.rtp.ssrc;
        let user_id = packet.user_id;
        let sequence = packet.rtp.sequence;
        match decoder.decode_packet(packet) {
            Ok(decoded) => Ok(decoded),
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Opus,
                    VoiceReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(sequence),
                    error.to_string(),
                );
                Err(error)
            }
        }
    }

    async fn decode_received_voice_packet(
        &self,
        raw: VoiceRawUdpPacket,
    ) -> VoiceResult<Option<VoiceReceivedPacket>> {
        let state = self.internal_state();
        let session_description = state
            .session_description
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing voice session description"))?;
        let rtp = match parse_rtp_header(&raw.bytes) {
            Ok(rtp) => rtp,
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Rtp,
                    VoiceReceiveDecodeErrorKind::MalformedRtp,
                    raw.ssrc,
                    None,
                    raw.sequence,
                    error.to_string(),
                );
                return Err(error.into());
            }
        };
        let transport_frame = match decrypt_transport_payload(
            &raw.bytes,
            &rtp,
            &session_description.mode,
            session_description.secret_key.as_slice(),
        ) {
            Ok(frame) => frame,
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Transport,
                    VoiceReceiveDecodeErrorKind::TransportDecryptFailed,
                    Some(rtp.ssrc),
                    state.ssrc_users.get(&rtp.ssrc).copied(),
                    Some(rtp.sequence),
                    error.to_string(),
                );
                return Err(error.into());
            }
        };
        let user_id = state.ssrc_users.get(&rtp.ssrc).copied();
        self.inner.receive.lock().await.record_rtp_packet(
            &self.inner.observer,
            &rtp,
            user_id,
            transport_frame.len(),
        );
        if state.dave.protocol_version.unwrap_or(0) > 0 {
            return self
                .decode_or_enqueue_dave_media(PendingVoiceMediaPacket {
                    raw,
                    rtp,
                    user_id,
                    transport_frame,
                    enqueued_at: Instant::now(),
                    reason: VoiceDavePendingMediaReason::DecryptStatePending,
                    was_pending: false,
                })
                .await;
        }
        Ok(Some(VoiceReceivedPacket {
            raw,
            rtp,
            user_id,
            opus_frame: transport_frame,
        }))
    }

    fn observe_rtcp_packet(&self, raw: &VoiceRawUdpPacket) {
        if !O::ENABLE_RTCP {
            return;
        }
        let state = self.internal_state();
        self.inner
            .observer
            .rtcp_packet_received(VoiceRtcpPacketEvent {
                endpoint: &state.config.endpoint,
                guild_id: state.config.server_id,
                user_id: state.config.user_id,
                bytes: &raw.bytes,
                header: raw.rtcp_header(),
            });
    }

    async fn drain_pending_dave_media(&self) -> VoiceResult<Option<VoiceReceivedPacket>> {
        let len = self.inner.receive.lock().await.pending_dave_media.len();
        for _ in 0..len {
            let Some(mut packet) = self
                .inner
                .receive
                .lock()
                .await
                .pending_dave_media
                .pop_front()
            else {
                return Ok(None);
            };
            packet.was_pending = true;
            if packet.enqueued_at.elapsed() >= DAVE_PENDING_MEDIA_TTL {
                self.observe_pending_dave_media(
                    &packet,
                    VoiceDavePendingMediaReason::Expired,
                    false,
                )
                .await;
                continue;
            }
            if let Some(decoded) = self.decode_or_enqueue_dave_media(packet).await? {
                return Ok(Some(decoded));
            }
        }
        Ok(None)
    }

    async fn decode_or_enqueue_dave_media(
        &self,
        mut packet: PendingVoiceMediaPacket,
    ) -> VoiceResult<Option<VoiceReceivedPacket>> {
        packet.user_id = self
            .inner
            .state
            .internal()
            .ssrc_users
            .get(&packet.rtp.ssrc)
            .copied();
        if packet.user_id.is_none() {
            self.enqueue_dave_media(packet, VoiceDavePendingMediaReason::MissingUser)
                .await;
            return Ok(None);
        }
        self.pump_dave().await?;
        let state = self.internal_state();
        let gateway_pending = !voice_dave_gateway_media_ready(&state.dave);
        {
            let dave = self.inner.dave.lock().await;
            let transition_zero_ready =
                voice_dave_transition_zero_media_ready(&state.dave, dave.transition_ready());
            if !dave.ready() {
                drop(dave);
                self.enqueue_dave_media(packet, VoiceDavePendingMediaReason::SessionNotReady)
                    .await;
                return Ok(None);
            }
            if gateway_pending && !transition_zero_ready {
                drop(dave);
                self.enqueue_dave_media(packet, VoiceDavePendingMediaReason::GatewayPending)
                    .await;
                return Ok(None);
            }
        }
        let decrypted = {
            let mut dave = self.inner.dave.lock().await;
            dave.session_mut()
                .decrypt_packet(packet.user_id, &packet.transport_frame)
        };
        match decrypted {
            Ok(opus_frame) => {
                if packet.was_pending {
                    self.observe_pending_dave_media(&packet, packet.reason, true)
                        .await;
                }
                Ok(Some(VoiceReceivedPacket {
                    raw: packet.raw,
                    rtp: packet.rtp,
                    user_id: packet.user_id,
                    opus_frame,
                }))
            }
            Err(error) => {
                let kind = error.receive_decode_kind();
                let detail = error.to_string();
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::DaveDecrypt,
                    kind,
                    Some(packet.rtp.ssrc),
                    packet.user_id,
                    Some(packet.rtp.sequence),
                    detail,
                );
                if packet.enqueued_at.elapsed() < DAVE_PENDING_MEDIA_TTL
                    && voice_dave_decrypt_failure_should_retry(
                        kind,
                        self.dave_decrypt_state_can_still_change().await,
                    )
                {
                    let reason = if matches!(error, VoiceDaveDecryptError::NoValidCryptor { .. }) {
                        VoiceDavePendingMediaReason::NoValidCryptorPending
                    } else {
                        VoiceDavePendingMediaReason::DecryptStatePending
                    };
                    self.enqueue_dave_media(packet, reason).await;
                    return Ok(None);
                }
                self.observe_pending_dave_media(
                    &packet,
                    VoiceDavePendingMediaReason::StableDecryptFailure,
                    false,
                )
                .await;
                Ok(None)
            }
        }
    }

    async fn dave_decrypt_state_can_still_change(&self) -> bool {
        let state = self.internal_state();
        let dave = self.inner.dave.lock().await;
        let transition_zero_ready =
            voice_dave_transition_zero_media_ready(&state.dave, dave.transition_ready());
        !dave.ready() || (!transition_zero_ready && !voice_dave_gateway_media_ready(&state.dave))
    }

    async fn enqueue_dave_media(
        &self,
        mut packet: PendingVoiceMediaPacket,
        reason: VoiceDavePendingMediaReason,
    ) {
        let was_pending = packet.was_pending;
        packet.reason = reason;
        self.inner
            .receive
            .lock()
            .await
            .pending_dave_media
            .push_back(packet);
        if O::ENABLE_RECEIVE_TELEMETRY && !was_pending {
            let receive = self.inner.receive.lock().await;
            if let Some(packet) = receive.pending_dave_media.back() {
                self.inner.observer.dave_pending_media_enqueued(
                    packet.event(receive.pending_dave_media.len(), reason),
                );
            }
        }
    }

    async fn observe_pending_dave_media(
        &self,
        packet: &PendingVoiceMediaPacket,
        reason: VoiceDavePendingMediaReason,
        drained: bool,
    ) {
        if !O::ENABLE_RECEIVE_TELEMETRY {
            return;
        }
        let pending_packets = self.inner.receive.lock().await.pending_dave_media.len();
        let event = packet.event(pending_packets, reason);
        if drained {
            self.inner.observer.dave_pending_media_drained(event);
        } else if matches!(
            reason,
            VoiceDavePendingMediaReason::StableDecryptFailure
                | VoiceDavePendingMediaReason::Expired
        ) {
            self.inner.observer.dave_pending_media_dropped(event);
        } else {
            self.inner.observer.dave_pending_media_enqueued(event);
        }
    }

    fn observe_decode_error(
        &self,
        stage: VoiceReceiveDecodeStage,
        kind: VoiceReceiveDecodeErrorKind,
        ssrc: Option<u32>,
        user_id: Option<u64>,
        sequence: Option<u16>,
        detail: String,
    ) {
        if O::ENABLE_RECEIVE_TELEMETRY {
            self.inner
                .observer
                .receive_decode_error(VoiceReceiveDecodeErrorEvent {
                    stage,
                    kind,
                    ssrc,
                    user_id,
                    sequence,
                    detail,
                });
        }
    }

    fn send(&self, command: VoiceGatewayCommand) -> VoiceResult<()> {
        self.ensure_open()?;
        send_gateway_command(&self.inner.command_tx, command)
    }

    pub fn set_speaking(&self, flags: VoiceSpeakingFlags, delay: u32) -> VoiceResult<()> {
        self.send(VoiceGatewayCommand::Speaking(VoiceSpeakingCommand {
            speaking: flags.bits(),
            delay: Some(delay),
            ssrc: self.inner.state.internal().ready.ssrc,
            user_id: None,
        }))
    }

    pub async fn send_opus_frame(
        &self,
        opus_frame: &[u8],
        duration: Duration,
    ) -> VoiceResult<VoiceOutboundPacket> {
        self.ensure_open()?;
        self.pump_dave().await?;
        if self.dave_active() {
            self.wait_until_media_ready(DAVE_SEND_MEDIA_READY_TIMEOUT)
                .await?;
            let encrypted = self
                .inner
                .dave
                .lock()
                .await
                .session_mut()
                .encrypt_opus(opus_frame)?;
            self.send_opus_payload(&encrypted, duration, true).await
        } else {
            self.send_opus_payload(opus_frame, duration, false).await
        }
    }

    async fn send_opus_payload(
        &self,
        opus_payload: &[u8],
        duration: Duration,
        requires_dave: bool,
    ) -> VoiceResult<VoiceOutboundPacket> {
        self.ensure_open()?;
        let state = self.internal_state();
        let session_description = state
            .session_description
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing voice session description"))?;

        let build_started = O::ENABLE_TIMING.then(Instant::now);
        let packet = self.inner.outbound_rtp.lock().await.build_packet(
            opus_payload,
            duration,
            &session_description.mode,
            session_description.secret_key.as_slice(),
        )?;
        let build_elapsed = build_started.map(|started| started.elapsed());
        let send_started = O::ENABLE_TIMING.then(Instant::now);
        tokio::select! {
            sent = self.inner.udp_socket.send(&packet.bytes) => {
                sent?;
            }
            () = self.inner.close.closed() => return Err(VoiceError::Closed),
        }
        if let (Some(build_elapsed), Some(send_started)) = (build_elapsed, send_started) {
            self.inner
                .observer
                .udp_packet_sent(VoiceUdpPacketSentEvent {
                    endpoint: &state.config.endpoint,
                    guild_id: state.config.server_id,
                    user_id: state.config.user_id,
                    dave: requires_dave,
                    opus_bytes: opus_payload.len(),
                    packet_bytes: packet.bytes.len(),
                    build_elapsed,
                    send_elapsed: send_started.elapsed(),
                });
        }
        Ok(packet)
    }
}

pub async fn connect_voice(
    config: VoiceConnectionConfig,
) -> VoiceResult<VoiceConnection<NoopVoiceConnectionObserver>> {
    connect_voice_with_observer(config, NoopVoiceConnectionObserver).await
}

pub async fn connect_voice_with_observer<O>(
    config: VoiceConnectionConfig,
    observer: O,
) -> VoiceResult<VoiceConnection<O>>
where
    O: VoiceConnectionObserver,
{
    let websocket_url = config.websocket_url()?;
    let voice_endpoint = config.endpoint.clone();
    let voice_guild_id = config.server_id;
    let voice_channel_id = config.channel_id;
    let voice_user_id = config.user_id;
    let (ws_stream, _) = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::WebSocketConnect,
        VOICE_CONNECT_TIMEOUT,
        connect_voice_websocket(&websocket_url),
    )
    .await?;
    let (mut write, mut read) = ws_stream.split();

    let hello = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::Hello,
        VOICE_HELLO_TIMEOUT,
        read_voice_event(&mut read),
    )
    .await?;
    let hello_data: VoiceHelloData = parse_voice_data(hello.data)?;

    write
        .send(WsMessage::Text(
            VoiceGatewayCommand::Identify(VoiceIdentifyCommand::from_config(&config))
                .text_payload()?
                .into(),
        ))
        .await?;

    let mut last_sequence = hello.sequence;
    let ready_event = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::Ready,
        VOICE_READY_TIMEOUT,
        wait_for_voice_opcode(&mut read, VoiceOpcode::Ready, &mut last_sequence),
    )
    .await?;
    let ready: VoiceGatewayReady = parse_voice_data(ready_event.data)?;

    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    udp_socket.connect((&*ready.ip, ready.port)).await?;
    udp_socket
        .send(&VoiceUdpDiscoveryPacket::request(ready.ssrc))
        .await?;

    let mut discovery_buffer = [0_u8; VoiceUdpDiscoveryPacket::LEN];
    let received = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::UdpDiscovery,
        VOICE_UDP_DISCOVERY_TIMEOUT,
        async { Ok(udp_socket.recv(&mut discovery_buffer).await?) },
    )
    .await?;
    let discovery = VoiceUdpDiscoveryPacket::decode(&discovery_buffer[..received])?;
    let selected_mode = select_encryption_mode(&config, &ready)?;

    write
        .send(WsMessage::Text(
            VoiceGatewayCommand::SelectProtocol(VoiceSelectProtocolCommand::udp(
                discovery.address.clone(),
                discovery.port,
                selected_mode.clone(),
            ))
            .text_payload()?
            .into(),
        ))
        .await?;

    let (session_description_event, pending_events) = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::SessionDescription,
        VOICE_SESSION_DESCRIPTION_TIMEOUT,
        wait_for_session_description(&mut read, &mut last_sequence),
    )
    .await?;
    let session_description: VoiceSessionDescription =
        parse_voice_data(session_description_event.data)?;
    let dave_protocol_version = session_description.dave_protocol_version;

    let initial_state = VoiceConnectionInternalState {
        config,
        heartbeat_interval_ms: hello_data.heartbeat_interval_ms(),
        last_sequence,
        ready,
        discovery,
        selected_mode,
        session_description: Some(session_description),
        connected_user_ids: HashSet::from([voice_user_id]),
        ssrc_users: HashMap::new(),
        speaking: HashMap::new(),
        dave: VoiceDaveInternalState {
            protocol_version: dave_protocol_version,
            passthrough: dave_protocol_version.unwrap_or(0) == 0,
            ..VoiceDaveInternalState::default()
        },
        roster_authoritative: false,
        resumed: false,
    };
    let state = VoiceConnectionStateChannels::new(initial_state);
    replay_pending_voice_events(&state, pending_events, &observer)?;
    let (command_tx, command_rx) = mpsc::channel::<VoiceGatewayCommand>(128);
    let close = VoiceConnectionClose::new();
    let udp_socket_handle = Arc::clone(&udp_socket);
    let outbound_rtp = Arc::new(Mutex::new(VoiceOutboundRtpState::new(
        state.internal().ready.ssrc,
    )));
    let task = tokio::spawn(run_voice_control_task(
        write,
        read,
        command_rx,
        close.clone(),
        VoiceControlTaskContext {
            endpoint: voice_endpoint.clone(),
            guild_id: voice_guild_id,
            user_id: voice_user_id,
            state: state.clone(),
            observer: observer.clone(),
        },
    ));

    Ok(VoiceConnection {
        inner: Arc::new(VoiceConnectionInner {
            state,
            command_tx,
            close,
            task: SyncMutex::new(Some(task)),
            udp_socket: udp_socket_handle,
            outbound_rtp,
            dave: Mutex::new(VoiceDaveCoordinator::new(voice_user_id, voice_channel_id)?),
            receive: Mutex::new(VoiceReceiveState::default()),
            observer,
        }),
    })
}

struct VoiceControlTaskContext<O: VoiceConnectionObserver> {
    endpoint: String,
    guild_id: u64,
    user_id: u64,
    state: VoiceConnectionStateChannels,
    observer: O,
}

async fn run_voice_control_task<O>(
    write: VoiceWebSocketWrite,
    read: VoiceWebSocketRead,
    command_rx: mpsc::Receiver<VoiceGatewayCommand>,
    close: VoiceConnectionClose,
    context: VoiceControlTaskContext<O>,
) -> VoiceResult<()>
where
    O: VoiceConnectionObserver,
{
    let result = run_voice_control_loop(write, read, command_rx, close, &context).await;
    if let Err(error) = &result {
        context
            .observer
            .control_task_failed(VoiceConnectionErrorEvent {
                endpoint: &context.endpoint,
                guild_id: context.guild_id,
                user_id: context.user_id,
                error,
            });
    }
    result
}

async fn run_voice_control_loop<O>(
    mut write: VoiceWebSocketWrite,
    mut read: VoiceWebSocketRead,
    mut command_rx: mpsc::Receiver<VoiceGatewayCommand>,
    close: VoiceConnectionClose,
    context: &VoiceControlTaskContext<O>,
) -> VoiceResult<()>
where
    O: VoiceConnectionObserver,
{
    let mut heartbeat = interval(Duration::from_millis(
        context.state.internal().heartbeat_interval_ms,
    ));
    heartbeat.tick().await;
    let mut heartbeat_nonce = initial_voice_heartbeat_nonce();
    let mut heartbeat_ack_pending = false;
    let mut heartbeat_sent_at: Option<Instant> = None;
    let heartbeat_ack_timeout =
        voice_heartbeat_ack_timeout(context.state.internal().heartbeat_interval_ms);

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if heartbeat_ack_pending {
                    if heartbeat_sent_at.is_some_and(|sent_at| {
                        sent_at.elapsed() >= heartbeat_ack_timeout
                    }) {
                        return Err(VoiceError::protocol("voice heartbeat ACK timed out"));
                    }
                    continue;
                }
                let heartbeat_command = {
                    let state = context.state.internal();
                    VoiceHeartbeatCommand {
                        t: next_voice_heartbeat_nonce(&mut heartbeat_nonce),
                        seq_ack: state.last_sequence,
                    }
                };
                write
                    .send(WsMessage::Text(
                        VoiceGatewayCommand::Heartbeat(heartbeat_command)
                            .text_payload()?
                            .into(),
                    ))
                    .await?;
                heartbeat_ack_pending = true;
                heartbeat_sent_at = Some(Instant::now());
            }
            command = command_rx.recv() => {
                match command {
                    Some(command) => send_voice_control_command(&mut write, command, context).await?,
                    None => break,
                }
            }
            () = close.closed() => {
                let _ = write.send(WsMessage::Close(None)).await;
                break;
            }
            message = read.next() => {
                match message {
                    Some(Ok(WsMessage::Text(text))) => {
                        let event = parse_voice_event_text(&text)?;
                        context.observer.websocket_text_event(VoiceWebSocketTextEvent {
                            endpoint: &context.endpoint,
                            guild_id: context.guild_id,
                            user_id: context.user_id,
                            opcode: event.opcode,
                            sequence: event.sequence,
                        });
                        if let Some(sequence) = event.sequence {
                            update_state(&context.state, |state| {
                                state.last_sequence = Some(sequence);
                            });
                        }
                        handle_voice_text_event(
                            &context.state,
                            event,
                            &mut heartbeat_ack_pending,
                            &mut heartbeat_sent_at,
                            &context.observer,
                        )?;
                    }
                    Some(Ok(WsMessage::Binary(bytes))) => {
                        context.observer.websocket_binary_event(VoiceWebSocketBinaryEvent {
                            endpoint: &context.endpoint,
                            guild_id: context.guild_id,
                            user_id: context.user_id,
                            bytes: bytes.len(),
                            first_byte: bytes.first().copied(),
                        });
                        handle_voice_binary_event(&context.state, &bytes)?;
                    }
                    Some(Ok(WsMessage::Close(frame))) => {
                        context.observer.websocket_closed(VoiceWebSocketClosedEvent {
                            endpoint: &context.endpoint,
                            guild_id: context.guild_id,
                            user_id: context.user_id,
                            frame: frame.as_ref().map(VoiceWebSocketCloseFrame::from_frame),
                        });
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        context.observer.websocket_read_failed(VoiceConnectionErrorEvent {
                            endpoint: &context.endpoint,
                            guild_id: context.guild_id,
                            user_id: context.user_id,
                            error: &error,
                        });
                        return Err(error.into());
                    }
                    None => {
                        context.observer.websocket_stream_ended(VoiceConnectionEvent {
                            endpoint: &context.endpoint,
                            guild_id: context.guild_id,
                            user_id: context.user_id,
                        });
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn send_voice_control_command<O>(
    write: &mut VoiceWebSocketWrite,
    command: VoiceGatewayCommand,
    context: &VoiceControlTaskContext<O>,
) -> VoiceResult<()>
where
    O: VoiceConnectionObserver,
{
    if let Some(bytes) = command.binary_payload() {
        if let Err(error) = write.send(WsMessage::Binary(bytes.into())).await {
            context
                .observer
                .websocket_command_failed(VoiceWebSocketCommandFailedEvent {
                    endpoint: &context.endpoint,
                    guild_id: context.guild_id,
                    user_id: context.user_id,
                    frame_kind: VoiceWebSocketFrameKind::Binary,
                    opcode: command.opcode().code(),
                    error: &error,
                });
            return Err(error.into());
        }
    } else {
        let payload = command.text_payload()?;
        if let Err(error) = write.send(WsMessage::Text(payload.into())).await {
            context
                .observer
                .websocket_command_failed(VoiceWebSocketCommandFailedEvent {
                    endpoint: &context.endpoint,
                    guild_id: context.guild_id,
                    user_id: context.user_id,
                    opcode: command.opcode().code(),
                    frame_kind: VoiceWebSocketFrameKind::Text,
                    error: &error,
                });
            return Err(error.into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct VoiceSpeakingFlags(u8);

impl VoiceSpeakingFlags {
    pub const NONE: Self = Self(0);
    pub const MICROPHONE: Self = Self(1);

    fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug)]
enum VoiceGatewayCommand {
    Identify(VoiceIdentifyCommand),
    SelectProtocol(VoiceSelectProtocolCommand),
    Speaking(VoiceSpeakingCommand),
    Heartbeat(VoiceHeartbeatCommand),
    DaveProtocolTransitionReady(VoiceDaveTransitionReadyCommand),
    DaveMlsKeyPackage {
        key_package: Vec<u8>,
    },
    DaveMlsCommitWelcome {
        commit: Vec<u8>,
        welcome: Option<Vec<u8>>,
    },
    DaveMlsInvalidCommitWelcome(VoiceDaveInvalidCommitWelcomeCommand),
}

impl VoiceGatewayCommand {
    fn opcode(&self) -> VoiceOpcode {
        match self {
            Self::Identify(_) => VoiceOpcode::Identify,
            Self::SelectProtocol(_) => VoiceOpcode::SelectProtocol,
            Self::Speaking(_) => VoiceOpcode::Speaking,
            Self::Heartbeat(_) => VoiceOpcode::Heartbeat,
            Self::DaveProtocolTransitionReady(_) => VoiceOpcode::DaveTransitionReady,
            Self::DaveMlsKeyPackage { .. } => VoiceOpcode::DaveMlsKeyPackage,
            Self::DaveMlsCommitWelcome { .. } => VoiceOpcode::DaveMlsCommitWelcome,
            Self::DaveMlsInvalidCommitWelcome(_) => VoiceOpcode::DaveMlsInvalidCommitWelcome,
        }
    }

    fn text_payload(&self) -> anyhow::Result<String> {
        match self {
            Self::Identify(data) => serialize_voice_payload(self.opcode(), data),
            Self::SelectProtocol(data) => serialize_voice_payload(self.opcode(), data),
            Self::Speaking(data) => serialize_voice_payload(self.opcode(), data),
            Self::Heartbeat(data) => serialize_voice_payload(self.opcode(), data),
            Self::DaveProtocolTransitionReady(data) => serialize_voice_payload(self.opcode(), data),
            Self::DaveMlsInvalidCommitWelcome(data) => serialize_voice_payload(self.opcode(), data),
            Self::DaveMlsKeyPackage { .. } | Self::DaveMlsCommitWelcome { .. } => {
                anyhow::bail!("DAVE MLS key package and commit/welcome use binary websocket frames")
            }
        }
    }

    fn binary_payload(&self) -> Option<Vec<u8>> {
        match self {
            Self::DaveMlsKeyPackage { key_package } => {
                let mut bytes = Vec::with_capacity(1 + key_package.len());
                bytes.push(self.opcode().byte());
                bytes.extend_from_slice(key_package);
                Some(bytes)
            }
            Self::DaveMlsCommitWelcome { commit, welcome } => {
                let mut bytes =
                    Vec::with_capacity(1 + commit.len() + welcome.as_ref().map_or(0, Vec::len));
                bytes.push(self.opcode().byte());
                bytes.extend_from_slice(commit);
                if let Some(welcome) = welcome {
                    bytes.extend_from_slice(welcome);
                }
                Some(bytes)
            }
            _ => None,
        }
    }
}

fn send_gateway_command(
    command_tx: &mpsc::Sender<VoiceGatewayCommand>,
    command: VoiceGatewayCommand,
) -> VoiceResult<()> {
    match command_tx.try_send(command) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(VoiceError::Closed),
        Err(mpsc::error::TrySendError::Full(_)) => Err(VoiceError::Backpressure(
            "voice gateway command queue is full".to_string(),
        )),
    }
}

#[derive(Clone, Debug, Serialize)]
struct VoiceGatewayPayload<'a, T: ?Sized> {
    op: u64,
    d: &'a T,
}

fn serialize_voice_payload<T>(opcode: VoiceOpcode, data: &T) -> anyhow::Result<String>
where
    T: Serialize + ?Sized,
{
    Ok(serde_json::to_string(&VoiceGatewayPayload {
        op: opcode.code(),
        d: data,
    })?)
}

#[derive(Clone, Debug, Serialize)]
struct VoiceIdentifyCommand {
    server_id: String,
    user_id: String,
    session_id: String,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_dave_protocol_version: Option<u16>,
}

impl VoiceIdentifyCommand {
    fn from_config(config: &VoiceConnectionConfig) -> Self {
        Self {
            server_id: config.server_id.to_string(),
            user_id: config.user_id.to_string(),
            session_id: config.session_id.clone(),
            token: config.token.clone(),
            max_dave_protocol_version: config.max_dave_protocol_version,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct VoiceSelectProtocolCommand {
    protocol: &'static str,
    data: VoiceSelectProtocolData,
}

impl VoiceSelectProtocolCommand {
    fn udp(address: String, port: u16, mode: VoiceEncryptionMode) -> Self {
        Self {
            protocol: "udp",
            data: VoiceSelectProtocolData {
                address,
                port,
                mode,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct VoiceSelectProtocolData {
    address: String,
    port: u16,
    mode: VoiceEncryptionMode,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VoiceSpeakingUpdate {
    pub speaking: u64,
    pub ssrc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<DiscordId>,
}

#[derive(Clone, Debug, Serialize)]
struct VoiceSpeakingCommand {
    speaking: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    delay: Option<u32>,
    ssrc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<DiscordId>,
}

#[derive(Clone, Debug, Serialize)]
struct VoiceHeartbeatCommand {
    t: u64,
    seq_ack: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct VoiceDaveTransitionReadyCommand {
    transition_id: u16,
}

#[derive(Clone, Debug, Serialize)]
struct VoiceDaveInvalidCommitWelcomeCommand {
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceGatewayEvent {
    op: u64,
    #[serde(default)]
    seq: Option<i64>,
    #[serde(default)]
    d: Option<Value>,
}

#[derive(Clone, Debug)]
struct ParsedVoiceGatewayEvent {
    opcode: u64,
    sequence: Option<i64>,
    data: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceHelloData {
    heartbeat_interval: f64,
}

impl VoiceHelloData {
    fn heartbeat_interval_ms(&self) -> u64 {
        self.heartbeat_interval.max(1.0).ceil() as u64
    }
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceDavePrepareTransitionEvent {
    protocol_version: u16,
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceDaveExecuteTransitionEvent {
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceDavePrepareEpochEvent {
    protocol_version: u16,
    epoch: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceClientsConnectEvent {
    #[serde(default)]
    user_ids: Vec<DiscordId>,
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceClientConnectEvent {
    user_id: DiscordId,
    #[serde(default)]
    audio_ssrc: Option<u32>,
    #[serde(default)]
    ssrc: Option<u32>,
}

impl VoiceClientConnectEvent {
    fn voice_ssrc(&self) -> Option<u32> {
        self.audio_ssrc.or(self.ssrc)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct VoiceClientDisconnectEvent {
    user_id: DiscordId,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct VoiceGatewayReady {
    pub ssrc: u32,
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub modes: Vec<VoiceEncryptionMode>,
    #[serde(default)]
    pub heartbeat_interval: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceUdpDiscoveryPacket {
    pub ssrc: u32,
    pub address: String,
    pub port: u16,
}

impl VoiceUdpDiscoveryPacket {
    const LEN: usize = 74;
    const REQUEST_TYPE: u16 = 1;
    const RESPONSE_TYPE: u16 = 2;
    const BODY_LEN: u16 = 70;

    fn request(ssrc: u32) -> [u8; Self::LEN] {
        let mut packet = [0_u8; Self::LEN];
        packet[..2].copy_from_slice(&Self::REQUEST_TYPE.to_be_bytes());
        packet[2..4].copy_from_slice(&Self::BODY_LEN.to_be_bytes());
        packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
        packet
    }

    fn decode(packet: &[u8]) -> anyhow::Result<Self> {
        if packet.len() < Self::LEN {
            anyhow::bail!(
                "voice discovery packet must be at least {} bytes",
                Self::LEN
            );
        }

        let packet_type = u16::from_be_bytes([packet[0], packet[1]]);
        if packet_type != Self::RESPONSE_TYPE {
            anyhow::bail!("unexpected voice discovery packet type {packet_type}");
        }

        let packet_len = u16::from_be_bytes([packet[2], packet[3]]);
        if packet_len != Self::BODY_LEN {
            anyhow::bail!("unexpected voice discovery packet length {packet_len}");
        }

        let address_end = packet[8..72]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| offset + 8)
            .unwrap_or(72);
        let address = std::str::from_utf8(&packet[8..address_end])
            .map_err(|error| anyhow::anyhow!("invalid voice discovery ip: {error}"))?
            .to_string();

        Ok(Self {
            ssrc: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            address,
            port: u16::from_be_bytes([packet[72], packet[73]]),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscordId(u64);

impl DiscordId {
    fn get(&self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for DiscordId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DiscordIdVisitor;

        impl Visitor<'_> for DiscordIdVisitor {
            type Value = DiscordId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Discord snowflake as a string or integer")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(DiscordId(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                value.parse().map(DiscordId).map_err(DeError::custom)
            }
        }

        deserializer.deserialize_any(DiscordIdVisitor)
    }
}

impl Serialize for DiscordId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.0)
    }
}

struct VoiceDaveySession {
    session: DaveSession,
}

impl VoiceDaveySession {
    fn new(
        protocol_version: NonZeroU16,
        user_id: u64,
        channel_id: u64,
    ) -> Result<Self, VoiceDaveError> {
        Ok(Self {
            session: DaveSession::new(protocol_version, user_id, channel_id, None).map_err(
                |error| VoiceDaveError::CreateSession {
                    detail: error.to_string(),
                },
            )?,
        })
    }

    fn discord_default(user_id: u64, channel_id: u64) -> Result<Self, VoiceDaveError> {
        let protocol_version = NonZeroU16::new(DAVE_PROTOCOL_VERSION).ok_or(
            VoiceDaveError::InvalidProtocolVersion {
                version: DAVE_PROTOCOL_VERSION,
            },
        )?;
        Self::new(protocol_version, user_id, channel_id)
    }

    fn is_ready(&self) -> bool {
        self.session.is_ready()
    }

    fn set_external_sender(&mut self, external_sender: &[u8]) -> Result<(), VoiceDaveError> {
        self.session
            .set_external_sender(external_sender)
            .map_err(|error| VoiceDaveError::SetExternalSender {
                detail: error.to_string(),
            })
    }

    fn create_key_package(&mut self) -> Result<Vec<u8>, VoiceDaveError> {
        self.session
            .create_key_package()
            .map_err(|error| VoiceDaveError::CreateKeyPackage {
                detail: error.to_string(),
            })
    }

    fn process_welcome(&mut self, welcome: &[u8]) -> Result<(), VoiceDaveError> {
        self.session
            .process_welcome(welcome)
            .map_err(|error| VoiceDaveError::ProcessWelcome {
                detail: error.to_string(),
            })
    }

    fn process_commit(&mut self, commit: &[u8]) -> Result<(), VoiceDaveError> {
        self.session
            .process_commit(commit)
            .map_err(|error| VoiceDaveError::ProcessCommit {
                detail: error.to_string(),
            })
    }

    fn process_proposals(
        &mut self,
        operation_type: ProposalsOperationType,
        proposals: &[u8],
        expected_user_ids: Option<&[u64]>,
    ) -> Result<Option<davey::CommitWelcome>, VoiceDaveError> {
        self.session
            .process_proposals(operation_type, proposals, expected_user_ids)
            .map_err(|error| VoiceDaveError::ProcessProposals {
                detail: error.to_string(),
            })
    }

    fn set_passthrough_mode(&mut self, enabled: bool, transition_expiry: Option<u32>) {
        self.session
            .set_passthrough_mode(enabled, transition_expiry);
    }

    fn encrypt_opus(&mut self, opus_frame: &[u8]) -> Result<Vec<u8>, VoiceDaveError> {
        self.session
            .encrypt_opus(opus_frame)
            .map(|frame| frame.into_owned())
            .map_err(|error| VoiceDaveError::Encrypt(error.into()))
    }

    fn decrypt_packet(
        &mut self,
        user_id: Option<u64>,
        packet: &[u8],
    ) -> Result<Vec<u8>, VoiceDaveDecryptError> {
        self.session
            .decrypt(
                user_id.ok_or(VoiceDaveDecryptError::MissingUser)?,
                MediaType::AUDIO,
                packet,
            )
            .map_err(VoiceDaveDecryptError::from)
    }
}

struct VoiceDaveCoordinator {
    session: VoiceDaveySession,
    bot_user_id: u64,
    voice_channel_id: u64,
    external_sender_set: bool,
    sent_key_package_for: Option<VoiceDaveKeyPackageScope>,
    processed_proposals: usize,
    processed_welcome: Option<Vec<u8>>,
    processed_commit: Option<Vec<u8>>,
    transition_ready: Option<u16>,
    prepared_epoch: Option<VoiceDavePreparedEpoch>,
    last_gateway_state: Option<VoiceDaveGatewayStateEvent>,
    passthrough_enabled: bool,
}

impl VoiceDaveCoordinator {
    fn new(bot_user_id: u64, voice_channel_id: u64) -> VoiceResult<Self> {
        Ok(Self {
            session: VoiceDaveySession::discord_default(bot_user_id, voice_channel_id)?,
            bot_user_id,
            voice_channel_id,
            external_sender_set: false,
            sent_key_package_for: None,
            processed_proposals: 0,
            processed_welcome: None,
            processed_commit: None,
            transition_ready: None,
            prepared_epoch: None,
            last_gateway_state: None,
            passthrough_enabled: false,
        })
    }

    fn ready(&self) -> bool {
        self.session.is_ready()
    }

    fn transition_ready(&self) -> Option<u16> {
        self.transition_ready
    }

    fn session_mut(&mut self) -> &mut VoiceDaveySession {
        &mut self.session
    }

    fn set_passthrough_mode(&mut self, enabled: bool, transition_expiry: Option<u32>) {
        if self.passthrough_enabled == enabled {
            return;
        }
        self.session
            .set_passthrough_mode(enabled, transition_expiry);
        self.passthrough_enabled = enabled;
    }

    fn pump<D>(
        &mut self,
        command_tx: &mpsc::Sender<VoiceGatewayCommand>,
        dave: &VoiceDaveInternalState,
        connected_user_ids: &HashSet<u64>,
        roster_authoritative: bool,
        observer: &D,
    ) -> VoiceResult<()>
    where
        D: VoiceConnectionObserver,
    {
        self.observe_gateway_state(observer, dave);
        self.sync_prepared_epoch(dave)?;

        if dave.protocol_version.unwrap_or(0) == 0 {
            self.set_passthrough_mode(true, Some(120));
            self.send_transition_ready(
                command_tx,
                observer,
                dave.transition_id,
                dave.protocol_version,
            )?;
            return Ok(());
        }

        let transition_zero_ready =
            voice_dave_transition_zero_media_ready(dave, self.transition_ready);
        self.set_passthrough_mode(
            transition_zero_ready && !voice_dave_gateway_media_ready(dave),
            Some(10),
        );

        if let Some(external_sender) = dave.external_sender.as_deref()
            && !self.external_sender_set
        {
            self.session.set_external_sender(external_sender)?;
            self.external_sender_set = true;
            observer.dave_external_sender_set(VoiceDaveKeyPackageEvent {
                protocol_version: dave.protocol_version,
            });
        }

        if let Some(key_package_scope) =
            VoiceDaveKeyPackageScope::from_state(dave, self.prepared_epoch)
            && self.sent_key_package_for != Some(key_package_scope)
        {
            send_gateway_command(
                command_tx,
                VoiceGatewayCommand::DaveMlsKeyPackage {
                    key_package: self.session.create_key_package()?,
                },
            )?;
            self.sent_key_package_for = Some(key_package_scope);
            observer.dave_key_package_sent(VoiceDaveKeyPackageEvent {
                protocol_version: Some(key_package_scope.protocol_version()),
            });
        }

        if !self.external_sender_set {
            return Ok(());
        }

        if self.processed_proposals > dave.proposals.len() {
            self.processed_proposals = 0;
        }
        if dave.proposals.len() > self.processed_proposals && !roster_authoritative {
            return Ok(());
        }
        let expected_user_ids = connected_user_ids.iter().copied().collect::<Vec<_>>();
        for proposals in dave.proposals.iter().skip(self.processed_proposals) {
            let (operation, proposal_bytes) = VoiceDaveProposalsOperation::parse(proposals)?;
            let mut commit_sent = false;
            let mut welcome_sent = false;
            match self.session.process_proposals(
                operation.kind,
                proposal_bytes,
                Some(expected_user_ids.as_slice()),
            ) {
                Ok(Some(commit_welcome)) => {
                    welcome_sent = commit_welcome.welcome.is_some();
                    send_gateway_command(
                        command_tx,
                        VoiceGatewayCommand::DaveMlsCommitWelcome {
                            commit: commit_welcome.commit,
                            welcome: commit_welcome.welcome,
                        },
                    )?;
                    commit_sent = true;
                }
                Ok(None) => {}
                Err(error) => {
                    self.processed_proposals += 1;
                    observer.dave_proposals_ignored(VoiceDaveIgnoredProposalsEvent {
                        operation: operation.label,
                        proposal_bytes: proposal_bytes.len(),
                        error: error.to_string(),
                    });
                    continue;
                }
            }
            self.processed_proposals += 1;
            observer.dave_proposals_processed(VoiceDaveProposalsEvent {
                operation: operation.label,
                proposal_bytes: proposal_bytes.len(),
                commit_sent,
                welcome_sent,
            });
        }

        if let Some(welcome) = dave.pending_welcome.as_ref()
            && self.processed_welcome.as_ref() != Some(welcome)
        {
            match self.session.process_welcome(welcome) {
                Ok(()) => {
                    self.processed_welcome = Some(welcome.clone());
                    self.send_transition_ready(
                        command_tx,
                        observer,
                        dave.transition_id,
                        dave.protocol_version,
                    )?;
                }
                Err(error) => {
                    self.processed_welcome = Some(welcome.clone());
                    if let Some(transition_id) = dave.transition_id {
                        send_gateway_command(
                            command_tx,
                            VoiceGatewayCommand::DaveMlsInvalidCommitWelcome(
                                VoiceDaveInvalidCommitWelcomeCommand { transition_id },
                            ),
                        )?;
                    }
                    if let Err(recovery_error) = self.recover_after_invalid_group(command_tx, dave)
                    {
                        return Err(voice_dave_recovery_error(
                            "welcome processing",
                            &error,
                            recovery_error,
                        ));
                    }
                    return Err(error.into());
                }
            }
        }

        if let Some(commit) = dave.pending_commit.as_ref()
            && self.processed_commit.as_ref() != Some(commit)
        {
            match self.session.process_commit(commit) {
                Ok(()) => {
                    self.processed_commit = Some(commit.clone());
                    self.send_transition_ready(
                        command_tx,
                        observer,
                        dave.transition_id,
                        dave.protocol_version,
                    )?;
                }
                Err(error) => {
                    self.processed_commit = Some(commit.clone());
                    if let Some(transition_id) = dave.transition_id {
                        send_gateway_command(
                            command_tx,
                            VoiceGatewayCommand::DaveMlsInvalidCommitWelcome(
                                VoiceDaveInvalidCommitWelcomeCommand { transition_id },
                            ),
                        )?;
                    }
                    if let Err(recovery_error) = self.recover_after_invalid_group(command_tx, dave)
                    {
                        return Err(voice_dave_recovery_error(
                            "commit processing",
                            &error,
                            recovery_error,
                        ));
                    }
                    return Err(error.into());
                }
            }
        }

        Ok(())
    }

    fn sync_prepared_epoch(&mut self, dave: &VoiceDaveInternalState) -> VoiceResult<()> {
        let prepared_epoch = VoiceDavePreparedEpoch::from_state(dave);
        if self.prepared_epoch == prepared_epoch {
            return Ok(());
        }

        if let Some(prepared_epoch) = prepared_epoch {
            self.sent_key_package_for = None;
            self.processed_proposals = 0;
            self.processed_welcome = None;
            self.processed_commit = None;
            self.transition_ready = None;
            if prepared_epoch.epoch == 1 {
                self.replace_session(prepared_epoch.protocol_version)?;
            }
        }
        self.prepared_epoch = prepared_epoch;
        Ok(())
    }

    fn replace_session(&mut self, protocol_version: u16) -> VoiceResult<()> {
        let protocol_version =
            NonZeroU16::new(protocol_version).ok_or(VoiceDaveError::InvalidProtocolVersion {
                version: protocol_version,
            })?;
        self.session =
            VoiceDaveySession::new(protocol_version, self.bot_user_id, self.voice_channel_id)?;
        self.external_sender_set = false;
        Ok(())
    }

    fn recover_after_invalid_group(
        &mut self,
        command_tx: &mpsc::Sender<VoiceGatewayCommand>,
        dave: &VoiceDaveInternalState,
    ) -> VoiceResult<()> {
        let Some(protocol_version) = dave.protocol_version else {
            return Ok(());
        };
        if protocol_version == 0 {
            self.set_passthrough_mode(true, Some(120));
            return Ok(());
        }

        self.replace_session(protocol_version)?;
        if let Some(external_sender) = dave.external_sender.as_deref() {
            self.session.set_external_sender(external_sender)?;
            self.external_sender_set = true;
        }
        if let Some(key_package_scope) =
            VoiceDaveKeyPackageScope::from_state(dave, self.prepared_epoch)
        {
            send_gateway_command(
                command_tx,
                VoiceGatewayCommand::DaveMlsKeyPackage {
                    key_package: self.session.create_key_package()?,
                },
            )?;
            self.sent_key_package_for = Some(key_package_scope);
        }
        self.processed_proposals = dave.proposals.len();
        Ok(())
    }

    fn observe_gateway_state(
        &mut self,
        observer: &impl VoiceConnectionObserver,
        dave: &VoiceDaveInternalState,
    ) {
        let gateway_state = VoiceDaveGatewayStateEvent::from_state(dave);
        if self.last_gateway_state.as_ref() == Some(&gateway_state) {
            return;
        }
        self.last_gateway_state = Some(gateway_state.clone());
        observer.dave_gateway_state(gateway_state);
    }

    fn send_transition_ready<D>(
        &mut self,
        command_tx: &mpsc::Sender<VoiceGatewayCommand>,
        observer: &D,
        transition_id: Option<u16>,
        protocol_version: Option<u16>,
    ) -> VoiceResult<()>
    where
        D: VoiceConnectionObserver,
    {
        let Some(transition_id) = transition_id else {
            return Ok(());
        };
        if self.transition_ready == Some(transition_id) {
            return Ok(());
        }
        let protocol_version = protocol_version.unwrap_or(0);
        send_gateway_command(
            command_tx,
            VoiceGatewayCommand::DaveProtocolTransitionReady(VoiceDaveTransitionReadyCommand {
                transition_id,
            }),
        )?;
        self.transition_ready = Some(transition_id);
        observer.dave_transition_ready_sent(VoiceDaveTransitionEvent {
            transition_id,
            protocol_version,
        });
        Ok(())
    }
}

fn voice_dave_recovery_error(
    operation: &'static str,
    original: &VoiceDaveError,
    recovery: VoiceError,
) -> VoiceError {
    let detail = format!("after {operation} error ({original}): {recovery}");
    match recovery {
        VoiceError::Dave(_) => VoiceDaveError::RecoverInvalidGroup { detail }.into(),
        _ => recovery,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VoiceDavePreparedEpoch {
    epoch: u64,
    protocol_version: u16,
    sequence: u64,
}

impl VoiceDavePreparedEpoch {
    fn from_state(dave: &VoiceDaveInternalState) -> Option<Self> {
        let protocol_version = dave.protocol_version?;
        if protocol_version == 0 {
            return None;
        }
        Some(Self {
            epoch: dave.epoch?,
            protocol_version,
            sequence: dave.prepare_epoch_sequence,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VoiceDaveKeyPackageScope {
    Session { protocol_version: u16 },
    Epoch(VoiceDavePreparedEpoch),
}

impl VoiceDaveKeyPackageScope {
    fn from_state(
        dave: &VoiceDaveInternalState,
        prepared_epoch: Option<VoiceDavePreparedEpoch>,
    ) -> Option<Self> {
        if let Some(prepared_epoch) = prepared_epoch
            && prepared_epoch.epoch == 1
        {
            return Some(Self::Epoch(prepared_epoch));
        }
        let protocol_version = dave.protocol_version?;
        (protocol_version > 0).then_some(Self::Session { protocol_version })
    }

    fn protocol_version(&self) -> u16 {
        match self {
            Self::Session { protocol_version } => *protocol_version,
            Self::Epoch(prepared_epoch) => prepared_epoch.protocol_version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveGatewayStateEvent {
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub epoch: Option<u64>,
    pub prepare_epoch_sequence: u64,
    pub passthrough: bool,
    pub mls: VoiceDaveMlsState,
}

impl VoiceDaveGatewayStateEvent {
    fn from_state(dave: &VoiceDaveInternalState) -> Self {
        Self {
            protocol_version: dave.protocol_version,
            transition_id: dave.transition_id,
            epoch: dave.epoch,
            prepare_epoch_sequence: dave.prepare_epoch_sequence,
            passthrough: dave.passthrough,
            mls: dave.mls_state(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveKeyPackageEvent {
    pub protocol_version: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveTransitionEvent {
    pub transition_id: u16,
    pub protocol_version: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveProposalsEvent {
    pub operation: &'static str,
    pub proposal_bytes: usize,
    pub commit_sent: bool,
    pub welcome_sent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveIgnoredProposalsEvent {
    pub operation: &'static str,
    pub proposal_bytes: usize,
    pub error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveMediaStatus {
    pub active: bool,
    pub media_ready: bool,
    pub session_ready: bool,
    pub transition_ready: Option<u16>,
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub mls: VoiceDaveMlsState,
}

struct VoiceDaveProposalsOperation {
    kind: ProposalsOperationType,
    label: &'static str,
}

impl VoiceDaveProposalsOperation {
    fn parse(payload: &[u8]) -> Result<(Self, &[u8]), VoiceDaveError> {
        let Some((&operation, proposals)) = payload.split_first() else {
            return Err(VoiceDaveError::InvalidProposalsPayload {
                detail: "payload was empty".to_string(),
            });
        };
        let (kind, label) = match operation {
            0 => (ProposalsOperationType::APPEND, "append"),
            1 => (ProposalsOperationType::REVOKE, "revoke"),
            other => {
                return Err(VoiceDaveError::InvalidProposalsPayload {
                    detail: format!("unknown proposals operation type {other}"),
                });
            }
        };
        Ok((Self { kind, label }, proposals))
    }
}

fn voice_dave_gateway_media_ready(dave: &VoiceDaveInternalState) -> bool {
    dave.transition_id.is_none()
        && dave.pending_commit.is_none()
        && dave.pending_welcome.is_none()
        && dave.proposals.is_empty()
}

fn voice_dave_transition_zero_media_ready(
    dave: &VoiceDaveInternalState,
    transition_ready: Option<u16>,
) -> bool {
    dave.transition_id == Some(0) && transition_ready == Some(0)
}

fn voice_dave_decrypt_failure_can_become_recoverable(kind: VoiceReceiveDecodeErrorKind) -> bool {
    matches!(
        kind,
        VoiceReceiveDecodeErrorKind::DaveNoDecryptorForUser
            | VoiceReceiveDecodeErrorKind::DaveNoValidCryptor
            | VoiceReceiveDecodeErrorKind::DaveOtherDecryptError
    )
}

fn voice_dave_decrypt_failure_should_retry(
    kind: VoiceReceiveDecodeErrorKind,
    state_can_still_change: bool,
) -> bool {
    if kind == VoiceReceiveDecodeErrorKind::DaveNoValidCryptor {
        return true;
    }
    voice_dave_decrypt_failure_can_become_recoverable(kind) && state_can_still_change
}

fn decrypted_rtp_payload(
    encrypted: Vec<u8>,
    opus_offset: usize,
    rtp: &VoiceRtpHeader,
) -> anyhow::Result<Vec<u8>> {
    let mut payload = encrypted
        .get(opus_offset..)
        .map(Vec::from)
        .ok_or_else(|| anyhow::anyhow!("voice RTP packet has truncated encrypted extension"))?;
    if rtp.padding {
        let padding = usize::from(
            *payload
                .last()
                .ok_or_else(|| anyhow::anyhow!("voice RTP packet has empty padded payload"))?,
        );
        if padding == 0 || padding > payload.len() {
            anyhow::bail!(
                "voice RTP packet has invalid padding length {padding} for payload length {}",
                payload.len()
            );
        }
        payload.truncate(payload.len() - padding);
    }
    Ok(payload)
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn parse_rtp_header(bytes: &[u8]) -> anyhow::Result<VoiceRtpHeader> {
    if bytes.len() < 12 {
        anyhow::bail!("voice RTP packet is shorter than 12 bytes");
    }

    let extension = bytes[0] & 0x10 != 0;
    let csrc_count = usize::from(bytes[0] & 0x0f);
    let mut header_len = 12 + csrc_count * 4;
    if bytes.len() < header_len {
        anyhow::bail!("voice RTP packet has truncated CSRC list");
    }

    let mut encrypted_body_offset = header_len;
    if extension {
        if bytes.len() < header_len + 4 {
            anyhow::bail!("voice RTP packet has truncated extension header");
        }
        encrypted_body_offset += 4;
        let extension_words = usize::from(u16::from_be_bytes([
            bytes[header_len + 2],
            bytes[header_len + 3],
        ]));
        header_len += 4 + extension_words * 4;
        if bytes.len() < header_len {
            anyhow::bail!("voice RTP packet has truncated extension payload");
        }
    }

    Ok(VoiceRtpHeader {
        version: bytes[0] >> 6,
        padding: bytes[0] & 0x20 != 0,
        extension,
        marker: bytes[1] & 0x80 != 0,
        payload_type: bytes[1] & 0x7f,
        sequence: u16::from_be_bytes([bytes[2], bytes[3]]),
        timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ssrc: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        header_len,
        encrypted_body_offset,
    })
}

fn decrypt_transport_payload(
    packet: &[u8],
    rtp: &VoiceRtpHeader,
    mode: &VoiceEncryptionMode,
    secret_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if secret_key.len() != 32 {
        anyhow::bail!("voice secret_key must be 32 bytes");
    }
    if packet.len() < rtp.encrypted_body_offset + VOICE_AEAD_TAG_LEN + VOICE_RTPSIZE_NONCE_LEN {
        anyhow::bail!("voice RTP packet is missing the RTP-size nonce suffix");
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
            .map_err(|_| anyhow::anyhow!("invalid AES-GCM voice secret key"))?;
        let mut nonce = [0_u8; 12];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(nonce_suffix);
        cipher
            .decrypt_in_place_detached(
                AesNonce::from_slice(&nonce),
                aad,
                &mut encrypted,
                AesTag::from_slice(tag),
            )
            .map_err(|_| anyhow::anyhow!("failed to decrypt AES-GCM voice packet"))?;
        return decrypted_rtp_payload(encrypted, opus_offset, rtp);
    }

    if mode == &VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize() {
        let cipher = XChaCha20Poly1305::new_from_slice(secret_key)
            .map_err(|_| anyhow::anyhow!("invalid XChaCha20-Poly1305 voice secret key"))?;
        let mut nonce = [0_u8; 24];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(nonce_suffix);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                aad,
                &mut encrypted,
                XTag::from_slice(tag),
            )
            .map_err(|_| anyhow::anyhow!("failed to decrypt XChaCha20-Poly1305 voice packet"))?;
        return decrypted_rtp_payload(encrypted, opus_offset, rtp);
    }

    anyhow::bail!("unsupported voice encryption mode for receive: {mode:?}");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VoiceOutboundEncryptParams {
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    payload_type: u8,
    nonce_suffix: [u8; 4],
}

fn encrypt_transport_payload(
    params: VoiceOutboundEncryptParams,
    opus_frame: &[u8],
    mode: &VoiceEncryptionMode,
    secret_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if secret_key.len() != 32 {
        anyhow::bail!("voice secret_key must be 32 bytes");
    }

    let mut packet = build_rtp_header(
        params.sequence,
        params.timestamp,
        params.ssrc,
        params.payload_type,
    );
    let aad = packet.clone();
    let mut encrypted = opus_frame.to_vec();

    if mode == &VoiceEncryptionMode::aead_aes256_gcm_rtpsize() {
        let cipher = Aes256Gcm::new_from_slice(secret_key)
            .map_err(|_| anyhow::anyhow!("invalid AES-GCM voice secret key"))?;
        let mut nonce = [0_u8; 12];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&params.nonce_suffix);
        let tag = cipher
            .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut encrypted)
            .map_err(|_| anyhow::anyhow!("failed to encrypt AES-GCM voice packet"))?;
        encrypted.extend_from_slice(&tag);
    } else if mode == &VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize() {
        let cipher = XChaCha20Poly1305::new_from_slice(secret_key)
            .map_err(|_| anyhow::anyhow!("invalid XChaCha20-Poly1305 voice secret key"))?;
        let mut nonce = [0_u8; 24];
        nonce[..VOICE_RTPSIZE_NONCE_LEN].copy_from_slice(&params.nonce_suffix);
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut encrypted)
            .map_err(|_| anyhow::anyhow!("failed to encrypt XChaCha20-Poly1305 voice packet"))?;
        encrypted.extend_from_slice(&tag);
    } else {
        anyhow::bail!("unsupported voice encryption mode for send: {mode:?}");
    }

    packet.extend_from_slice(&encrypted);
    packet.extend_from_slice(&params.nonce_suffix);
    Ok(packet)
}

fn build_rtp_header(sequence: u16, timestamp: u32, ssrc: u32, payload_type: u8) -> Vec<u8> {
    let mut packet = vec![RTP_VERSION << 6, payload_type & 0x7f];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet
}

fn timestamp_increment(sample_rate: u32, duration: Duration) -> u32 {
    let samples = (u128::from(sample_rate) * duration.as_nanos()) / 1_000_000_000;
    samples.max(1).min(u128::from(u32::MAX)) as u32
}

fn initial_voice_heartbeat_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64 % JS_MAX_SAFE_INTEGER)
        .unwrap_or(0)
}

fn next_voice_heartbeat_nonce(current: &mut u64) -> u64 {
    *current = current.wrapping_add(1) % JS_MAX_SAFE_INTEGER;
    *current
}

fn select_encryption_mode(
    config: &VoiceConnectionConfig,
    ready: &VoiceGatewayReady,
) -> anyhow::Result<VoiceEncryptionMode> {
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
        anyhow::bail!("voice ready payload did not include encryption modes");
    }
    anyhow::bail!(
        "voice ready payload did not include a supported encryption mode: {:?}",
        ready.modes
    )
}

fn update_state(
    channels: &VoiceConnectionStateChannels,
    update: impl FnOnce(&mut VoiceConnectionInternalState),
) {
    channels.update(update);
}

async fn connect_voice_websocket(
    websocket_url: &str,
) -> anyhow::Result<VoiceWebSocketConnectResult> {
    let (host, port) = voice_websocket_host_port(websocket_url)?;
    let addresses = ordered_voice_socket_addrs(
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolve voice websocket endpoint {host}:{port}"))?,
    );
    if addresses.is_empty() {
        anyhow::bail!("voice websocket endpoint {host}:{port} did not resolve to any addresses");
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
                Err(_) => Err(anyhow::anyhow!(
                    "voice websocket connect to {address} timed out after {:?}",
                    VOICE_WEBSOCKET_ADDRESS_CONNECT_TIMEOUT
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

    anyhow::bail!(
        "voice websocket connect to {host}:{port} failed across {} resolved addresses: {}",
        addresses.len(),
        errors.join("; ")
    );
}

async fn connect_voice_websocket_address(
    websocket_url: String,
    address: SocketAddr,
) -> anyhow::Result<VoiceWebSocketConnectResult> {
    let socket = TcpStream::connect(address)
        .await
        .with_context(|| format!("tcp connect {address}"))?;
    socket.set_nodelay(true)?;
    client_async_tls_with_config(websocket_url, socket, None, None)
        .await
        .map_err(anyhow::Error::new)
}

fn voice_websocket_host_port(websocket_url: &str) -> anyhow::Result<(String, u16)> {
    let request = websocket_url.into_client_request()?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("voice websocket URL did not include a host"))?
        .to_string();
    let port = uri
        .port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("voice websocket URL did not include a usable scheme"))?;
    Ok((host, port))
}

fn ordered_voice_socket_addrs(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
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

fn opus_packet_channels(opus_frame: &[u8]) -> anyhow::Result<usize> {
    let Some(toc) = opus_frame.first() else {
        anyhow::bail!("Opus packet is empty");
    };
    Ok(if toc & 0x04 != 0 { 2 } else { 1 })
}

async fn voice_stage_timeout<T>(
    stage: VoiceConnectStage,
    duration: Duration,
    future: impl Future<Output = anyhow::Result<T>>,
) -> VoiceResult<T> {
    match timeout(duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(VoiceError::Timeout {
            stage: Some(stage),
            duration,
        }),
    }
}

async fn observed_voice_stage_timeout<O, T>(
    observer: &O,
    connection: VoiceConnectionEvent<'_>,
    stage: VoiceConnectStage,
    duration: Duration,
    future: impl Future<Output = anyhow::Result<T>>,
) -> VoiceResult<T>
where
    O: VoiceConnectionObserver,
{
    let started = Instant::now();
    let result = voice_stage_timeout(stage, duration, future).await;
    match &result {
        Ok(_) => observer.connect_stage_completed(VoiceConnectStageCompletedEvent {
            endpoint: connection.endpoint,
            guild_id: connection.guild_id,
            user_id: connection.user_id,
            stage,
            elapsed: started.elapsed(),
        }),
        Err(error) => observer.connect_stage_failed(VoiceConnectStageFailedEvent {
            endpoint: connection.endpoint,
            guild_id: connection.guild_id,
            user_id: connection.user_id,
            stage,
            elapsed: started.elapsed(),
            error,
        }),
    }
    result
}

fn voice_heartbeat_ack_timeout(heartbeat_interval_ms: u64) -> Duration {
    Duration::from_millis(heartbeat_interval_ms.saturating_mul(2)).max(Duration::from_secs(1))
}

async fn read_voice_event(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> anyhow::Result<ParsedVoiceGatewayEvent> {
    loop {
        match read.next().await {
            Some(Ok(WsMessage::Text(text))) => return parse_voice_event_text(&text),
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
            None => anyhow::bail!("voice websocket closed unexpectedly"),
        }
    }
}

async fn wait_for_voice_opcode(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    opcode: VoiceOpcode,
    last_sequence: &mut Option<i64>,
) -> anyhow::Result<ParsedVoiceGatewayEvent> {
    loop {
        let event = read_voice_event(read).await?;
        if let Some(sequence) = event.sequence {
            *last_sequence = Some(sequence);
        }
        if event.opcode == opcode.code() {
            return Ok(event);
        }
    }
}

async fn wait_for_session_description(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    last_sequence: &mut Option<i64>,
) -> anyhow::Result<(ParsedVoiceGatewayEvent, Vec<PendingVoiceGatewayEvent>)> {
    let mut pending_events = Vec::new();
    loop {
        match read.next().await {
            Some(Ok(WsMessage::Text(text))) => {
                let event = parse_voice_event_text(&text)?;
                if let Some(sequence) = event.sequence {
                    *last_sequence = Some(sequence);
                }
                if event.opcode == VoiceOpcode::SessionDescription.code() {
                    return Ok((event, pending_events));
                }
                pending_events.push(PendingVoiceGatewayEvent::Text(event));
            }
            Some(Ok(WsMessage::Binary(bytes))) => {
                pending_events.push(PendingVoiceGatewayEvent::Binary(bytes.to_vec()));
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
            None => anyhow::bail!("voice websocket closed unexpectedly"),
        }
    }
}

enum PendingVoiceGatewayEvent {
    Text(ParsedVoiceGatewayEvent),
    Binary(Vec<u8>),
}

fn replay_pending_voice_events(
    state: &VoiceConnectionStateChannels,
    pending_events: Vec<PendingVoiceGatewayEvent>,
    observer: &impl VoiceConnectionObserver,
) -> anyhow::Result<()> {
    let mut heartbeat_ack_pending = false;
    let mut heartbeat_sent_at = None;
    for event in pending_events {
        match event {
            PendingVoiceGatewayEvent::Text(event) => {
                if let Some(sequence) = event.sequence {
                    update_state(state, |state| state.last_sequence = Some(sequence));
                }
                handle_voice_text_event(
                    state,
                    event,
                    &mut heartbeat_ack_pending,
                    &mut heartbeat_sent_at,
                    observer,
                )?;
            }
            PendingVoiceGatewayEvent::Binary(bytes) => {
                handle_voice_binary_event(state, &bytes)?;
            }
        }
    }
    Ok(())
}

fn parse_voice_event_text(text: &str) -> anyhow::Result<ParsedVoiceGatewayEvent> {
    let event: VoiceGatewayEvent = serde_json::from_str(text)?;
    Ok(ParsedVoiceGatewayEvent {
        opcode: event.op,
        sequence: event.seq,
        data: event.d.unwrap_or(Value::Null),
    })
}

fn parse_voice_data<T>(data: Value) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    Ok(serde_json::from_value(data)?)
}

fn handle_voice_text_event(
    channels: &VoiceConnectionStateChannels,
    event: ParsedVoiceGatewayEvent,
    heartbeat_ack_pending: &mut bool,
    heartbeat_sent_at: &mut Option<Instant>,
    observer: &impl VoiceConnectionObserver,
) -> anyhow::Result<()> {
    let state = channels.internal();
    let endpoint = state.config.endpoint.clone();
    let guild_id = state.config.server_id;
    let user_id = state.config.user_id;
    drop(state);

    match VoiceOpcode::from_code(event.opcode) {
        Some(VoiceOpcode::SessionDescription) => {
            let description: VoiceSessionDescription = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state
                    .dave
                    .set_session_protocol(description.dave_protocol_version);
                state.session_description = Some(description);
            });
        }
        Some(VoiceOpcode::Resumed) => {
            update_state(channels, |state| state.resumed = true);
        }
        Some(VoiceOpcode::DavePrepareTransition) => {
            let transition: VoiceDavePrepareTransitionEvent = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state
                    .dave
                    .prepare_transition(transition.transition_id, transition.protocol_version);
            });
        }
        Some(VoiceOpcode::DaveExecuteTransition) => {
            let transition: VoiceDaveExecuteTransitionEvent = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state.dave.execute_transition(transition.transition_id);
            });
        }
        Some(VoiceOpcode::DavePrepareEpoch) => {
            let epoch: VoiceDavePrepareEpochEvent = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state
                    .dave
                    .prepare_epoch(epoch.protocol_version, epoch.epoch);
            });
        }
        Some(VoiceOpcode::Speaking) => {
            let update: VoiceSpeakingUpdate = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                if let Some(user_id) = update.user_id.as_ref() {
                    state.ssrc_users.insert(update.ssrc, user_id.get());
                }
                state.speaking.insert(update.ssrc, update);
            });
        }
        Some(VoiceOpcode::ClientsConnect) => {
            let clients: VoiceClientsConnectEvent = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state.roster_authoritative = true;
                state
                    .connected_user_ids
                    .extend(clients.user_ids.iter().map(DiscordId::get));
            });
            if !clients.user_ids.is_empty() {
                observer.clients_connected(VoiceClientsConnectedEvent {
                    endpoint: &endpoint,
                    guild_id,
                    user_id,
                    user_count: clients.user_ids.len(),
                });
            }
        }
        Some(VoiceOpcode::ClientConnect) => {
            let client: VoiceClientConnectEvent = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state.roster_authoritative = true;
                state.connected_user_ids.insert(client.user_id.get());
                if let Some(ssrc) = client.voice_ssrc() {
                    state.ssrc_users.insert(ssrc, client.user_id.get());
                }
            });
        }
        Some(VoiceOpcode::ClientDisconnect) => {
            let disconnect: VoiceClientDisconnectEvent = parse_voice_data(event.data)?;
            update_state(channels, |state| {
                state.roster_authoritative = true;
                state.connected_user_ids.remove(&disconnect.user_id.get());
                state
                    .ssrc_users
                    .retain(|_, stored_user_id| stored_user_id != &disconnect.user_id.get());
            });
        }
        Some(VoiceOpcode::HeartbeatAck) => {
            *heartbeat_ack_pending = false;
            *heartbeat_sent_at = None;
        }
        Some(
            VoiceOpcode::Hello | VoiceOpcode::Ready | VoiceOpcode::Heartbeat | VoiceOpcode::Resume,
        ) => {}
        _ => {}
    }

    Ok(())
}

fn handle_voice_binary_event(
    channels: &VoiceConnectionStateChannels,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let Some(event) = VoiceBinaryEvent::parse(bytes) else {
        return Ok(());
    };
    if let Some(sequence) = event.sequence {
        update_state(channels, |state| state.last_sequence = Some(sequence));
    }

    match event.opcode {
        VoiceOpcode::DaveMlsExternalSender => {
            update_state(channels, |state| {
                state.dave.external_sender = Some(event.payload.to_vec())
            });
        }
        VoiceOpcode::DaveMlsProposals => {
            update_state(channels, |state| {
                state.dave.proposals.push(event.payload.to_vec())
            });
        }
        VoiceOpcode::DaveMlsAnnounceCommitTransition if event.payload.len() >= 2 => {
            let transition_id = u16::from_be_bytes([event.payload[0], event.payload[1]]);
            let commit = event.payload[2..].to_vec();
            update_state(channels, |state| {
                if state.dave.transition_id != Some(transition_id) {
                    state.dave.clear_pending_mls();
                }
                state.dave.transition_id = Some(transition_id);
                state.dave.pending_commit = Some(commit);
            });
        }
        VoiceOpcode::DaveMlsWelcome if event.payload.len() >= 2 => {
            let transition_id = u16::from_be_bytes([event.payload[0], event.payload[1]]);
            let welcome = event.payload[2..].to_vec();
            update_state(channels, |state| {
                if state.dave.transition_id != Some(transition_id) {
                    state.dave.clear_pending_mls();
                }
                state.dave.transition_id = Some(transition_id);
                state.dave.pending_welcome = Some(welcome);
            });
        }
        _ => {}
    }

    Ok(())
}

struct VoiceBinaryEvent<'a> {
    sequence: Option<i64>,
    opcode: VoiceOpcode,
    payload: &'a [u8],
}

impl<'a> VoiceBinaryEvent<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        match bytes {
            [first, second, opcode, payload @ ..] => {
                let opcode = VoiceOpcode::from_server_binary(*opcode)?;
                Some(Self {
                    sequence: Some(i64::from(u16::from_be_bytes([*first, *second]))),
                    opcode,
                    payload,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> VoiceConnectionInternalState {
        let selected_mode = VoiceEncryptionMode::aead_aes256_gcm_rtpsize();
        VoiceConnectionInternalState {
            config: VoiceConnectionConfig::new(1, 2, 3, "session", "token", "127.0.0.1"),
            heartbeat_interval_ms: 50,
            last_sequence: None,
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
        let (command_tx, _command_rx) = mpsc::channel::<VoiceGatewayCommand>(1);
        let udp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        udp_socket.connect("127.0.0.1:9").await.unwrap();
        VoiceConnection {
            inner: Arc::new(VoiceConnectionInner {
                state,
                command_tx,
                close: VoiceConnectionClose::new(),
                task: SyncMutex::new(Some(tokio::spawn(async {
                    std::future::pending::<VoiceResult<()>>().await
                }))),
                udp_socket,
                outbound_rtp: Arc::new(Mutex::new(VoiceOutboundRtpState::new(42))),
                dave: Mutex::new(VoiceDaveCoordinator::new(3, 2).unwrap()),
                receive: Mutex::new(VoiceReceiveState::default()),
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
    fn missing_dave_user_is_typed_error() {
        let mut session = VoiceDaveySession::discord_default(1, 2).unwrap();
        assert_eq!(
            session.decrypt_packet(None, b"packet").unwrap_err(),
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
    fn heartbeat_payload_includes_sequence_ack() {
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
        transport_crypto_decrypts_rtp_extensions(
            VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize(),
        );
    }

    #[test]
    fn transport_crypto_strips_rtp_padding_after_decrypt() {
        transport_crypto_strips_rtp_padding(VoiceEncryptionMode::aead_aes256_gcm_rtpsize());
        transport_crypto_strips_rtp_padding(VoiceEncryptionMode::aead_xchacha20_poly1305_rtpsize());
    }

    #[test]
    fn raw_udp_packet_parses_rtcp_header() {
        let packet =
            VoiceRawUdpPacket::from_bytes(vec![0x81, 201, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef]);

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
                sequence: 10,
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
            .decode_packet(VoiceReceivedPacket {
                raw: VoiceRawUdpPacket::from_bytes(Vec::new()),
                rtp: VoiceRtpHeader {
                    version: RTP_VERSION,
                    padding: false,
                    extension: false,
                    marker: false,
                    payload_type: RTP_PAYLOAD_TYPE_OPUS,
                    sequence: 0,
                    timestamp: 0,
                    ssrc: 0,
                    header_len: 12,
                    encrypted_body_offset: 12,
                },
                user_id: Some(1),
                opus_frame: opus.bytes,
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
            .decode_packet(test_received_packet(opus[..written].to_vec()))
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

    fn test_received_packet(opus_frame: Vec<u8>) -> VoiceReceivedPacket {
        VoiceReceivedPacket {
            raw: VoiceRawUdpPacket::from_bytes(Vec::new()),
            rtp: VoiceRtpHeader {
                version: RTP_VERSION,
                padding: false,
                extension: false,
                marker: false,
                payload_type: RTP_PAYLOAD_TYPE_OPUS,
                sequence: 0,
                timestamp: 0,
                ssrc: 0,
                header_len: 12,
                encrypted_body_offset: 12,
            },
            user_id: Some(1),
            opus_frame,
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
                sequence: Some(7),
                data: serde_json::from_str(r#"{"user_ids":["469770478001586176"]}"#).unwrap(),
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
                .contains(&469_770_478_001_586_176)
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
                sequence: None,
                data: serde_json::from_str(
                    r#"{"user_id":"469770478001586176","audio_ssrc":123,"video_ssrc":456}"#,
                )
                .unwrap(),
            },
            &mut ack_pending,
            &mut heartbeat_sent_at,
            &NoopVoiceConnectionObserver,
        )
        .unwrap();

        assert_eq!(
            state_tx.internal().ssrc_users.get(&123),
            Some(&469_770_478_001_586_176)
        );
        assert!(
            state_tx
                .internal()
                .connected_user_ids
                .contains(&469_770_478_001_586_176)
        );
    }

    #[test]
    fn client_disconnect_removes_user_from_media_roster_and_ssrcs() {
        let state_tx = VoiceConnectionStateChannels::new({
            let mut state = test_state();
            state.connected_user_ids.insert(469_770_478_001_586_176);
            state.ssrc_users.insert(123, 469_770_478_001_586_176);
            state.ssrc_users.insert(456, 1);
            state
        });
        let mut ack_pending = false;
        let mut heartbeat_sent_at = None;

        handle_voice_text_event(
            &state_tx,
            ParsedVoiceGatewayEvent {
                opcode: VoiceOpcode::ClientDisconnect.code(),
                sequence: None,
                data: serde_json::from_str(r#"{"user_id":"469770478001586176"}"#).unwrap(),
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
                .contains(&469_770_478_001_586_176)
        );
        assert!(!state_tx.internal().ssrc_users.contains_key(&123));
        assert_eq!(state_tx.internal().ssrc_users.get(&456), Some(&1));
    }

    #[test]
    fn hello_accepts_fractional_heartbeat_interval() {
        let hello: VoiceHelloData =
            serde_json::from_str(r#"{"heartbeat_interval":41250.5}"#).unwrap();
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
    fn dave_binary_parser_accepts_sequence_prefixed_server_frames() {
        let bytes = [0, 7, VoiceOpcode::DaveMlsExternalSender.byte(), 0xde, 0xad];
        let event = VoiceBinaryEvent::parse(&bytes).unwrap();
        assert_eq!(event.sequence, Some(7));
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
                sequence: Some(11),
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
        assert_eq!(state.dave.prepare_epoch_sequence, 1);
        assert!(state.dave.proposals.is_empty());
        assert!(state.dave.pending_commit.is_none());
        assert!(state.dave.pending_welcome.is_none());
    }

    #[test]
    fn dave_repeated_prepare_epoch_events_remain_distinct() {
        let state_tx = test_state_channels();
        let mut ack_pending = false;
        let mut heartbeat_sent_at = None;

        for sequence in [11, 12] {
            update_state(&state_tx, |state| {
                state.dave.proposals.push(vec![0xde]);
                state.dave.pending_commit = Some(vec![0xad]);
                state.dave.pending_welcome = Some(vec![0xbe]);
            });

            handle_voice_text_event(
                &state_tx,
                ParsedVoiceGatewayEvent {
                    opcode: VoiceOpcode::DavePrepareEpoch.code(),
                    sequence: Some(sequence),
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
        assert_eq!(state.dave.prepare_epoch_sequence, 2);
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
    fn dave_no_valid_cryptor_remains_retryable_after_state_looks_stable() {
        assert!(voice_dave_decrypt_failure_should_retry(
            VoiceReceiveDecodeErrorKind::DaveNoValidCryptor,
            false
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
    fn dave_prepared_epoch_scope_includes_prepare_event_sequence() {
        let mut first = VoiceDaveInternalState {
            protocol_version: Some(1),
            epoch: Some(1),
            prepare_epoch_sequence: 1,
            ..VoiceDaveInternalState::default()
        };
        let second = VoiceDaveInternalState {
            prepare_epoch_sequence: 2,
            ..first.clone()
        };

        assert_ne!(
            VoiceDavePreparedEpoch::from_state(&first),
            VoiceDavePreparedEpoch::from_state(&second)
        );

        first.prepare_epoch_sequence = 2;
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
}
