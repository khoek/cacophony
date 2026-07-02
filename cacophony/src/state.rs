use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use dave::{Codec, DAVE_PROTOCOL_VERSION, MediaType};
use serde::{Deserialize, Deserializer, Serialize, de};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use zeroize::Zeroize;

use crate::{
    codecs::{self, DiscordRtpCodecMap},
    dave::DaveIdentityKey,
    errors::{Error, InvalidInputError, Result},
    gateway::{GatewayReady, SpeakingUpdate, UdpDiscoveryPacket},
    media::{
        FrameRaw, RtpFrameAssembler, RtpHeader, TransportCryptoConfig, duration_ms, duration_us,
    },
    observer::{
        ConnectionEvent, ConnectionObserver, DavePendingMediaEvent, DavePendingMediaReason,
        ReceiveRtpPacketEvent, ReceiveRtpPacketLossEvent, WebSocketCloseFrame,
    },
    queue::{BucketDeadlineQueue, DeadlineSet, QueueBucket},
    secrets::RedactedSecret,
    stats::SlidingStats,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionTuning {
    pub dave_pending_media_ttl: Duration,
    pub receive_interarrival_window: usize,
    pub rtp_reorder_ttl: Duration,
    pub rtp_reorder_buffer_max_frames: usize,
    pub udp_receive_buffer_bytes: usize,
    pub ready_frame_buffer_max: usize,
    pub media_queue_capacity: usize,
}

impl Default for ConnectionTuning {
    fn default() -> Self {
        Self {
            dave_pending_media_ttl: Duration::from_secs(10),
            receive_interarrival_window: 256,
            rtp_reorder_ttl: Duration::from_millis(60),
            rtp_reorder_buffer_max_frames: 32,
            udp_receive_buffer_bytes: u16::MAX as usize,
            ready_frame_buffer_max: 4096,
            media_queue_capacity: 256,
        }
    }
}

impl ConnectionTuning {
    pub(crate) fn validate(self) -> Result<ConnectionRuntimeTuning> {
        for (field, duration) in [
            ("dave_pending_media_ttl", self.dave_pending_media_ttl),
            ("rtp_reorder_ttl", self.rtp_reorder_ttl),
        ] {
            if duration.is_zero() {
                return Err(Error::InvalidInput(
                    InvalidInputError::ConnectionTuningDurationZero { field },
                ));
            }
        }
        let receive_interarrival_window = nonzero_tuning(
            self.receive_interarrival_window,
            "receive_interarrival_window",
        )?;
        let rtp_reorder_buffer_max_frames = nonzero_tuning(
            self.rtp_reorder_buffer_max_frames,
            "rtp_reorder_buffer_max_frames",
        )?;
        let udp_receive_buffer_bytes =
            nonzero_tuning(self.udp_receive_buffer_bytes, "udp_receive_buffer_bytes")?;
        let ready_frame_buffer_max =
            nonzero_tuning(self.ready_frame_buffer_max, "ready_frame_buffer_max")?;
        let media_queue_capacity =
            nonzero_tuning(self.media_queue_capacity, "media_queue_capacity")?;
        if self.udp_receive_buffer_bytes < u16::MAX as usize {
            return Err(Error::InvalidInput(
                InvalidInputError::ConnectionTuningTooSmall {
                    field: "udp_receive_buffer_bytes",
                    min: u16::MAX as usize,
                    actual: self.udp_receive_buffer_bytes,
                },
            ));
        }
        Ok(ConnectionRuntimeTuning {
            dave_pending_media_ttl: self.dave_pending_media_ttl,
            receive_interarrival_window,
            rtp_reorder_ttl: self.rtp_reorder_ttl,
            rtp_reorder_buffer_max_frames,
            udp_receive_buffer_bytes,
            ready_frame_buffer_max,
            media_queue_capacity,
        })
    }
}

fn nonzero_tuning(value: usize, field: &'static str) -> Result<NonZeroUsize> {
    NonZeroUsize::new(value).ok_or(Error::InvalidInput(
        InvalidInputError::ConnectionTuningZero { field },
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionRuntimeTuning {
    pub(crate) dave_pending_media_ttl: Duration,
    pub(crate) receive_interarrival_window: NonZeroUsize,
    pub(crate) rtp_reorder_ttl: Duration,
    pub(crate) rtp_reorder_buffer_max_frames: NonZeroUsize,
    pub(crate) udp_receive_buffer_bytes: NonZeroUsize,
    pub(crate) ready_frame_buffer_max: NonZeroUsize,
    pub(crate) media_queue_capacity: NonZeroUsize,
}

impl Default for ConnectionRuntimeTuning {
    fn default() -> Self {
        ConnectionTuning::default()
            .validate()
            .expect("default connection tuning is valid")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VideoCodecPreferences {
    codecs: Vec<Codec>,
}

impl VideoCodecPreferences {
    pub fn all_libdave() -> Self {
        Self::new(codecs::video_codecs().collect::<Vec<_>>())
            .expect("libdave video codec list is valid")
    }

    pub fn new(video_codecs: impl Into<Vec<Codec>>) -> Result<Self> {
        let codecs = video_codecs.into();
        validate_video_codecs(&codecs)?;
        Ok(Self { codecs })
    }

    pub fn is_empty(&self) -> bool {
        self.codecs.is_empty()
    }

    pub fn as_slice(&self) -> &[Codec] {
        &self.codecs
    }

    pub fn iter(&self) -> impl Iterator<Item = Codec> + '_ {
        self.codecs.iter().copied()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionCodecPreferences {
    pub video_codecs: VideoCodecPreferences,
}

impl ConnectionCodecPreferences {
    pub fn all_libdave_video_codecs() -> Self {
        Self {
            video_codecs: VideoCodecPreferences::all_libdave(),
        }
    }

    pub fn with_video_codecs(video_codecs: impl Into<Vec<Codec>>) -> Result<Self> {
        Ok(Self {
            video_codecs: VideoCodecPreferences::new(video_codecs)?,
        })
    }

    pub fn video_enabled(&self) -> bool {
        !self.video_codecs.is_empty()
    }

    pub(crate) fn video_codecs(&self) -> &[Codec] {
        self.video_codecs.as_slice()
    }
}

fn validate_video_codecs(video_codecs: &[Codec]) -> Result<()> {
    let mut seen = HashSet::with_capacity(video_codecs.len());
    for &codec in video_codecs {
        if codec.media_type() != MediaType::Video {
            return Err(Error::InvalidInput(
                InvalidInputError::VideoCodecPreferenceNotVideo { codec },
            ));
        }
        if !seen.insert(codec) {
            return Err(Error::InvalidInput(
                InvalidInputError::DuplicateVideoCodecPreference { codec },
            ));
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub guild_id: u64,
    pub channel_id: u64,
    pub user_id: u64,
    pub session_id: String,
    pub token: String,
    pub endpoint: String,
}

impl Drop for ConnectionConfig {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.token.zeroize();
    }
}

impl fmt::Debug for ConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionConfig")
            .field("guild_id", &self.guild_id)
            .field("channel_id", &self.channel_id)
            .field("user_id", &self.user_id)
            .field("session_id", &"<redacted>")
            .field("token", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionOptions {
    pub gateway_version: u8,
    pub required_mode: Option<EncryptionMode>,
    pub max_dave_protocol_version: Option<u16>,
    pub dave_identity: Option<DaveIdentityKey>,
    pub dave_send_media_ready_timeout: Duration,
    pub codec_preferences: ConnectionCodecPreferences,
    pub tuning: ConnectionTuning,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            gateway_version: 8,
            required_mode: Some(EncryptionMode::aead_aes256_gcm_rtpsize()),
            max_dave_protocol_version: Some(DAVE_PROTOCOL_VERSION.get()),
            dave_identity: None,
            dave_send_media_ready_timeout: crate::DAVE_SEND_MEDIA_READY_TIMEOUT,
            codec_preferences: ConnectionCodecPreferences::default(),
            tuning: ConnectionTuning::default(),
        }
    }
}

pub(crate) type SessionId = RedactedSecret<String>;
pub(crate) type Token = RedactedSecret<String>;

impl ConnectionConfig {
    pub fn with_options(self, options: ConnectionOptions) -> ConnectionRequest {
        ConnectionRequest {
            config: self,
            options,
        }
    }

    pub fn validate(self) -> Result<ValidatedConnectionConfig> {
        self.with_options(ConnectionOptions::default()).validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub config: ConnectionConfig,
    pub options: ConnectionOptions,
}

impl ConnectionRequest {
    pub fn validate(mut self) -> Result<ValidatedConnectionConfig> {
        let options = self.options.validate()?;
        let session_id = std::mem::take(&mut self.config.session_id);
        let token = std::mem::take(&mut self.config.token);
        let endpoint = std::mem::take(&mut self.config.endpoint);
        let websocket_url = websocket_url(&endpoint, options.gateway_version);
        Ok(ValidatedConnectionConfig {
            identity: ConnectionIdentity {
                guild_id: self.config.guild_id,
                channel_id: self.config.channel_id,
                user_id: self.config.user_id,
            },
            secrets: ConnectionSecrets {
                session_id: SessionId::new(session_id),
                token: Token::new(token),
            },
            endpoint,
            websocket_url,
            options,
        })
    }
}

impl ConnectionOptions {
    pub fn validate(self) -> Result<ValidatedConnectionOptions> {
        if self.gateway_version < 4 {
            return Err(Error::InvalidInput(
                InvalidInputError::UnsupportedGatewayVersion {
                    version: self.gateway_version,
                },
            ));
        }
        Ok(ValidatedConnectionOptions {
            gateway_version: self.gateway_version,
            required_mode: self.required_mode,
            max_dave_protocol_version: self.max_dave_protocol_version,
            dave_identity: self.dave_identity,
            dave_send_media_ready_timeout: self.dave_send_media_ready_timeout,
            codec_preferences: self.codec_preferences,
            tuning: self.tuning.validate()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedConnectionOptions {
    pub gateway_version: u8,
    pub required_mode: Option<EncryptionMode>,
    pub max_dave_protocol_version: Option<u16>,
    pub dave_identity: Option<DaveIdentityKey>,
    pub dave_send_media_ready_timeout: Duration,
    pub codec_preferences: ConnectionCodecPreferences,
    pub(crate) tuning: ConnectionRuntimeTuning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionIdentity {
    pub(crate) guild_id: u64,
    pub(crate) channel_id: u64,
    pub(crate) user_id: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ConnectionSecrets {
    pub(crate) session_id: SessionId,
    pub(crate) token: Token,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedConnectionConfig {
    pub(crate) identity: ConnectionIdentity,
    pub(crate) secrets: ConnectionSecrets,
    pub(crate) endpoint: String,
    pub(crate) websocket_url: String,
    pub(crate) options: ValidatedConnectionOptions,
}

impl fmt::Debug for ValidatedConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedConnectionConfig")
            .field("identity", &self.identity)
            .field("session_id", &"<redacted>")
            .field("token", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("websocket_url", &self.websocket_url)
            .field("options", &self.options)
            .finish()
    }
}

impl ValidatedConnectionConfig {
    pub fn info(&self) -> ConnectionInfo {
        ConnectionInfo {
            guild_id: self.identity.guild_id,
            channel_id: self.identity.channel_id,
            user_id: self.identity.user_id,
            endpoint: self.endpoint.clone(),
            gateway_version: self.options.gateway_version,
            max_dave_protocol_version: self.options.max_dave_protocol_version,
        }
    }

    pub fn options(&self) -> &ValidatedConnectionOptions {
        &self.options
    }

    pub(crate) fn runtime_config(self) -> ConnectionRuntimeConfig {
        ConnectionRuntimeConfig {
            identity: self.identity,
            endpoint: self.endpoint,
            options: self.options,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionRuntimeConfig {
    pub(crate) identity: ConnectionIdentity,
    pub(crate) endpoint: String,
    pub(crate) options: ValidatedConnectionOptions,
}

impl ConnectionRuntimeConfig {
    pub(crate) fn public_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            guild_id: self.identity.guild_id,
            channel_id: self.identity.channel_id,
            user_id: self.identity.user_id,
            endpoint: self.endpoint.clone(),
            gateway_version: self.options.gateway_version,
            max_dave_protocol_version: self.options.max_dave_protocol_version,
        }
    }
}

fn websocket_url(endpoint: &str, gateway_version: u8) -> String {
    let mut endpoint = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("wss://{endpoint}")
    };

    if !endpoint.contains("?v=") {
        let separator = if endpoint.contains('?') { "&" } else { "/?" };
        endpoint.push_str(separator);
        endpoint.push_str(&format!("v={gateway_version}"));
    }

    endpoint
}

impl WebSocketCloseFrame {
    pub(crate) fn from_frame(frame: &CloseFrame) -> Self {
        Self {
            code: format!("{:?}", frame.code),
            reason: frame.reason.to_string(),
            discord_call_terminated: matches!(frame.code, CloseCode::Library(4022)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EncryptionMode {
    #[serde(rename = "aead_aes256_gcm_rtpsize")]
    AeadAes256GcmRtpSize,
    #[serde(rename = "aead_xchacha20_poly1305_rtpsize")]
    AeadXChaCha20Poly1305RtpSize,
}

impl EncryptionMode {
    pub const ALL: [Self; 2] = [
        Self::AeadAes256GcmRtpSize,
        Self::AeadXChaCha20Poly1305RtpSize,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AeadAes256GcmRtpSize => "aead_aes256_gcm_rtpsize",
            Self::AeadXChaCha20Poly1305RtpSize => "aead_xchacha20_poly1305_rtpsize",
        }
    }

    pub const fn aead_aes256_gcm_rtpsize() -> Self {
        Self::AeadAes256GcmRtpSize
    }

    pub const fn aead_xchacha20_poly1305_rtpsize() -> Self {
        Self::AeadXChaCha20Poly1305RtpSize
    }
}

impl fmt::Display for EncryptionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OfferedEncryptionMode(String);

impl OfferedEncryptionMode {
    pub fn new(mode: impl Into<String>) -> Self {
        Self(mode.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_supported(mode: EncryptionMode) -> Self {
        Self(mode.as_str().to_string())
    }

    pub fn supported(&self) -> Option<EncryptionMode> {
        EncryptionMode::ALL
            .into_iter()
            .find(|mode| self.0 == mode.as_str())
    }
}

impl From<EncryptionMode> for OfferedEncryptionMode {
    fn from(mode: EncryptionMode) -> Self {
        Self::new(mode.as_str())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SessionDescription {
    pub mode: EncryptionMode,
    #[serde(default, skip_serializing)]
    pub(crate) secret_key: SecretKey,
    #[serde(skip_serializing)]
    pub(crate) transport_crypto: TransportCryptoConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_codec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video_codec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dave_protocol_version: Option<u16>,
}

impl SessionDescription {
    pub(crate) fn new(parts: SessionDescriptionParts) -> Result<Self> {
        Ok(Self {
            transport_crypto: TransportCryptoConfig::new(parts.mode, parts.secret_key.as_slice())?,
            mode: parts.mode,
            secret_key: parts.secret_key,
            audio_codec: parts.audio_codec,
            video_codec: parts.video_codec,
            dave_protocol_version: parts.dave_protocol_version,
        })
    }
}

pub(crate) struct SessionDescriptionParts {
    pub(crate) mode: EncryptionMode,
    pub(crate) secret_key: SecretKey,
    pub(crate) audio_codec: Option<String>,
    pub(crate) video_codec: Option<String>,
    pub(crate) dave_protocol_version: Option<u16>,
}

impl<'de> Deserialize<'de> for SessionDescription {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireSessionDescription {
            mode: EncryptionMode,
            #[serde(default)]
            secret_key: SecretKey,
            audio_codec: Option<String>,
            video_codec: Option<String>,
            dave_protocol_version: Option<u16>,
        }

        let wire = WireSessionDescription::deserialize(deserializer)?;
        Self::new(SessionDescriptionParts {
            mode: wire.mode,
            secret_key: wire.secret_key,
            audio_codec: wire.audio_codec,
            video_codec: wire.video_codec,
            dave_protocol_version: wire.dave_protocol_version,
        })
        .map_err(de::Error::custom)
    }
}

impl fmt::Debug for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionDescription")
            .field("mode", &self.mode)
            .field("secret_key", &self.secret_key)
            .field("audio_codec", &self.audio_codec)
            .field("video_codec", &self.video_codec)
            .field("dave_protocol_version", &self.dave_protocol_version)
            .finish()
    }
}

pub(crate) type SecretKey = RedactedSecret<Vec<u8>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub guild_id: u64,
    pub channel_id: u64,
    pub user_id: u64,
    pub endpoint: String,
    pub gateway_version: u8,
    pub max_dave_protocol_version: Option<u16>,
}

impl ConnectionInfo {
    pub(crate) fn connection_event(&self) -> ConnectionEvent<'_> {
        ConnectionEvent {
            endpoint: &self.endpoint,
            guild_id: self.guild_id,
            user_id: self.user_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionState {
    pub mode: EncryptionMode,
    pub audio_codec: Option<String>,
    pub video_codec: Option<String>,
    pub dave_protocol_version: Option<u16>,
}

impl From<&SessionDescription> for SessionState {
    fn from(description: &SessionDescription) -> Self {
        Self {
            mode: description.mode,
            audio_codec: description.audio_codec.clone(),
            video_codec: description.video_codec.clone(),
            dave_protocol_version: description.dave_protocol_version,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DaveState {
    pub protocol_version: Option<u16>,
    pub active_send_protocol_version: Option<u16>,
    pub active_receive_protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub epoch: Option<u64>,
    pub prepare_epoch_seq: u64,
    pub passthrough: bool,
    pub mls: DaveMlsState,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) enum DaveProtocolState {
    #[default]
    Unknown,
    Transport,
    Dave(u16),
}

impl DaveProtocolState {
    pub(crate) fn from_gateway(protocol_version: Option<u16>) -> Self {
        protocol_version.map_or(Self::Unknown, Self::from_prepared)
    }

    pub(crate) fn from_prepared(protocol_version: u16) -> Self {
        if protocol_version == 0 {
            Self::Transport
        } else {
            Self::Dave(protocol_version)
        }
    }

    pub(crate) fn gateway_version(self) -> Option<u16> {
        match self {
            Self::Unknown => None,
            Self::Transport => Some(0),
            Self::Dave(protocol_version) => Some(protocol_version),
        }
    }

    pub(crate) const fn is_dave(self) -> bool {
        matches!(self, Self::Dave(_))
    }

    pub(crate) const fn is_transport_or_unknown(self) -> bool {
        !self.is_dave()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct DaveActiveMediaState {
    send: DaveProtocolState,
    receive: DaveProtocolState,
}

impl DaveActiveMediaState {
    pub(crate) fn set_both(&mut self, protocol: DaveProtocolState) {
        self.send = protocol;
        self.receive = protocol;
    }

    pub(crate) fn send_protocol(self) -> Option<u16> {
        self.send.gateway_version()
    }

    pub(crate) fn receive_protocol(self) -> Option<u16> {
        self.receive.gateway_version()
    }

    pub(crate) const fn send_active(self) -> bool {
        self.send.is_dave()
    }

    pub(crate) const fn receive_active(self) -> bool {
        self.receive.is_dave()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) enum DaveGatewayPhase {
    #[default]
    Unknown,
    Session {
        protocol: DaveProtocolState,
    },
    PreparedTransition {
        transition_id: u16,
        protocol: DaveProtocolState,
    },
    PreparedEpoch {
        protocol: DaveProtocolState,
        epoch: u64,
        seq: u64,
        transition_id: Option<u16>,
    },
}

impl DaveGatewayPhase {
    pub(crate) fn protocol(self) -> DaveProtocolState {
        match self {
            Self::Unknown => DaveProtocolState::Unknown,
            Self::Session { protocol }
            | Self::PreparedTransition { protocol, .. }
            | Self::PreparedEpoch { protocol, .. } => protocol,
        }
    }

    pub(crate) fn protocol_version(self) -> Option<u16> {
        self.protocol().gateway_version()
    }

    pub(crate) fn transition_id(self) -> Option<u16> {
        match self {
            Self::PreparedTransition { transition_id, .. } => Some(transition_id),
            Self::PreparedEpoch { transition_id, .. } => transition_id,
            Self::Unknown | Self::Session { .. } => None,
        }
    }

    pub(crate) fn epoch(self) -> Option<u64> {
        match self {
            Self::PreparedEpoch { epoch, .. } => Some(epoch),
            Self::Unknown | Self::Session { .. } | Self::PreparedTransition { .. } => None,
        }
    }

    pub(crate) fn prepare_epoch_seq(self) -> u64 {
        match self {
            Self::PreparedEpoch { seq, .. } => seq,
            Self::Unknown | Self::Session { .. } | Self::PreparedTransition { .. } => 0,
        }
    }

    pub(crate) fn passthrough(self) -> bool {
        match self {
            Self::Unknown => false,
            Self::Session { protocol }
            | Self::PreparedTransition { protocol, .. }
            | Self::PreparedEpoch { protocol, .. } => protocol.is_transport_or_unknown(),
        }
    }

    fn with_transition_id(self, transition_id: u16) -> Self {
        match self {
            Self::PreparedEpoch {
                protocol,
                epoch,
                seq,
                ..
            } => Self::PreparedEpoch {
                protocol,
                epoch,
                seq,
                transition_id: Some(transition_id),
            },
            Self::Unknown | Self::Session { .. } | Self::PreparedTransition { .. } => {
                Self::PreparedTransition {
                    transition_id,
                    protocol: self.protocol(),
                }
            }
        }
    }

    fn without_transition(self, transition_id: u16) -> Self {
        if self.transition_id() != Some(transition_id) {
            return self;
        }
        match self {
            Self::PreparedEpoch {
                protocol,
                epoch,
                seq,
                ..
            } => Self::PreparedEpoch {
                protocol,
                epoch,
                seq,
                transition_id: None,
            },
            Self::PreparedTransition { protocol, .. } => Self::Session { protocol },
            Self::Unknown | Self::Session { .. } => self,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DaveMlsState {
    pub external_sender: bool,
    pub pending: DavePendingMlsState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DavePendingMlsState {
    pub proposals: usize,
    pub commit: bool,
    pub welcome: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
pub(crate) enum DaveMlsMessageKind {
    Commit,
    Welcome,
}

impl DaveMlsMessageKind {
    pub(crate) const fn operation_label(self) -> &'static str {
        match self {
            Self::Commit => "commit processing",
            Self::Welcome => "welcome processing",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
pub(crate) struct DaveMlsMessageIdentity {
    pub(crate) kind: DaveMlsMessageKind,
    pub(crate) seq: i64,
    pub(crate) transition_id: u16,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingDaveMlsMessage {
    pub(crate) identity: DaveMlsMessageIdentity,
    pub(crate) payload: Vec<u8>,
}

impl PendingDaveMlsMessage {
    pub(crate) fn new(identity: DaveMlsMessageIdentity, payload: Vec<u8>) -> Self {
        Self { identity, payload }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct DaveMlsSlots<T> {
    commit: Option<T>,
    welcome: Option<T>,
}

impl<T> Default for DaveMlsSlots<T> {
    fn default() -> Self {
        Self {
            commit: None,
            welcome: None,
        }
    }
}

impl<T> DaveMlsSlots<T> {
    pub(crate) const fn commit(&self) -> Option<&T> {
        self.commit.as_ref()
    }

    pub(crate) const fn welcome(&self) -> Option<&T> {
        self.welcome.as_ref()
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.commit.is_none() && self.welcome.is_none()
    }

    pub(crate) fn clear(&mut self) {
        self.commit = None;
        self.welcome = None;
    }

    pub(crate) fn get(&self, kind: DaveMlsMessageKind) -> Option<&T> {
        match kind {
            DaveMlsMessageKind::Commit => self.commit(),
            DaveMlsMessageKind::Welcome => self.welcome(),
        }
    }

    pub(crate) fn set(&mut self, kind: DaveMlsMessageKind, value: T) {
        match kind {
            DaveMlsMessageKind::Commit => self.commit = Some(value),
            DaveMlsMessageKind::Welcome => self.welcome = Some(value),
        }
    }

    pub(crate) fn welcome_then_commit(&self) -> impl Iterator<Item = &T> {
        [self.welcome(), self.commit()].into_iter().flatten()
    }
}

impl DaveMlsSlots<PendingDaveMlsMessage> {
    pub(crate) fn set_message(&mut self, message: PendingDaveMlsMessage) {
        self.set(message.identity.kind, message);
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct DaveInternalState {
    #[serde(default)]
    pub(crate) phase: DaveGatewayPhase,
    #[serde(default)]
    pub(crate) active: DaveActiveMediaState,
    #[serde(default)]
    pub(crate) external_sender: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) proposals: Vec<Vec<u8>>,
    #[serde(default)]
    pub(crate) pending_mls: DaveMlsSlots<PendingDaveMlsMessage>,
}

impl DaveInternalState {
    pub(crate) fn mls_state(&self) -> DaveMlsState {
        DaveMlsState {
            external_sender: self.external_sender.is_some(),
            pending: DavePendingMlsState {
                proposals: self.proposals.len(),
                commit: self.pending_mls.commit().is_some(),
                welcome: self.pending_mls.welcome().is_some(),
            },
        }
    }

    pub(crate) fn public_state(&self) -> DaveState {
        DaveState {
            protocol_version: self.protocol_version(),
            active_send_protocol_version: self.active_send_protocol_version(),
            active_receive_protocol_version: self.active_receive_protocol_version(),
            transition_id: self.transition_id(),
            epoch: self.epoch(),
            prepare_epoch_seq: self.prepare_epoch_seq(),
            passthrough: self.passthrough(),
            mls: self.mls_state(),
        }
    }

    pub(crate) fn protocol_version(&self) -> Option<u16> {
        self.phase.protocol_version()
    }

    pub(crate) fn active_send_protocol_version(&self) -> Option<u16> {
        self.active.send_protocol()
    }

    pub(crate) fn active_receive_protocol_version(&self) -> Option<u16> {
        self.active.receive_protocol()
    }

    pub(crate) fn transition_id(&self) -> Option<u16> {
        self.phase.transition_id()
    }

    pub(crate) fn epoch(&self) -> Option<u64> {
        self.phase.epoch()
    }

    pub(crate) fn prepare_epoch_seq(&self) -> u64 {
        self.phase.prepare_epoch_seq()
    }

    pub(crate) fn passthrough(&self) -> bool {
        self.phase.passthrough()
    }

    pub(crate) fn set_session_protocol(&mut self, protocol_version: Option<u16>) {
        let protocol = DaveProtocolState::from_gateway(protocol_version);
        if self.phase.protocol() != protocol {
            self.clear_pending_mls();
        }
        self.phase = DaveGatewayPhase::Session { protocol };
        if protocol.is_transport_or_unknown() {
            self.active.set_both(protocol);
        }
    }

    pub(crate) fn prepare_transition(&mut self, transition_id: u16, protocol_version: u16) {
        if self.transition_id() != Some(transition_id) {
            self.clear_pending_mls();
        }
        let protocol = DaveProtocolState::from_prepared(protocol_version);
        self.phase = match self.phase {
            DaveGatewayPhase::PreparedEpoch { epoch, seq, .. } => DaveGatewayPhase::PreparedEpoch {
                protocol,
                epoch,
                seq,
                transition_id: Some(transition_id),
            },
            DaveGatewayPhase::Unknown
            | DaveGatewayPhase::Session { .. }
            | DaveGatewayPhase::PreparedTransition { .. } => DaveGatewayPhase::PreparedTransition {
                transition_id,
                protocol,
            },
        };
        if self.epoch() == Some(1) && transition_id == 0 && protocol.is_dave() {
            self.execute_transition(transition_id);
        }
    }

    pub(crate) fn prepare_epoch(&mut self, protocol_version: u16, epoch: u64) {
        let seq = self.prepare_epoch_seq().saturating_add(1);
        if epoch == 1 || self.epoch() != Some(epoch) {
            self.clear_pending_mls();
        }
        self.phase = DaveGatewayPhase::PreparedEpoch {
            protocol: DaveProtocolState::from_prepared(protocol_version),
            epoch,
            seq,
            transition_id: self.transition_id(),
        };
    }

    pub(crate) fn execute_transition(&mut self, transition_id: u16) {
        if self.transition_id() == Some(transition_id) {
            self.active.set_both(self.phase.protocol());
            self.phase = self.phase.without_transition(transition_id);
        }
        self.clear_pending_mls();
    }

    pub(crate) fn set_pending_mls_message(&mut self, message: PendingDaveMlsMessage) {
        if self.transition_id() != Some(message.identity.transition_id) {
            self.clear_pending_mls();
        }
        self.phase = self
            .phase
            .with_transition_id(message.identity.transition_id);
        self.pending_mls.set_message(message);
    }

    pub(crate) fn clear_pending_mls(&mut self) {
        self.proposals.clear();
        self.pending_mls.clear();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionState {
    pub connection: ConnectionInfo,
    pub heartbeat_interval_ms: u64,
    pub local_ssrc: u32,
    pub selected_mode: EncryptionMode,
    pub session: Option<SessionState>,
    pub connected_user_ids: Arc<HashSet<u64>>,
    pub ssrc_users: Arc<HashMap<u32, u64>>,
    pub speaking: Arc<HashMap<u32, SpeakingUpdate>>,
    pub dave: DaveState,
    pub resumed: bool,
}

pub type ConnectionStateSnapshot = Arc<ConnectionState>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionInternalState {
    pub(crate) config: ConnectionRuntimeConfig,
    pub(crate) heartbeat_interval_ms: u64,
    pub(crate) last_seq: Option<i64>,
    pub(crate) ready: GatewayReady,
    pub(crate) discovery: UdpDiscoveryPacket,
    pub(crate) selected_mode: EncryptionMode,
    pub(crate) session_description: Option<SessionDescription>,
    pub(crate) rtp_codecs: Option<DiscordRtpCodecMap>,
    pub(crate) connected_user_ids: Arc<HashSet<u64>>,
    pub(crate) ssrc_users: Arc<HashMap<u32, u64>>,
    pub(crate) speaking: Arc<HashMap<u32, SpeakingUpdate>>,
    pub(crate) dave: DaveInternalState,
    pub(crate) roster_authoritative: bool,
    pub(crate) resumed: bool,
}

impl ConnectionInternalState {
    pub(crate) fn connected_user_ids_mut(&mut self) -> &mut HashSet<u64> {
        Arc::make_mut(&mut self.connected_user_ids)
    }

    pub(crate) fn ssrc_users_mut(&mut self) -> &mut HashMap<u32, u64> {
        Arc::make_mut(&mut self.ssrc_users)
    }

    pub(crate) fn speaking_mut(&mut self) -> &mut HashMap<u32, SpeakingUpdate> {
        Arc::make_mut(&mut self.speaking)
    }

    pub(crate) fn public_state(&self) -> ConnectionState {
        ConnectionState {
            connection: self.config.public_info(),
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            local_ssrc: self.ready.ssrc,
            selected_mode: self.selected_mode,
            session: self.session_description.as_ref().map(SessionState::from),
            connected_user_ids: self.connected_user_ids.clone(),
            ssrc_users: self.ssrc_users.clone(),
            speaking: self.speaking.clone(),
            dave: self.dave.public_state(),
            resumed: self.resumed,
        }
    }
}

pub(crate) struct ReceiveState<Raw>
where
    Raw: FrameRaw,
{
    tuning: ConnectionRuntimeTuning,
    pub(crate) pending_dave_media: PendingDaveMediaQueues<Raw>,
    pub(crate) ssrc: HashMap<u32, ReceiveSsrcState<Raw>>,
    ready_ssrcs: VecDeque<u32>,
    queued_ready_ssrcs: HashSet<u32>,
    rtp_reorder_deadlines: DeadlineSet<u32>,
}

impl<Raw> Default for ReceiveState<Raw>
where
    Raw: FrameRaw,
{
    fn default() -> Self {
        Self::new(ConnectionRuntimeTuning::default())
    }
}

impl<Raw> ReceiveState<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn new(tuning: ConnectionRuntimeTuning) -> Self {
        Self {
            tuning,
            pending_dave_media: PendingDaveMediaQueues::new(tuning.dave_pending_media_ttl),
            ssrc: HashMap::new(),
            ready_ssrcs: VecDeque::new(),
            queued_ready_ssrcs: HashSet::new(),
            rtp_reorder_deadlines: DeadlineSet::default(),
        }
    }

    pub(crate) fn pending_dave_media_deadline(&self) -> Option<Instant> {
        self.pending_dave_media.deadline()
    }

    pub(crate) fn pending_rtp_reorder_deadline(&self) -> Option<Instant> {
        self.rtp_reorder_deadlines.next_deadline()
    }

    pub(crate) fn prune_ssrcs(&mut self, removed_ssrcs: &HashSet<u32>) {
        if removed_ssrcs.is_empty() {
            return;
        }
        self.ssrc.retain(|ssrc, _| !removed_ssrcs.contains(ssrc));
        self.queued_ready_ssrcs
            .retain(|ssrc| !removed_ssrcs.contains(ssrc));
        self.ready_ssrcs
            .retain(|ssrc| !removed_ssrcs.contains(ssrc));
        for ssrc in removed_ssrcs {
            self.rtp_reorder_deadlines.remove(ssrc);
        }
        self.pending_dave_media.prune_ssrcs(removed_ssrcs);
    }

    pub(crate) fn push_media_packet<O>(
        &mut self,
        observer: &O,
        packet: PendingMediaPacket<Raw>,
    ) -> Result<Option<PendingMediaFrame<Raw>>>
    where
        O: ConnectionObserver,
    {
        let now = Instant::now();
        let ssrc = packet.rtp.ssrc;
        let frame = self
            .ssrc
            .entry(packet.rtp.ssrc)
            .or_insert_with(|| ReceiveSsrcState::new(self.tuning))
            .push_media_packet(observer, packet, now);
        self.refresh_ssrc_schedules(ssrc);
        frame
    }

    pub(crate) fn drain_ordered_media<O>(
        &mut self,
        observer: &O,
    ) -> Option<Result<PendingMediaFrame<Raw>>>
    where
        O: ConnectionObserver,
    {
        let now = Instant::now();
        loop {
            if let Some(ssrc) = self.pop_ready_buffered_ssrc() {
                let Some(state) = self.ssrc.get_mut(&ssrc) else {
                    continue;
                };
                match state.pop_ready_buffered_frame() {
                    Ok(Some(frame)) => {
                        self.refresh_ssrc_schedules(ssrc);
                        return Some(Ok(frame));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.refresh_ssrc_schedules(ssrc);
                        return Some(Err(error));
                    }
                }
                self.refresh_ssrc_schedules(ssrc);
                continue;
            }
            if let Some(ssrc) = self.expired_missing_ssrc(now) {
                if let Some(state) = self.ssrc.get_mut(&ssrc) {
                    state.expire_missing_head(observer, ssrc, now, false);
                }
                self.refresh_ssrc_schedules(ssrc);
                continue;
            }
            return None;
        }
    }

    fn pop_ready_buffered_ssrc(&mut self) -> Option<u32> {
        while let Some(ssrc) = self.ready_ssrcs.pop_front() {
            self.queued_ready_ssrcs.remove(&ssrc);
            if self
                .ssrc
                .get(&ssrc)
                .is_some_and(ReceiveSsrcState::has_ready_buffered_media)
            {
                return Some(ssrc);
            }
        }
        None
    }

    fn expired_missing_ssrc(&mut self, now: Instant) -> Option<u32> {
        while let Some(ssrc) = self.rtp_reorder_deadlines.pop_expired(now) {
            if self
                .ssrc
                .get(&ssrc)
                .and_then(ReceiveSsrcState::pending_reorder_deadline)
                .is_some_and(|deadline| deadline <= now)
            {
                return Some(ssrc);
            }
        }
        None
    }

    pub(crate) fn refresh_ssrc_schedules(&mut self, ssrc: u32) {
        let Some(state) = self.ssrc.get(&ssrc) else {
            return;
        };
        if state.has_ready_buffered_media() && self.queued_ready_ssrcs.insert(ssrc) {
            self.ready_ssrcs.push_back(ssrc);
        }
        if let Some(deadline) = state.pending_reorder_deadline() {
            self.rtp_reorder_deadlines.insert(ssrc, deadline);
        } else {
            self.rtp_reorder_deadlines.remove(&ssrc);
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum DavePendingMediaBucket {
    MissingUser,
    SessionNotReady,
    GatewayPending,
    DecryptStatePending,
}

impl DavePendingMediaBucket {
    const ALL: [Self; 4] = [
        Self::MissingUser,
        Self::SessionNotReady,
        Self::GatewayPending,
        Self::DecryptStatePending,
    ];
    const COUNT: usize = Self::ALL.len();

    const fn bucket_index(self) -> usize {
        match self {
            Self::MissingUser => 0,
            Self::SessionNotReady => 1,
            Self::GatewayPending => 2,
            Self::DecryptStatePending => 3,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::MissingUser => 1 << 0,
            Self::SessionNotReady => 1 << 1,
            Self::GatewayPending => 1 << 2,
            Self::DecryptStatePending => 1 << 3,
        }
    }

    pub(crate) fn from_reason(reason: DavePendingMediaReason) -> Option<Self> {
        match reason {
            DavePendingMediaReason::MissingUser => Some(Self::MissingUser),
            DavePendingMediaReason::SessionNotReady => Some(Self::SessionNotReady),
            DavePendingMediaReason::GatewayPending => Some(Self::GatewayPending),
            DavePendingMediaReason::DecryptStatePending
            | DavePendingMediaReason::NoValidCryptorPending => Some(Self::DecryptStatePending),
            DavePendingMediaReason::StableDecryptFailure | DavePendingMediaReason::Expired => None,
        }
    }
}

impl QueueBucket for DavePendingMediaBucket {
    fn index(self) -> usize {
        self.bucket_index()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DavePendingMediaRetry {
    bits: u8,
}

impl DavePendingMediaRetry {
    pub(crate) const fn dave_state() -> Self {
        Self {
            bits: DavePendingMediaBucket::SessionNotReady.bit()
                | DavePendingMediaBucket::GatewayPending.bit()
                | DavePendingMediaBucket::DecryptStatePending.bit(),
        }
    }

    pub(crate) const fn missing_user() -> Self {
        Self {
            bits: DavePendingMediaBucket::MissingUser.bit(),
        }
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.bits == 0
    }

    pub(crate) fn include(&mut self, retry: Self) {
        self.bits |= retry.bits;
    }

    pub(crate) fn includes(self, bucket: DavePendingMediaBucket) -> bool {
        self.bits & bucket.bit() != 0
    }
}

pub(crate) struct PendingDaveMediaQueues<Raw>
where
    Raw: FrameRaw,
{
    ttl: Duration,
    buckets: BucketDeadlineQueue<
        DavePendingMediaBucket,
        PendingMediaFrame<Raw>,
        { DavePendingMediaBucket::COUNT },
    >,
}

impl<Raw> Default for PendingDaveMediaQueues<Raw>
where
    Raw: FrameRaw,
{
    fn default() -> Self {
        Self::new(ConnectionRuntimeTuning::default().dave_pending_media_ttl)
    }
}

impl<Raw> PendingDaveMediaQueues<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            buckets: BucketDeadlineQueue::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.buckets.len()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &PendingMediaFrame<Raw>> {
        self.buckets.iter()
    }

    pub(crate) fn push(&mut self, media: PendingMediaFrame<Raw>) -> usize {
        let bucket = DavePendingMediaBucket::from_reason(media.reason)
            .expect("queued DAVE media must have a retryable reason");
        let deadline = media.enqueued_at + self.ttl;
        self.buckets.push(bucket, media, deadline);
        self.len()
    }

    pub(crate) fn pop_retry(
        &mut self,
        retry: DavePendingMediaRetry,
    ) -> Option<PendingMediaFrame<Raw>> {
        self.buckets.pop_matching(|bucket| retry.includes(*bucket))
    }

    pub(crate) fn pop_expired(&mut self, now: Instant) -> Option<PendingMediaFrame<Raw>> {
        self.buckets.pop_expired(now)
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.buckets.next_deadline()
    }

    pub(crate) fn prune_ssrcs(&mut self, removed_ssrcs: &HashSet<u32>) {
        for bucket in DavePendingMediaBucket::ALL {
            self.buckets
                .retain(bucket, |media| !removed_ssrcs.contains(&media.rtp.ssrc));
        }
    }
}

pub(crate) struct ReceiveSsrcState<Raw>
where
    Raw: FrameRaw,
{
    tuning: ConnectionRuntimeTuning,
    pub(crate) last_arrival: Option<Instant>,
    pub(crate) next_seq: Option<u16>,
    pub(crate) missing: BTreeMap<u16, MissingRtpPacket>,
    pub(crate) pending_media: BTreeMap<u16, PendingMediaPacket<Raw>>,
    pub(crate) interarrival: SlidingStats<u64>,
    pub(crate) assembler: RtpFrameAssembler<Raw>,
}

impl<Raw> Default for ReceiveSsrcState<Raw>
where
    Raw: FrameRaw,
{
    fn default() -> Self {
        Self::new(ConnectionRuntimeTuning::default())
    }
}

impl<Raw> ReceiveSsrcState<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn new(tuning: ConnectionRuntimeTuning) -> Self {
        Self {
            tuning,
            last_arrival: None,
            next_seq: None,
            missing: BTreeMap::new(),
            pending_media: BTreeMap::new(),
            interarrival: SlidingStats::new(tuning.receive_interarrival_window.get()),
            assembler: RtpFrameAssembler::default(),
        }
    }

    fn push_media_packet<O>(
        &mut self,
        observer: &O,
        packet: PendingMediaPacket<Raw>,
        now: Instant,
    ) -> Result<Option<PendingMediaFrame<Raw>>>
    where
        O: ConnectionObserver,
    {
        self.record_arrival(observer, &packet, now);
        let ssrc = packet.rtp.ssrc;
        let seq = packet.rtp.seq;
        let Some(expected) = self.next_seq else {
            self.next_seq = Some(seq.wrapping_add(1));
            return self.assembler.push_packet(packet);
        };
        if seq == expected {
            self.missing.remove(&seq);
            self.pending_media.remove(&seq);
            self.next_seq = Some(seq.wrapping_add(1));
            return self.assembler.push_packet(packet);
        }

        let forward = seq.wrapping_sub(expected);
        if forward < 0x8000 {
            if usize::from(forward) > self.tuning.rtp_reorder_buffer_max_frames.get() {
                self.emit_packet_loss(
                    observer,
                    ReceiveRtpPacketLossEvent {
                        ssrc,
                        user_id: packet.user_id,
                        first_seq: expected,
                        last_seq: seq.wrapping_sub(1),
                        missing_packets: forward,
                        age_ms: 0,
                    },
                );
                self.missing.clear();
                self.pending_media.clear();
                self.assembler.clear();
                self.next_seq = Some(seq.wrapping_add(1));
                return self.assembler.push_packet(packet);
            }

            self.mark_missing(expected, forward, packet.user_id, now);
            self.pending_media.entry(seq).or_insert(packet);
            if self.pending_media.len() > self.tuning.rtp_reorder_buffer_max_frames.get() {
                self.expire_missing_head(observer, ssrc, now, true);
            }
            return self.pop_ready_buffered_frame();
        }

        Ok(None)
    }

    fn record_arrival<O>(&mut self, observer: &O, packet: &PendingMediaPacket<Raw>, now: Instant)
    where
        O: ConnectionObserver,
    {
        if !O::ENABLE_RECEIVE_TELEMETRY {
            return;
        }
        let interarrival = self.last_arrival.map(|last| now.duration_since(last));
        let interarrival_us = interarrival.map(duration_us);
        if let Some(interarrival_us) = interarrival_us {
            self.record_interarrival(interarrival_us);
        }
        self.last_arrival = Some(now);
        observer.receive_rtp_packet(ReceiveRtpPacketEvent {
            ssrc: packet.rtp.ssrc,
            user_id: packet.user_id,
            seq: packet.rtp.seq,
            timestamp: packet.rtp.timestamp,
            payload_bytes: packet.encrypted_payload.len(),
            interarrival_us,
            interarrival_p95_us: self.interarrival_p95_us(),
            interarrival_max_us: self.interarrival_max_us(),
        });
    }

    fn mark_missing(
        &mut self,
        expected: u16,
        forward: u16,
        user_id: Option<u64>,
        detected_at: Instant,
    ) {
        for offset in 0..forward {
            self.missing
                .entry(expected.wrapping_add(offset))
                .or_insert(MissingRtpPacket {
                    user_id,
                    detected_at,
                });
        }
    }

    fn has_ready_buffered_media(&self) -> bool {
        self.assembler.has_completed_frame()
            || self
                .next_seq
                .is_some_and(|seq| self.pending_media.contains_key(&seq))
    }

    fn pop_ready_buffered_frame(&mut self) -> Result<Option<PendingMediaFrame<Raw>>> {
        if let Some(frame) = self.assembler.pop_completed() {
            return Ok(Some(frame));
        }
        let Some(seq) = self.next_seq else {
            return Ok(None);
        };
        let Some(packet) = self.pending_media.remove(&seq) else {
            return Ok(None);
        };
        self.missing.remove(&seq);
        self.next_seq = Some(seq.wrapping_add(1));
        self.assembler.push_packet(packet)
    }

    fn pending_reorder_deadline(&self) -> Option<Instant> {
        let seq = self.next_seq?;
        self.missing
            .get(&seq)
            .map(|missing| missing.detected_at + self.tuning.rtp_reorder_ttl)
    }

    fn expire_missing_head<O>(&mut self, observer: &O, ssrc: u32, now: Instant, force: bool) -> bool
    where
        O: ConnectionObserver,
    {
        let Some(mut seq) = self.next_seq else {
            return false;
        };
        let Some(first_missing) = self.missing.get(&seq) else {
            return false;
        };
        if !force && now < first_missing.detected_at + self.tuning.rtp_reorder_ttl {
            return false;
        }

        let first_seq = seq;
        let mut last_seq = seq;
        let mut missing_packets = 0_u16;
        let mut user_id = first_missing.user_id;
        let detected_at = first_missing.detected_at;
        while let Some(missing) = self.missing.get(&seq) {
            if !force && now < missing.detected_at + self.tuning.rtp_reorder_ttl {
                break;
            }
            user_id = user_id.or(missing.user_id);
            self.missing.remove(&seq);
            last_seq = seq;
            missing_packets = missing_packets.saturating_add(1);
            seq = seq.wrapping_add(1);
        }
        if missing_packets == 0 {
            return false;
        }
        self.assembler.clear();
        self.next_seq = Some(seq);
        self.emit_packet_loss(
            observer,
            ReceiveRtpPacketLossEvent {
                ssrc,
                user_id,
                first_seq,
                last_seq,
                missing_packets,
                age_ms: duration_ms(now.duration_since(detected_at)),
            },
        );
        true
    }

    fn emit_packet_loss<O>(&self, observer: &O, event: ReceiveRtpPacketLossEvent)
    where
        O: ConnectionObserver,
    {
        if O::ENABLE_RECEIVE_TELEMETRY {
            observer.receive_rtp_packet_loss(event);
        }
    }
    pub(crate) fn record_interarrival(&mut self, interarrival_us: u64) {
        self.interarrival.observe(interarrival_us);
    }

    pub(crate) fn interarrival_p95_us(&self) -> Option<u64> {
        self.interarrival.percentile(95)
    }

    pub(crate) fn interarrival_max_us(&self) -> Option<u64> {
        self.interarrival.max()
    }
}

pub(crate) struct MissingRtpPacket {
    pub(crate) user_id: Option<u64>,
    pub(crate) detected_at: Instant,
}

pub(crate) struct PendingMediaPacket<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) raw: Raw::Packet,
    pub(crate) rtp: RtpHeader,
    pub(crate) user_id: Option<u64>,
    pub(crate) codec: Codec,
    pub(crate) encrypted_payload: Vec<u8>,
    pub(crate) dave: bool,
}

pub(crate) struct PendingMediaFrame<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) raw: Raw,
    pub(crate) rtp: RtpHeader,
    pub(crate) user_id: Option<u64>,
    pub(crate) codec: Codec,
    pub(crate) encrypted_frame: Vec<u8>,
    pub(crate) dave: bool,
    pub(crate) enqueued_at: Instant,
    pub(crate) reason: DavePendingMediaReason,
    pub(crate) was_pending: bool,
}

impl<Raw> PendingMediaFrame<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn event(
        &self,
        pending_packets: usize,
        reason: DavePendingMediaReason,
    ) -> DavePendingMediaEvent {
        DavePendingMediaEvent {
            reason,
            ssrc: self.rtp.ssrc,
            user_id: self.user_id,
            seq: self.rtp.seq,
            pending_packets,
            age_ms: duration_ms(self.enqueued_at.elapsed()),
        }
    }
}
