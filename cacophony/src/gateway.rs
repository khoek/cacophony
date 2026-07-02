use std::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
    time::Duration,
};

use futures_util::StreamExt;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};
use serde_json::Value;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::{
    GatewayWebSocketRead,
    codecs::{self, DiscordRtpCodecMap},
    connection::ConnectionStateStore,
    errors::{DaveError, DaveGatewayPayloadError, Error, ProtocolError, Result},
    media::TransportCryptoConfig,
    observer::{ClientsConnectedEvent, ConnectionObserver},
    rtp::RtpPayloadType,
    state::{
        ConnectionCodecPreferences, DaveMlsMessageIdentity, DaveMlsMessageKind,
        DavePendingMediaRetry, EncryptionMode, OfferedEncryptionMode, PendingDaveMlsMessage,
        SessionDescription, ValidatedConnectionConfig, ValidatedConnectionOptions,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Opcode {
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
    SessionUpdate = 14,
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

impl Opcode {
    pub(crate) const ALL: [Self; 25] = [
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
        Self::SessionUpdate,
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

    pub(crate) const fn code(self) -> u64 {
        self as u8 as u64
    }

    pub(crate) const fn byte(self) -> u8 {
        self as u8
    }

    pub(crate) const fn dave_mls_message_kind(self) -> Option<DaveMlsMessageKind> {
        match self {
            Self::DaveMlsAnnounceCommitTransition => Some(DaveMlsMessageKind::Commit),
            Self::DaveMlsWelcome => Some(DaveMlsMessageKind::Welcome),
            _ => None,
        }
    }

    pub(crate) fn from_code(code: u64) -> Option<Self> {
        let byte = u8::try_from(code).ok()?;
        Self::from_byte(byte)
    }

    pub(crate) fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|opcode| opcode.byte() == byte)
    }

    pub(crate) fn from_server_binary(byte: u8) -> Option<Self> {
        Self::from_byte(byte).filter(|opcode| opcode.is_server_binary())
    }

    pub(crate) const fn is_server_binary(self) -> bool {
        matches!(
            self,
            Self::DaveMlsExternalSender
                | Self::DaveMlsProposals
                | Self::DaveMlsAnnounceCommitTransition
                | Self::DaveMlsWelcome
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SpeakingFlags(u8);

impl SpeakingFlags {
    pub const NONE: Self = Self(0);
    /// Normal transmission of voice audio.
    pub const MICROPHONE: Self = Self(1 << 0);
    /// Context audio for video without a speaking indicator.
    pub const SOUNDSHARE: Self = Self(1 << 1);
    /// Priority speaker audio.
    pub const PRIORITY: Self = Self(1 << 2);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for SpeakingFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for SpeakingFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for SpeakingFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for SpeakingFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

#[derive(Clone, Debug)]
pub(crate) enum GatewayCommand {
    SelectProtocol(SelectProtocolCommand),
    Speaking(SpeakingCommand),
    Heartbeat(HeartbeatCommand),
    DaveProtocolTransitionReady(DaveTransitionReadyCommand),
    DaveMlsKeyPackage {
        key_package: Vec<u8>,
    },
    DaveMlsCommitWelcome {
        commit: Vec<u8>,
        welcome: Option<Vec<u8>>,
    },
    DaveMlsInvalidCommitWelcome(DaveInvalidCommitWelcomeCommand),
}

impl GatewayCommand {
    pub(crate) fn opcode(&self) -> Opcode {
        match self {
            Self::SelectProtocol(_) => Opcode::SelectProtocol,
            Self::Speaking(_) => Opcode::Speaking,
            Self::Heartbeat(_) => Opcode::Heartbeat,
            Self::DaveProtocolTransitionReady(_) => Opcode::DaveTransitionReady,
            Self::DaveMlsKeyPackage { .. } => Opcode::DaveMlsKeyPackage,
            Self::DaveMlsCommitWelcome { .. } => Opcode::DaveMlsCommitWelcome,
            Self::DaveMlsInvalidCommitWelcome(_) => Opcode::DaveMlsInvalidCommitWelcome,
        }
    }

    pub(crate) fn text_payload(&self) -> Result<String> {
        match self {
            Self::SelectProtocol(data) => serialize_payload(self.opcode(), data),
            Self::Speaking(data) => serialize_payload(self.opcode(), data),
            Self::Heartbeat(data) => serialize_payload(self.opcode(), data),
            Self::DaveProtocolTransitionReady(data) => serialize_payload(self.opcode(), data),
            Self::DaveMlsInvalidCommitWelcome(data) => serialize_payload(self.opcode(), data),
            Self::DaveMlsKeyPackage { .. } | Self::DaveMlsCommitWelcome { .. } => Err(
                Error::Protocol(ProtocolError::TextPayloadRequiresBinaryDaveMlsCommand),
            ),
        }
    }

    pub(crate) fn binary_payload(&self) -> Option<Vec<u8>> {
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

#[derive(Clone, Debug, Serialize)]
pub(crate) struct GatewayPayload<'a, T: ?Sized> {
    op: u64,
    d: &'a T,
}

pub(crate) fn serialize_payload<T>(opcode: Opcode, data: &T) -> Result<String>
where
    T: Serialize + ?Sized,
{
    Ok(serde_json::to_string(&GatewayPayload {
        op: opcode.code(),
        d: data,
    })?)
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentifyCommand<'a> {
    server_id: String,
    user_id: String,
    session_id: &'a str,
    token: &'a str,
    #[serde(skip_serializing_if = "is_false")]
    video: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    streams: Vec<IdentifyStream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_dave_protocol_version: Option<u16>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentifyStream {
    #[serde(rename = "type")]
    kind: &'static str,
    rid: &'static str,
    quality: u8,
    active: bool,
}

const PRIMARY_VIDEO_RID: &str = "100";
const PRIMARY_VIDEO_QUALITY: u8 = 100;
const OPUS_SELECT_PROTOCOL_PRIORITY: u32 = 1_000;
const VIDEO_SELECT_PROTOCOL_PRIORITY_BASE: u32 = 2_000;
const SELECT_PROTOCOL_PRIORITY_STEP: u32 = 1_000;

impl<'a> IdentifyCommand<'a> {
    pub(crate) fn from_config(config: &'a ValidatedConnectionConfig) -> Self {
        let video = config.options.codec_preferences.video_enabled();
        Self {
            server_id: config.identity.guild_id.to_string(),
            user_id: config.identity.user_id.to_string(),
            session_id: config.secrets.session_id.as_str(),
            token: config.secrets.token.as_str(),
            video,
            streams: if video {
                vec![IdentifyStream {
                    kind: "video",
                    rid: PRIMARY_VIDEO_RID,
                    quality: PRIMARY_VIDEO_QUALITY,
                    active: true,
                }]
            } else {
                Vec::new()
            },
            max_dave_protocol_version: config.options.max_dave_protocol_version,
        }
    }
}

pub(crate) fn identify_payload(config: &ValidatedConnectionConfig) -> Result<String> {
    serialize_payload(Opcode::Identify, &IdentifyCommand::from_config(config))
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SelectProtocolCommand {
    protocol: &'static str,
    pub(crate) data: SelectProtocolData,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    codecs: Vec<SelectProtocolCodec>,
}

impl SelectProtocolCommand {
    pub(crate) fn udp(
        address: String,
        port: u16,
        mode: EncryptionMode,
        codec_preferences: &ConnectionCodecPreferences,
    ) -> Self {
        Self {
            protocol: "udp",
            data: SelectProtocolData {
                address,
                port,
                mode,
            },
            codecs: select_protocol_codecs(codec_preferences),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SelectProtocolData {
    address: String,
    port: u16,
    mode: EncryptionMode,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SelectProtocolCodec {
    name: &'static str,
    #[serde(rename = "type")]
    media_type: &'static str,
    priority: u32,
    payload_type: RtpPayloadType,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtx_payload_type: Option<RtpPayloadType>,
    encode: bool,
    decode: bool,
}

impl SelectProtocolCodec {
    fn from_codec(codec: dave::Codec, priority: u32) -> Self {
        let descriptor = codecs::descriptor(codec);
        Self {
            name: descriptor.wire_name,
            media_type: codec.media_type().as_str(),
            priority,
            payload_type: descriptor.payload_type,
            rtx_payload_type: descriptor.rtx_payload_type,
            encode: true,
            decode: true,
        }
    }
}

fn select_protocol_codecs(
    codec_preferences: &ConnectionCodecPreferences,
) -> Vec<SelectProtocolCodec> {
    if !codec_preferences.video_enabled() {
        return Vec::new();
    }

    std::iter::once(SelectProtocolCodec::from_codec(
        dave::Codec::Opus,
        OPUS_SELECT_PROTOCOL_PRIORITY,
    ))
    .chain(
        codec_preferences
            .video_codecs()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, codec)| {
                SelectProtocolCodec::from_codec(
                    codec,
                    VIDEO_SELECT_PROTOCOL_PRIORITY_BASE
                        + u32::try_from(index).expect("codec preference count fits u32")
                            * SELECT_PROTOCOL_PRIORITY_STEP,
                )
            }),
    )
    .collect()
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SpeakingUpdate {
    pub speaking: u64,
    pub ssrc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<DiscordId>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SpeakingCommand {
    pub(crate) speaking: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) delay: Option<u32>,
    pub(crate) ssrc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_id: Option<DiscordId>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct HeartbeatCommand {
    pub(crate) t: u64,
    pub(crate) seq_ack: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DaveTransitionReadyCommand {
    pub(crate) transition_id: u16,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DaveInvalidCommitWelcomeCommand {
    pub(crate) transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GatewayEvent {
    op: u64,
    #[serde(default)]
    seq: Option<i64>,
    #[serde(default)]
    d: Option<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedVoiceGatewayEvent {
    pub(crate) opcode: u64,
    pub(crate) seq: Option<i64>,
    pub(crate) data: Value,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct HelloData {
    heartbeat_interval: f64,
}

impl HelloData {
    pub(crate) fn heartbeat_interval_ms(&self) -> u64 {
        self.heartbeat_interval.max(1.0).ceil() as u64
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DavePrepareTransitionEvent {
    protocol_version: u16,
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SessionUpdateEvent {
    #[serde(default)]
    audio_codec: Option<String>,
    #[serde(default)]
    video_codec: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DaveExecuteTransitionEvent {
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DavePrepareEpochEvent {
    protocol_version: u16,
    epoch: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ClientsConnectEvent {
    #[serde(default)]
    user_ids: Vec<DiscordId>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ClientConnectEvent {
    user_id: DiscordId,
    #[serde(default)]
    audio_ssrc: Option<u32>,
    #[serde(default)]
    ssrc: Option<u32>,
}

impl ClientConnectEvent {
    pub(crate) fn ssrc(&self) -> Option<u32> {
        self.audio_ssrc.or(self.ssrc)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ClientDisconnectEvent {
    user_id: DiscordId,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GatewayReady {
    pub ssrc: u32,
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub modes: Vec<OfferedEncryptionMode>,
    #[serde(default)]
    pub heartbeat_interval: Option<u64>,
    #[serde(default)]
    pub streams: Vec<GatewayReadyStream>,
}

impl GatewayReady {
    pub(crate) fn select_encryption_mode(
        &self,
        options: &ValidatedConnectionOptions,
    ) -> Result<EncryptionMode> {
        if self.modes.is_empty() {
            return Err(Error::Protocol(ProtocolError::ReadyMissingEncryptionModes));
        }

        if let Some(required_mode) = options.required_mode {
            if self.offers_mode(required_mode) {
                return Ok(required_mode);
            }
            return Err(Error::Protocol(
                ProtocolError::RequiredEncryptionModeUnavailable {
                    required_mode,
                    modes: self.modes.clone(),
                },
            ));
        }

        for mode in EncryptionMode::ALL {
            if self.offers_mode(mode) {
                return Ok(mode);
            }
        }

        Err(Error::Protocol(
            ProtocolError::ReadyMissingSupportedEncryptionMode {
                modes: self.modes.clone(),
            },
        ))
    }

    pub(crate) fn primary_video_stream(&self) -> Option<GatewayReadyVideoStream> {
        self.streams
            .iter()
            .filter(|stream| stream.is_active_video())
            .max_by_key(|stream| {
                (
                    stream.rid.as_deref() == Some(PRIMARY_VIDEO_RID),
                    stream.quality == Some(PRIMARY_VIDEO_QUALITY),
                    stream.quality.unwrap_or_default(),
                )
            })
            .or_else(|| {
                (self.streams.len() == 1 && self.streams[0].active != Some(false))
                    .then(|| &self.streams[0])
            })
            .map(|stream| GatewayReadyVideoStream {
                ssrc: stream.ssrc,
                rtx_ssrc: stream.rtx_ssrc,
            })
    }

    fn offers_mode(&self, mode: EncryptionMode) -> bool {
        self.modes
            .iter()
            .any(|offered| offered.supported() == Some(mode))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GatewayReadyVideoStream {
    pub(crate) ssrc: u32,
    pub(crate) rtx_ssrc: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GatewayReadyStream {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub rid: Option<String>,
    pub ssrc: u32,
    #[serde(default)]
    pub rtx_ssrc: Option<u32>,
    #[serde(default)]
    pub quality: Option<u8>,
    #[serde(default)]
    pub active: Option<bool>,
}

impl GatewayReadyStream {
    fn is_active_video(&self) -> bool {
        self.kind.as_deref() == Some("video") && self.active != Some(false)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDiscoveryPacket {
    pub ssrc: u32,
    pub address: String,
    pub port: u16,
}

impl UdpDiscoveryPacket {
    pub(crate) const LEN: usize = 74;
    const REQUEST_TYPE: u16 = 1;
    const RESPONSE_TYPE: u16 = 2;
    const BODY_LEN: u16 = 70;

    pub(crate) fn request(ssrc: u32) -> [u8; Self::LEN] {
        let mut packet = [0_u8; Self::LEN];
        packet[..2].copy_from_slice(&Self::REQUEST_TYPE.to_be_bytes());
        packet[2..4].copy_from_slice(&Self::BODY_LEN.to_be_bytes());
        packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
        packet
    }

    pub(crate) fn decode(packet: &[u8]) -> Result<Self> {
        if packet.len() < Self::LEN {
            return Err(Error::Protocol(ProtocolError::UdpDiscoveryPacketTooShort {
                len: packet.len(),
                min_len: Self::LEN,
            }));
        }

        let packet_type = u16::from_be_bytes([packet[0], packet[1]]);
        if packet_type != Self::RESPONSE_TYPE {
            return Err(Error::Protocol(
                ProtocolError::UnexpectedUdpDiscoveryPacketType {
                    packet_type,
                    expected_packet_type: Self::RESPONSE_TYPE,
                },
            ));
        }

        let packet_len = u16::from_be_bytes([packet[2], packet[3]]);
        if packet_len != Self::BODY_LEN {
            return Err(Error::Protocol(
                ProtocolError::UnexpectedUdpDiscoveryPacketLen {
                    packet_len,
                    expected_packet_len: Self::BODY_LEN,
                },
            ));
        }

        let address_end = packet[8..72]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| offset + 8)
            .unwrap_or(72);
        let address = std::str::from_utf8(&packet[8..address_end])
            .map_err(|error| Error::Protocol(ProtocolError::InvalidUdpDiscoveryIp(error)))?
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
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for DiscordId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DiscordIdVisitor;

        impl Visitor<'_> for DiscordIdVisitor {
            type Value = DiscordId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Discord snowflake as a string or integer")
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(DiscordId(value))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
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
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.0)
    }
}

pub(crate) async fn read_event(read: &mut GatewayWebSocketRead) -> Result<ParsedVoiceGatewayEvent> {
    loop {
        match read.next().await {
            Some(Ok(WsMessage::Text(text))) => return parse_event_text(&text),
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
            None => return Err(Error::Closed),
        }
    }
}

pub(crate) async fn wait_for_opcode(
    read: &mut GatewayWebSocketRead,
    opcode: Opcode,
    last_seq: &mut Option<i64>,
) -> Result<ParsedVoiceGatewayEvent> {
    loop {
        let event = read_event(read).await?;
        if let Some(seq) = event.seq {
            *last_seq = Some(seq);
        }
        if event.opcode == opcode.code() {
            return Ok(event);
        }
    }
}

pub(crate) async fn wait_for_session_description(
    read: &mut GatewayWebSocketRead,
    last_seq: &mut Option<i64>,
) -> Result<(ParsedVoiceGatewayEvent, Vec<PendingGatewayEvent>)> {
    let mut pending_events = Vec::new();
    loop {
        match read.next().await {
            Some(Ok(WsMessage::Text(text))) => {
                let event = parse_event_text(&text)?;
                if let Some(seq) = event.seq {
                    *last_seq = Some(seq);
                }
                if event.opcode == Opcode::SessionDescription.code() {
                    return Ok((event, pending_events));
                }
                pending_events.push(PendingGatewayEvent::Text(event));
            }
            Some(Ok(WsMessage::Binary(bytes))) => {
                pending_events.push(PendingGatewayEvent::Binary(bytes.to_vec()));
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
            None => return Err(Error::Closed),
        }
    }
}

pub(crate) enum PendingGatewayEvent {
    Text(ParsedVoiceGatewayEvent),
    Binary(Vec<u8>),
}

#[derive(Debug, Default)]
pub(crate) struct GatewayEventEffects {
    pub(crate) disconnected_user_ids: Vec<u64>,
    pub(crate) removed_ssrcs: Vec<u32>,
    pub(crate) retry_dave_pending_media: DavePendingMediaRetry,
    pub(crate) allow_plaintext_receive_grace: bool,
    pub(crate) transport_crypto: Option<TransportCryptoConfig>,
    pub(crate) media_session_updated: bool,
}

pub(crate) fn replay_pending_voice_events(
    state: &mut ConnectionStateStore,
    pending_events: Vec<PendingGatewayEvent>,
    observer: &impl ConnectionObserver,
) -> Result<()> {
    let mut heartbeat_ack = GatewayHeartbeatAckState::default();
    let mut handler = GatewayEventHandler::new(state, &mut heartbeat_ack, observer);
    for event in pending_events {
        match event {
            PendingGatewayEvent::Text(event) => {
                if let Some(seq) = event.seq {
                    handler
                        .state_store
                        .update(|state| state.last_seq = Some(seq));
                }
                let _ = handler.handle_text_event(event)?;
            }
            PendingGatewayEvent::Binary(bytes) => {
                let _ = handle_voice_binary_event(&mut *handler.state_store, &bytes)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GatewayHeartbeatAckState {
    pending: bool,
    sent_at: Option<Instant>,
}

impl GatewayHeartbeatAckState {
    pub(crate) fn is_pending(self) -> bool {
        self.pending
    }

    pub(crate) fn timed_out(self, timeout: Duration) -> bool {
        self.sent_at
            .is_some_and(|sent_at| sent_at.elapsed() >= timeout)
    }

    pub(crate) fn mark_sent(&mut self, sent_at: Instant) {
        self.pending = true;
        self.sent_at = Some(sent_at);
    }

    fn acknowledge(&mut self) {
        self.pending = false;
        self.sent_at = None;
    }
}

pub(crate) struct GatewayEventHandler<'a, O>
where
    O: ConnectionObserver,
{
    state_store: &'a mut ConnectionStateStore,
    heartbeat_ack: &'a mut GatewayHeartbeatAckState,
    observer: &'a O,
}

impl<'a, O> GatewayEventHandler<'a, O>
where
    O: ConnectionObserver,
{
    pub(crate) fn new(
        state_store: &'a mut ConnectionStateStore,
        heartbeat_ack: &'a mut GatewayHeartbeatAckState,
        observer: &'a O,
    ) -> Self {
        Self {
            state_store,
            heartbeat_ack,
            observer,
        }
    }

    pub(crate) fn handle_text_event(
        &mut self,
        event: ParsedVoiceGatewayEvent,
    ) -> Result<GatewayEventEffects> {
        let state = self.state_store.internal();
        let endpoint = state.config.endpoint.clone();
        let guild_id = state.config.identity.guild_id;
        let user_id = state.config.identity.user_id;
        let mut effects = GatewayEventEffects::default();

        match Opcode::from_code(event.opcode) {
            Some(Opcode::SessionDescription) => {
                let description: SessionDescription = parse_data(event.data)?;
                let rtp_codecs =
                    DiscordRtpCodecMap::new(&description, &state.config.options.codec_preferences)?;
                effects.transport_crypto = Some(description.transport_crypto.clone());
                effects.media_session_updated = true;
                self.state_store.update(|state| {
                    state
                        .dave
                        .set_session_protocol(description.dave_protocol_version);
                    state.session_description = Some(description);
                    state.rtp_codecs = Some(rtp_codecs);
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
            }
            Some(Opcode::SessionUpdate) => {
                let update: SessionUpdateEvent = parse_data(event.data)?;
                if update.audio_codec.is_some() || update.video_codec.is_some() {
                    let mut description =
                        self.state_store
                            .internal()
                            .session_description
                            .clone()
                            .ok_or(Error::Protocol(ProtocolError::MissingSessionDescription))?;
                    if let Some(audio_codec) = update.audio_codec {
                        description.audio_codec = Some(audio_codec);
                    }
                    if let Some(video_codec) = update.video_codec {
                        description.video_codec = Some(video_codec);
                    }
                    let rtp_codecs = DiscordRtpCodecMap::new(
                        &description,
                        &state.config.options.codec_preferences,
                    )?;
                    self.state_store.update(|state| {
                        state.session_description = Some(description);
                        state.rtp_codecs = Some(rtp_codecs);
                    });
                    effects.media_session_updated = true;
                }
            }
            Some(Opcode::Resumed) => {
                self.state_store.update(|state| state.resumed = true);
            }
            Some(Opcode::DavePrepareTransition) => {
                let transition: DavePrepareTransitionEvent = parse_data(event.data)?;
                self.state_store.update(|state| {
                    state
                        .dave
                        .prepare_transition(transition.transition_id, transition.protocol_version);
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
            }
            Some(Opcode::DaveExecuteTransition) => {
                let transition: DaveExecuteTransitionEvent = parse_data(event.data)?;
                let allow_plaintext_receive_grace = {
                    let dave = &self.state_store.internal().dave;
                    dave.transition_id() == Some(transition.transition_id)
                        && dave.active_receive_protocol_version().unwrap_or(0) == 0
                        && dave.protocol_version().unwrap_or(0) > 0
                };
                self.state_store.update(|state| {
                    state.dave.execute_transition(transition.transition_id);
                });
                effects.allow_plaintext_receive_grace = allow_plaintext_receive_grace;
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
            }
            Some(Opcode::DavePrepareEpoch) => {
                let epoch: DavePrepareEpochEvent = parse_data(event.data)?;
                self.state_store.update(|state| {
                    state
                        .dave
                        .prepare_epoch(epoch.protocol_version, epoch.epoch);
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
            }
            Some(Opcode::Speaking) => {
                let update: SpeakingUpdate = parse_data(event.data)?;
                self.state_store.update(|state| {
                    if let Some(user_id) = update.user_id.as_ref() {
                        state.ssrc_users_mut().insert(update.ssrc, user_id.get());
                    }
                    state.speaking_mut().insert(update.ssrc, update);
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::missing_user());
            }
            Some(Opcode::ClientsConnect) => {
                let clients: ClientsConnectEvent = parse_data(event.data)?;
                self.state_store.update(|state| {
                    state.roster_authoritative = true;
                    state
                        .connected_user_ids_mut()
                        .extend(clients.user_ids.iter().map(DiscordId::get));
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
                if !clients.user_ids.is_empty() {
                    self.observer.clients_connected(ClientsConnectedEvent {
                        endpoint: &endpoint,
                        guild_id,
                        user_id,
                        user_count: clients.user_ids.len(),
                    });
                }
            }
            Some(Opcode::ClientConnect) => {
                let client: ClientConnectEvent = parse_data(event.data)?;
                self.state_store.update(|state| {
                    state.roster_authoritative = true;
                    state.connected_user_ids_mut().insert(client.user_id.get());
                    if let Some(ssrc) = client.ssrc() {
                        state.ssrc_users_mut().insert(ssrc, client.user_id.get());
                    }
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::missing_user());
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
            }
            Some(Opcode::ClientDisconnect) => {
                let disconnect: ClientDisconnectEvent = parse_data(event.data)?;
                let disconnected_user_id = disconnect.user_id.get();
                effects.disconnected_user_ids.push(disconnected_user_id);
                self.state_store.update(|state| {
                    state.roster_authoritative = true;
                    state.connected_user_ids_mut().remove(&disconnected_user_id);
                    state.ssrc_users_mut().retain(|ssrc, stored_user_id| {
                        if stored_user_id == &disconnected_user_id {
                            effects.removed_ssrcs.push(*ssrc);
                            false
                        } else {
                            true
                        }
                    });
                });
                effects
                    .retry_dave_pending_media
                    .include(DavePendingMediaRetry::dave_state());
            }
            Some(Opcode::HeartbeatAck) => {
                self.heartbeat_ack.acknowledge();
            }
            Some(Opcode::Hello | Opcode::Ready | Opcode::Heartbeat | Opcode::Resume) => {}
            _ => {}
        }

        Ok(effects)
    }
}

pub(crate) fn parse_event_text(text: &str) -> Result<ParsedVoiceGatewayEvent> {
    let event: GatewayEvent = serde_json::from_str(text)?;
    Ok(ParsedVoiceGatewayEvent {
        opcode: event.op,
        seq: event.seq,
        data: event.d.unwrap_or(Value::Null),
    })
}

pub(crate) fn parse_data<T>(data: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    Ok(serde_json::from_value(data)?)
}

pub(crate) fn handle_voice_binary_event(
    state_store: &mut ConnectionStateStore,
    bytes: &[u8],
) -> Result<GatewayEventEffects> {
    let mut effects = GatewayEventEffects::default();
    let Some(event) = BinaryEvent::parse(bytes) else {
        return Ok(effects);
    };
    state_store.update(|state| state.last_seq = Some(event.seq));

    match event.opcode {
        Opcode::DaveMlsExternalSender => {
            state_store.update(|state| state.dave.external_sender = Some(event.payload.to_vec()));
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Opcode::DaveMlsProposals => {
            state_store.update(|state| state.dave.proposals.push(event.payload.to_vec()));
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Opcode::DaveMlsAnnounceCommitTransition | Opcode::DaveMlsWelcome => {
            let kind = event
                .opcode
                .dave_mls_message_kind()
                .expect("DAVE MLS message opcode has a message kind");
            let payload = DaveTransitionBinaryPayload::parse(event)?;
            let message = payload.pending_message(kind);
            state_store.update(|state| {
                state.dave.set_pending_mls_message(message);
            });
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        _ => {}
    }

    Ok(effects)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DaveTransitionBinaryPayload<'a> {
    seq: i64,
    transition_id: u16,
    body: &'a [u8],
}

impl<'a> DaveTransitionBinaryPayload<'a> {
    const TRANSITION_ID_LEN: usize = 2;

    fn parse(event: BinaryEvent<'a>) -> Result<Self> {
        if event.payload.len() < Self::TRANSITION_ID_LEN {
            return Err(DaveError::InvalidGatewayPayload(
                DaveGatewayPayloadError::PayloadTooShort {
                    opcode: event.opcode.byte(),
                    len: event.payload.len(),
                    min_len: Self::TRANSITION_ID_LEN,
                },
            )
            .into());
        }
        Ok(Self {
            seq: event.seq,
            transition_id: u16::from_be_bytes([event.payload[0], event.payload[1]]),
            body: &event.payload[Self::TRANSITION_ID_LEN..],
        })
    }

    fn pending_message(self, kind: DaveMlsMessageKind) -> PendingDaveMlsMessage {
        PendingDaveMlsMessage::new(
            DaveMlsMessageIdentity {
                kind,
                seq: self.seq,
                transition_id: self.transition_id,
            },
            self.body.to_vec(),
        )
    }
}

pub(crate) struct BinaryEvent<'a> {
    pub(crate) seq: i64,
    pub(crate) opcode: Opcode,
    pub(crate) payload: &'a [u8],
}

impl<'a> BinaryEvent<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        match bytes {
            [first, second, opcode, payload @ ..] => {
                let opcode = Opcode::from_server_binary(*opcode)?;
                Some(Self {
                    seq: i64::from(u16::from_be_bytes([*first, *second])),
                    opcode,
                    payload,
                })
            }
            _ => None,
        }
    }
}
