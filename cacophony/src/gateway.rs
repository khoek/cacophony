use std::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
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
    connection::ConnectionStateStore,
    errors::{DaveError, DaveGatewayPayloadError, Error, ProtocolError, Result},
    media::TransportCryptoConfig,
    media::update_state,
    observer::{ClientsConnectedEvent, ConnectionObserver},
    state::{DavePendingMediaRetry, EncryptionMode, SessionDescription, ValidatedConnectionConfig},
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
    pub(crate) const ALL: [Self; 24] = [
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

    pub(crate) const fn code(self) -> u64 {
        self as u8 as u64
    }

    pub(crate) const fn byte(self) -> u8 {
        self as u8
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
    #[serde(skip_serializing_if = "Option::is_none")]
    max_dave_protocol_version: Option<u16>,
}

impl<'a> IdentifyCommand<'a> {
    pub(crate) fn from_config(config: &'a ValidatedConnectionConfig) -> Self {
        Self {
            server_id: config.identity.guild_id.to_string(),
            user_id: config.identity.user_id.to_string(),
            session_id: config.secrets.session_id.as_str(),
            token: config.secrets.token.as_str(),
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
}

impl SelectProtocolCommand {
    pub(crate) fn udp(address: String, port: u16, mode: EncryptionMode) -> Self {
        Self {
            protocol: "udp",
            data: SelectProtocolData {
                address,
                port,
                mode,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SelectProtocolData {
    address: String,
    port: u16,
    mode: EncryptionMode,
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
    pub modes: Vec<EncryptionMode>,
    #[serde(default)]
    pub heartbeat_interval: Option<u64>,
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
    pub(crate) allow_transition_receive_passthrough: bool,
    pub(crate) transport_crypto: Option<TransportCryptoConfig>,
}

pub(crate) fn replay_pending_voice_events(
    state: &mut ConnectionStateStore,
    pending_events: Vec<PendingGatewayEvent>,
    observer: &impl ConnectionObserver,
) -> Result<()> {
    let mut heartbeat_ack_pending = false;
    let mut heartbeat_sent_at = None;
    for event in pending_events {
        match event {
            PendingGatewayEvent::Text(event) => {
                if let Some(seq) = event.seq {
                    update_state(state, |state| state.last_seq = Some(seq));
                }
                let _ = handle_voice_text_event(
                    state,
                    event,
                    &mut heartbeat_ack_pending,
                    &mut heartbeat_sent_at,
                    observer,
                )?;
            }
            PendingGatewayEvent::Binary(bytes) => {
                let _ = handle_voice_binary_event(state, &bytes)?;
            }
        }
    }
    Ok(())
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

pub(crate) fn handle_voice_text_event(
    state_store: &mut ConnectionStateStore,
    event: ParsedVoiceGatewayEvent,
    heartbeat_ack_pending: &mut bool,
    heartbeat_sent_at: &mut Option<Instant>,
    observer: &impl ConnectionObserver,
) -> Result<GatewayEventEffects> {
    let state = state_store.internal();
    let endpoint = state.config.endpoint.clone();
    let guild_id = state.config.identity.guild_id;
    let user_id = state.config.identity.user_id;
    let mut effects = GatewayEventEffects::default();

    match Opcode::from_code(event.opcode) {
        Some(Opcode::SessionDescription) => {
            let description: SessionDescription = parse_data(event.data)?;
            effects.transport_crypto = Some(description.transport_crypto.clone());
            update_state(state_store, |state| {
                state
                    .dave
                    .set_session_protocol(description.dave_protocol_version);
                state.session_description = Some(description);
            });
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Some(Opcode::Resumed) => {
            update_state(state_store, |state| state.resumed = true);
        }
        Some(Opcode::DavePrepareTransition) => {
            let transition: DavePrepareTransitionEvent = parse_data(event.data)?;
            update_state(state_store, |state| {
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
            let allow_transition_receive_passthrough = {
                let dave = &state_store.internal().dave;
                dave.transition_id == Some(transition.transition_id)
                    && dave.active_receive_protocol_version.unwrap_or(0) == 0
                    && dave.protocol_version.unwrap_or(0) > 0
            };
            update_state(state_store, |state| {
                state.dave.execute_transition(transition.transition_id);
            });
            effects.allow_transition_receive_passthrough = allow_transition_receive_passthrough;
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Some(Opcode::DavePrepareEpoch) => {
            let epoch: DavePrepareEpochEvent = parse_data(event.data)?;
            update_state(state_store, |state| {
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
            update_state(state_store, |state| {
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
            update_state(state_store, |state| {
                state.roster_authoritative = true;
                state
                    .connected_user_ids_mut()
                    .extend(clients.user_ids.iter().map(DiscordId::get));
            });
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
            if !clients.user_ids.is_empty() {
                observer.clients_connected(ClientsConnectedEvent {
                    endpoint: &endpoint,
                    guild_id,
                    user_id,
                    user_count: clients.user_ids.len(),
                });
            }
        }
        Some(Opcode::ClientConnect) => {
            let client: ClientConnectEvent = parse_data(event.data)?;
            update_state(state_store, |state| {
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
            update_state(state_store, |state| {
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
            *heartbeat_ack_pending = false;
            *heartbeat_sent_at = None;
        }
        Some(Opcode::Hello | Opcode::Ready | Opcode::Heartbeat | Opcode::Resume) => {}
        _ => {}
    }

    Ok(effects)
}

pub(crate) fn handle_voice_binary_event(
    state_store: &mut ConnectionStateStore,
    bytes: &[u8],
) -> Result<GatewayEventEffects> {
    let mut effects = GatewayEventEffects::default();
    let Some(event) = BinaryEvent::parse(bytes) else {
        return Ok(effects);
    };
    if let Some(seq) = event.seq {
        update_state(state_store, |state| state.last_seq = Some(seq));
    }

    match event.opcode {
        Opcode::DaveMlsExternalSender => {
            update_state(state_store, |state| {
                state.dave.external_sender = Some(event.payload.to_vec())
            });
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Opcode::DaveMlsProposals => {
            update_state(state_store, |state| {
                state.dave.proposals.push(event.payload.to_vec())
            });
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Opcode::DaveMlsAnnounceCommitTransition => {
            let payload = DaveTransitionBinaryPayload::parse(event)?;
            let commit = payload.body.to_vec();
            update_state(state_store, |state| {
                if state.dave.transition_id != Some(payload.transition_id) {
                    state.dave.clear_pending_mls();
                }
                state.dave.transition_id = Some(payload.transition_id);
                state.dave.pending_commit = Some(commit);
            });
            effects
                .retry_dave_pending_media
                .include(DavePendingMediaRetry::dave_state());
        }
        Opcode::DaveMlsWelcome => {
            let payload = DaveTransitionBinaryPayload::parse(event)?;
            let welcome = payload.body.to_vec();
            update_state(state_store, |state| {
                if state.dave.transition_id != Some(payload.transition_id) {
                    state.dave.clear_pending_mls();
                }
                state.dave.transition_id = Some(payload.transition_id);
                state.dave.pending_welcome = Some(welcome);
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
            transition_id: u16::from_be_bytes([event.payload[0], event.payload[1]]),
            body: &event.payload[Self::TRANSITION_ID_LEN..],
        })
    }
}

pub(crate) struct BinaryEvent<'a> {
    pub(crate) seq: Option<i64>,
    pub(crate) opcode: Opcode,
    pub(crate) payload: &'a [u8],
}

impl<'a> BinaryEvent<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        match bytes {
            [first, second, opcode, payload @ ..] => {
                let opcode = Opcode::from_server_binary(*opcode)?;
                Some(Self {
                    seq: Some(i64::from(u16::from_be_bytes([*first, *second]))),
                    opcode,
                    payload,
                })
            }
            _ => None,
        }
    }
}
