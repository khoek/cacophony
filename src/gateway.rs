use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum VoiceOpcode {
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
pub struct VoiceSpeakingFlags(u8);

impl VoiceSpeakingFlags {
    pub const NONE: Self = Self(0);
    pub const MICROPHONE: Self = Self(1);

    pub(crate) fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub(crate) enum VoiceGatewayCommand {
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
    pub(crate) fn opcode(&self) -> VoiceOpcode {
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

    pub(crate) fn text_payload(&self) -> VoiceResult<String> {
        match self {
            Self::Identify(data) => serialize_voice_payload(self.opcode(), data),
            Self::SelectProtocol(data) => serialize_voice_payload(self.opcode(), data),
            Self::Speaking(data) => serialize_voice_payload(self.opcode(), data),
            Self::Heartbeat(data) => serialize_voice_payload(self.opcode(), data),
            Self::DaveProtocolTransitionReady(data) => serialize_voice_payload(self.opcode(), data),
            Self::DaveMlsInvalidCommitWelcome(data) => serialize_voice_payload(self.opcode(), data),
            Self::DaveMlsKeyPackage { .. } | Self::DaveMlsCommitWelcome { .. } => {
                Err(VoiceError::protocol(
                    "DAVE MLS key package and commit/welcome use binary websocket frames",
                ))
            }
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
pub(crate) struct VoiceGatewayPayload<'a, T: ?Sized> {
    op: u64,
    d: &'a T,
}

pub(crate) fn serialize_voice_payload<T>(opcode: VoiceOpcode, data: &T) -> VoiceResult<String>
where
    T: Serialize + ?Sized,
{
    Ok(serde_json::to_string(&VoiceGatewayPayload {
        op: opcode.code(),
        d: data,
    })?)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct VoiceIdentifyCommand {
    server_id: String,
    user_id: String,
    session_id: String,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_dave_protocol_version: Option<u16>,
}

impl VoiceIdentifyCommand {
    pub(crate) fn from_config(config: &VoiceConnectionConfig) -> Self {
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
pub(crate) struct VoiceSelectProtocolCommand {
    protocol: &'static str,
    pub(crate) data: VoiceSelectProtocolData,
}

impl VoiceSelectProtocolCommand {
    pub(crate) fn udp(address: String, port: u16, mode: VoiceEncryptionMode) -> Self {
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
pub(crate) struct VoiceSelectProtocolData {
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
pub(crate) struct VoiceSpeakingCommand {
    pub(crate) speaking: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) delay: Option<u32>,
    pub(crate) ssrc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_id: Option<DiscordId>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct VoiceHeartbeatCommand {
    pub(crate) t: u64,
    pub(crate) seq_ack: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct VoiceDaveTransitionReadyCommand {
    pub(crate) transition_id: u16,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct VoiceDaveInvalidCommitWelcomeCommand {
    pub(crate) transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceGatewayEvent {
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
pub(crate) struct VoiceHelloData {
    heartbeat_interval: f64,
}

impl VoiceHelloData {
    pub(crate) fn heartbeat_interval_ms(&self) -> u64 {
        self.heartbeat_interval.max(1.0).ceil() as u64
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceDavePrepareTransitionEvent {
    protocol_version: u16,
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceDaveExecuteTransitionEvent {
    transition_id: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceDavePrepareEpochEvent {
    protocol_version: u16,
    epoch: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceClientsConnectEvent {
    #[serde(default)]
    user_ids: Vec<DiscordId>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceClientConnectEvent {
    user_id: DiscordId,
    #[serde(default)]
    audio_ssrc: Option<u32>,
    #[serde(default)]
    ssrc: Option<u32>,
}

impl VoiceClientConnectEvent {
    pub(crate) fn voice_ssrc(&self) -> Option<u32> {
        self.audio_ssrc.or(self.ssrc)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VoiceClientDisconnectEvent {
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

    pub(crate) fn decode(packet: &[u8]) -> VoiceResult<Self> {
        if packet.len() < Self::LEN {
            return Err(VoiceError::protocol(format!(
                "voice discovery packet must be at least {} bytes",
                Self::LEN
            )));
        }

        let packet_type = u16::from_be_bytes([packet[0], packet[1]]);
        if packet_type != Self::RESPONSE_TYPE {
            return Err(VoiceError::protocol(format!(
                "unexpected voice discovery packet type {packet_type}",
            )));
        }

        let packet_len = u16::from_be_bytes([packet[2], packet[3]]);
        if packet_len != Self::BODY_LEN {
            return Err(VoiceError::protocol(format!(
                "unexpected voice discovery packet length {packet_len}",
            )));
        }

        let address_end = packet[8..72]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| offset + 8)
            .unwrap_or(72);
        let address = std::str::from_utf8(&packet[8..address_end])
            .map_err(|error| VoiceError::protocol(format!("invalid voice discovery ip: {error}")))?
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

pub(crate) async fn read_voice_event(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> VoiceResult<ParsedVoiceGatewayEvent> {
    loop {
        match read.next().await {
            Some(Ok(WsMessage::Text(text))) => return parse_voice_event_text(&text),
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
            None => return Err(VoiceError::Closed),
        }
    }
}

pub(crate) async fn wait_for_voice_opcode(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    opcode: VoiceOpcode,
    last_seq: &mut Option<i64>,
) -> VoiceResult<ParsedVoiceGatewayEvent> {
    loop {
        let event = read_voice_event(read).await?;
        if let Some(seq) = event.seq {
            *last_seq = Some(seq);
        }
        if event.opcode == opcode.code() {
            return Ok(event);
        }
    }
}

pub(crate) async fn wait_for_session_description(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    last_seq: &mut Option<i64>,
) -> VoiceResult<(ParsedVoiceGatewayEvent, Vec<PendingVoiceGatewayEvent>)> {
    let mut pending_events = Vec::new();
    loop {
        match read.next().await {
            Some(Ok(WsMessage::Text(text))) => {
                let event = parse_voice_event_text(&text)?;
                if let Some(seq) = event.seq {
                    *last_seq = Some(seq);
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
            None => return Err(VoiceError::Closed),
        }
    }
}

pub(crate) enum PendingVoiceGatewayEvent {
    Text(ParsedVoiceGatewayEvent),
    Binary(Vec<u8>),
}

pub(crate) fn replay_pending_voice_events(
    state: &VoiceConnectionStateChannels,
    pending_events: Vec<PendingVoiceGatewayEvent>,
    observer: &impl VoiceConnectionObserver,
) -> VoiceResult<()> {
    let mut heartbeat_ack_pending = false;
    let mut heartbeat_sent_at = None;
    for event in pending_events {
        match event {
            PendingVoiceGatewayEvent::Text(event) => {
                if let Some(seq) = event.seq {
                    update_state(state, |state| state.last_seq = Some(seq));
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

pub(crate) fn parse_voice_event_text(text: &str) -> VoiceResult<ParsedVoiceGatewayEvent> {
    let event: VoiceGatewayEvent = serde_json::from_str(text)?;
    Ok(ParsedVoiceGatewayEvent {
        opcode: event.op,
        seq: event.seq,
        data: event.d.unwrap_or(Value::Null),
    })
}

pub(crate) fn parse_voice_data<T>(data: Value) -> VoiceResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    Ok(serde_json::from_value(data)?)
}

pub(crate) fn handle_voice_text_event(
    channels: &VoiceConnectionStateChannels,
    event: ParsedVoiceGatewayEvent,
    heartbeat_ack_pending: &mut bool,
    heartbeat_sent_at: &mut Option<Instant>,
    observer: &impl VoiceConnectionObserver,
) -> VoiceResult<()> {
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

pub(crate) fn handle_voice_binary_event(
    channels: &VoiceConnectionStateChannels,
    bytes: &[u8],
) -> VoiceResult<()> {
    let Some(event) = VoiceBinaryEvent::parse(bytes) else {
        return Ok(());
    };
    if let Some(seq) = event.seq {
        update_state(channels, |state| state.last_seq = Some(seq));
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

pub(crate) struct VoiceBinaryEvent<'a> {
    pub(crate) seq: Option<i64>,
    pub(crate) opcode: VoiceOpcode,
    pub(crate) payload: &'a [u8],
}

impl<'a> VoiceBinaryEvent<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        match bytes {
            [first, second, opcode, payload @ ..] => {
                let opcode = VoiceOpcode::from_server_binary(*opcode)?;
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
