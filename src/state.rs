use super::*;

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

    pub(crate) fn public_info(&self) -> VoiceConnectionInfo {
        VoiceConnectionInfo {
            server_id: self.server_id,
            channel_id: self.channel_id,
            user_id: self.user_id,
            endpoint: self.endpoint.clone(),
            gateway_version: self.gateway_version,
            max_dave_protocol_version: self.max_dave_protocol_version,
        }
    }

    pub(crate) fn websocket_url(&self) -> VoiceResult<String> {
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
    pub(crate) fn from_frame(frame: &CloseFrame) -> Self {
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
    pub(crate) secret_key: VoiceSecretKey,
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
pub(crate) struct VoiceSecretKey(pub(crate) Vec<u8>);

impl VoiceSecretKey {
    pub(crate) fn as_slice(&self) -> &[u8] {
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

impl VoiceConnectionInfo {
    pub(crate) fn connection_event(&self) -> VoiceConnectionEvent<'_> {
        VoiceConnectionEvent {
            endpoint: &self.endpoint,
            guild_id: self.server_id,
            user_id: self.user_id,
        }
    }
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
    pub prepare_epoch_seq: u64,
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
pub(crate) struct VoiceDaveInternalState {
    pub(crate) protocol_version: Option<u16>,
    pub(crate) transition_id: Option<u16>,
    pub(crate) epoch: Option<u64>,
    #[serde(default)]
    pub(crate) prepare_epoch_seq: u64,
    pub(crate) passthrough: bool,
    #[serde(default)]
    pub(crate) external_sender: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) proposals: Vec<Vec<u8>>,
    #[serde(default)]
    pub(crate) pending_commit: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) pending_welcome: Option<Vec<u8>>,
}

impl VoiceDaveInternalState {
    pub(crate) fn mls_state(&self) -> VoiceDaveMlsState {
        VoiceDaveMlsState {
            external_sender: self.external_sender.is_some(),
            pending: VoiceDavePendingMlsState {
                proposals: self.proposals.len(),
                commit: self.pending_commit.is_some(),
                welcome: self.pending_welcome.is_some(),
            },
        }
    }

    pub(crate) fn public_state(&self) -> VoiceDaveState {
        VoiceDaveState {
            protocol_version: self.protocol_version,
            transition_id: self.transition_id,
            epoch: self.epoch,
            prepare_epoch_seq: self.prepare_epoch_seq,
            passthrough: self.passthrough,
            mls: self.mls_state(),
        }
    }

    pub(crate) fn set_session_protocol(&mut self, protocol_version: Option<u16>) {
        if self.protocol_version != protocol_version {
            self.clear_pending_mls();
        }
        self.protocol_version = protocol_version;
        self.passthrough = protocol_version.unwrap_or(0) == 0;
    }

    pub(crate) fn prepare_transition(&mut self, transition_id: u16, protocol_version: u16) {
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

    pub(crate) fn prepare_epoch(&mut self, protocol_version: u16, epoch: u64) {
        self.prepare_epoch_seq = self.prepare_epoch_seq.saturating_add(1);
        if epoch == 1 || self.epoch != Some(epoch) {
            self.clear_pending_mls();
        }
        self.epoch = Some(epoch);
        self.protocol_version = Some(protocol_version);
        self.passthrough = protocol_version == 0;
    }

    pub(crate) fn execute_transition(&mut self, transition_id: u16) {
        if self.transition_id == Some(transition_id) {
            self.transition_id = None;
        }
        self.clear_pending_mls();
    }

    pub(crate) fn clear_pending_mls(&mut self) {
        self.proposals.clear();
        self.pending_commit = None;
        self.pending_welcome = None;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceConnectionState {
    pub connection: VoiceConnectionInfo,
    pub heartbeat_interval_ms: u64,
    pub last_seq: Option<i64>,
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
pub(crate) struct VoiceConnectionInternalState {
    pub(crate) config: VoiceConnectionConfig,
    pub(crate) heartbeat_interval_ms: u64,
    pub(crate) last_seq: Option<i64>,
    pub(crate) ready: VoiceGatewayReady,
    pub(crate) discovery: VoiceUdpDiscoveryPacket,
    pub(crate) selected_mode: VoiceEncryptionMode,
    pub(crate) session_description: Option<VoiceSessionDescription>,
    pub(crate) connected_user_ids: HashSet<u64>,
    pub(crate) ssrc_users: HashMap<u32, u64>,
    pub(crate) speaking: HashMap<u32, VoiceSpeakingUpdate>,
    pub(crate) dave: VoiceDaveInternalState,
    pub(crate) roster_authoritative: bool,
    pub(crate) resumed: bool,
}

impl VoiceConnectionInternalState {
    pub(crate) fn public_state(&self) -> VoiceConnectionState {
        VoiceConnectionState {
            connection: self.config.public_info(),
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            last_seq: self.last_seq,
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
}

#[derive(Default)]
pub(crate) struct VoiceReceiveState {
    pub(crate) pending_dave_media: VecDeque<PendingVoiceMediaFrame>,
    pub(crate) ssrc: HashMap<u32, VoiceReceiveSsrcState>,
}

impl VoiceReceiveState {
    pub(crate) fn pending_dave_media_deadline(&self) -> Option<Instant> {
        self.pending_dave_media
            .iter()
            .map(|packet| packet.enqueued_at + DAVE_PENDING_MEDIA_TTL)
            .min()
    }

    pub(crate) fn pending_rtp_reorder_deadline(&self) -> Option<Instant> {
        self.ssrc
            .values()
            .filter_map(VoiceReceiveSsrcState::pending_reorder_deadline)
            .min()
    }

    pub(crate) fn push_media_frame<O>(
        &mut self,
        observer: &O,
        media: PendingVoiceMediaFrame,
    ) -> Option<PendingVoiceMediaFrame>
    where
        O: VoiceConnectionObserver,
    {
        let now = Instant::now();
        self.ssrc
            .entry(media.rtp.ssrc)
            .or_default()
            .push_media_frame(observer, media, now)
    }

    pub(crate) fn drain_ordered_media<O>(&mut self, observer: &O) -> Option<PendingVoiceMediaFrame>
    where
        O: VoiceConnectionObserver,
    {
        let now = Instant::now();
        loop {
            if let Some(ssrc) = self.ready_buffered_ssrc() {
                return self
                    .ssrc
                    .get_mut(&ssrc)
                    .and_then(VoiceReceiveSsrcState::pop_ready_buffered_media);
            }
            if let Some(ssrc) = self.expired_missing_ssrc(now) {
                if let Some(state) = self.ssrc.get_mut(&ssrc) {
                    state.expire_missing_head(observer, ssrc, now, false);
                }
                continue;
            }
            return None;
        }
    }

    fn ready_buffered_ssrc(&self) -> Option<u32> {
        self.ssrc
            .iter()
            .find_map(|(ssrc, state)| state.has_ready_buffered_media().then_some(*ssrc))
    }

    fn expired_missing_ssrc(&self, now: Instant) -> Option<u32> {
        self.ssrc
            .iter()
            .find_map(|(ssrc, state)| state.head_missing_expired(now).then_some(*ssrc))
    }
}

#[derive(Default)]
pub(crate) struct VoiceReceiveSsrcState {
    pub(crate) last_arrival: Option<Instant>,
    pub(crate) next_seq: Option<u16>,
    pub(crate) missing: BTreeMap<u16, VoiceMissingRtpPacket>,
    pub(crate) pending_media: BTreeMap<u16, PendingVoiceMediaFrame>,
    pub(crate) interarrival_order: VecDeque<u64>,
    pub(crate) interarrival_sorted: Vec<u64>,
}

impl VoiceReceiveSsrcState {
    fn push_media_frame<O>(
        &mut self,
        observer: &O,
        media: PendingVoiceMediaFrame,
        now: Instant,
    ) -> Option<PendingVoiceMediaFrame>
    where
        O: VoiceConnectionObserver,
    {
        self.record_arrival(observer, &media, now);
        let ssrc = media.rtp.ssrc;
        let seq = media.rtp.seq;
        let Some(expected) = self.next_seq else {
            self.next_seq = Some(seq.wrapping_add(1));
            return Some(media);
        };
        if seq == expected {
            self.missing.remove(&seq);
            self.pending_media.remove(&seq);
            self.next_seq = Some(seq.wrapping_add(1));
            return Some(media);
        }

        let forward = seq.wrapping_sub(expected);
        if forward < 0x8000 {
            if usize::from(forward) > RTP_REORDER_BUFFER_MAX_FRAMES {
                self.emit_packet_loss(
                    observer,
                    VoiceReceiveRtpPacketLossEvent {
                        ssrc,
                        user_id: media.user_id,
                        first_seq: expected,
                        last_seq: seq.wrapping_sub(1),
                        missing_packets: forward,
                        age_ms: 0,
                    },
                );
                self.missing.clear();
                self.pending_media.clear();
                self.next_seq = Some(seq.wrapping_add(1));
                return Some(media);
            }

            self.mark_missing(expected, forward, media.user_id, now);
            self.pending_media.entry(seq).or_insert(media);
            if self.pending_media.len() > RTP_REORDER_BUFFER_MAX_FRAMES {
                self.expire_missing_head(observer, ssrc, now, true);
            }
            return self.pop_ready_buffered_media();
        }

        None
    }

    fn record_arrival<O>(&mut self, observer: &O, media: &PendingVoiceMediaFrame, now: Instant)
    where
        O: VoiceConnectionObserver,
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
        observer.receive_rtp_packet(VoiceReceiveRtpPacketEvent {
            ssrc: media.rtp.ssrc,
            user_id: media.user_id,
            seq: media.rtp.seq,
            timestamp: media.rtp.timestamp,
            payload_bytes: media.encrypted_frame.len(),
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
                .or_insert(VoiceMissingRtpPacket {
                    user_id,
                    detected_at,
                });
        }
    }

    fn has_ready_buffered_media(&self) -> bool {
        self.next_seq
            .is_some_and(|seq| self.pending_media.contains_key(&seq))
    }

    fn pop_ready_buffered_media(&mut self) -> Option<PendingVoiceMediaFrame> {
        let seq = self.next_seq?;
        let media = self.pending_media.remove(&seq)?;
        self.missing.remove(&seq);
        self.next_seq = Some(seq.wrapping_add(1));
        Some(media)
    }

    fn pending_reorder_deadline(&self) -> Option<Instant> {
        let seq = self.next_seq?;
        self.missing
            .get(&seq)
            .map(|missing| missing.detected_at + RTP_REORDER_TTL)
    }

    fn head_missing_expired(&self, now: Instant) -> bool {
        self.pending_reorder_deadline()
            .is_some_and(|deadline| now >= deadline)
    }

    fn expire_missing_head<O>(&mut self, observer: &O, ssrc: u32, now: Instant, force: bool) -> bool
    where
        O: VoiceConnectionObserver,
    {
        let Some(mut seq) = self.next_seq else {
            return false;
        };
        let Some(first_missing) = self.missing.get(&seq) else {
            return false;
        };
        if !force && now < first_missing.detected_at + RTP_REORDER_TTL {
            return false;
        }

        let first_seq = seq;
        let mut last_seq = seq;
        let mut missing_packets = 0_u16;
        let mut user_id = first_missing.user_id;
        let detected_at = first_missing.detected_at;
        while let Some(missing) = self.missing.get(&seq) {
            if !force && now < missing.detected_at + RTP_REORDER_TTL {
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
        self.next_seq = Some(seq);
        self.emit_packet_loss(
            observer,
            VoiceReceiveRtpPacketLossEvent {
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

    fn emit_packet_loss<O>(&self, observer: &O, event: VoiceReceiveRtpPacketLossEvent)
    where
        O: VoiceConnectionObserver,
    {
        if O::ENABLE_RECEIVE_TELEMETRY {
            observer.receive_rtp_packet_loss(event);
        }
    }
    pub(crate) fn record_interarrival(&mut self, interarrival_us: u64) {
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

    pub(crate) fn interarrival_p95_us(&self) -> Option<u64> {
        self.interarrival_sorted
            .get(((self.interarrival_sorted.len().saturating_sub(1)) * 95) / 100)
            .copied()
    }

    pub(crate) fn interarrival_max_us(&self) -> Option<u64> {
        self.interarrival_sorted.last().copied()
    }
}

pub(crate) struct VoiceMissingRtpPacket {
    pub(crate) user_id: Option<u64>,
    pub(crate) detected_at: Instant,
}

pub(crate) struct PendingVoiceMediaFrame {
    pub(crate) raw: VoiceRawUdpPacket,
    pub(crate) rtp: VoiceRtpHeader,
    pub(crate) user_id: Option<u64>,
    pub(crate) encrypted_frame: Vec<u8>,
    pub(crate) dave: bool,
    pub(crate) enqueued_at: Instant,
    pub(crate) reason: VoiceDavePendingMediaReason,
    pub(crate) was_pending: bool,
}

impl PendingVoiceMediaFrame {
    pub(crate) fn event(
        &self,
        pending_packets: usize,
        reason: VoiceDavePendingMediaReason,
    ) -> VoiceDavePendingMediaEvent {
        VoiceDavePendingMediaEvent {
            reason,
            ssrc: self.rtp.ssrc,
            user_id: self.user_id,
            seq: self.rtp.seq,
            pending_packets,
            age_ms: duration_ms(self.enqueued_at.elapsed()),
        }
    }
}
