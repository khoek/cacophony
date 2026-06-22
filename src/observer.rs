use super::*;

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

    fn receive_rtp_packet_loss(&self, _event: VoiceReceiveRtpPacketLossEvent) {}

    fn receive_decode_error(&self, _event: VoiceReceiveDecodeErrorEvent) {}

    fn receive_frame_dropped(&self, _event: VoiceReceiveFrameDroppedEvent) {}

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
    pub seq: Option<i64>,
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
    pub(crate) fn label(self) -> &'static str {
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
    pub seq: u16,
    pub timestamp: u32,
    pub payload_bytes: usize,
    pub interarrival_us: Option<u64>,
    pub interarrival_p95_us: Option<u64>,
    pub interarrival_max_us: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceReceiveRtpPacketLossEvent {
    pub ssrc: u32,
    pub user_id: Option<u64>,
    pub first_seq: u16,
    pub last_seq: u16,
    pub missing_packets: u16,
    pub age_ms: u64,
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
    pub seq: Option<u16>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceReceiveFrameDropReason {
    ReadyQueueOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceReceiveFrameDroppedEvent {
    pub reason: VoiceReceiveFrameDropReason,
    pub ssrc: Option<u32>,
    pub user_id: Option<u64>,
    pub seq: Option<u16>,
    pub queued_frames: usize,
    pub dropped_error: bool,
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
    pub seq: u16,
    pub pending_packets: usize,
    pub age_ms: u64,
}
