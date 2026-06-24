use std::{fmt, time::Duration};

use serde::{Serialize, Serializer};

use crate::{
    dave::{
        DaveGatewayStateEvent, DaveIgnoredProposalsEvent, DaveKeyPackageEvent, DaveProposalsEvent,
        DaveTransitionEvent,
    },
    errors::Error,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopConnectionObserver;

/// Receives typed connection callbacks from the voice connection driver.
///
/// Observer methods run inline on the connection driver task. Implementations must keep callbacks
/// O(1), nonblocking, and allocation-light; heavier telemetry should be handed to application-owned
/// queues or tasks from inside the callback.
pub trait ConnectionObserver: Clone + Send + Sync + 'static {
    const ENABLE_TIMING: bool = false;
    const ENABLE_RECEIVE_TELEMETRY: bool = false;
    const ENABLE_RTCP: bool = false;

    fn connection_dropped(&self, _event: ConnectionEvent<'_>) {}

    fn connect_stage_completed(&self, _event: ConnectStageCompletedEvent<'_>) {}

    fn connect_stage_failed(&self, _event: ConnectStageFailedEvent<'_>) {}

    fn control_task_failed(&self, _event: ConnectionErrorEvent<'_>) {}

    fn websocket_command_failed(&self, _event: WebSocketCommandFailedEvent<'_>) {}

    fn websocket_text_event(&self, _event: WebSocketTextEvent<'_>) {}

    fn websocket_binary_event(&self, _event: WebSocketBinaryEvent<'_>) {}

    fn websocket_closed(&self, _event: WebSocketClosedEvent<'_>) {}

    fn websocket_read_failed(&self, _event: ConnectionErrorEvent<'_>) {}

    fn websocket_stream_ended(&self, _event: ConnectionEvent<'_>) {}

    fn udp_packet_received(&self, _event: UdpPacketReceivedEvent<'_>) {}

    fn udp_packet_sent(&self, _event: UdpPacketSentEvent<'_>) {}

    fn rtcp_packet_received(&self, _event: RtcpPacketEvent<'_>) {}

    fn clients_connected(&self, _event: ClientsConnectedEvent<'_>) {}

    fn dave_gateway_state(&self, _event: DaveGatewayStateEvent) {}

    fn dave_external_sender_set(&self, _event: DaveKeyPackageEvent) {}

    fn dave_key_package_sent(&self, _event: DaveKeyPackageEvent) {}

    fn dave_proposals_processed(&self, _event: DaveProposalsEvent) {}

    fn dave_proposals_ignored(&self, _event: DaveIgnoredProposalsEvent<'_>) {}

    fn dave_transition_ready_sent(&self, _event: DaveTransitionEvent) {}

    fn receive_rtp_packet(&self, _event: ReceiveRtpPacketEvent) {}

    fn receive_rtp_packet_loss(&self, _event: ReceiveRtpPacketLossEvent) {}

    fn receive_decode_error(&self, _event: ReceiveDecodeErrorEvent<'_>) {}

    fn receive_frame_dropped(&self, _event: ReceiveFrameDroppedEvent) {}

    fn dave_pending_media_enqueued(&self, _event: DavePendingMediaEvent) {}

    fn dave_pending_media_drained(&self, _event: DavePendingMediaEvent) {}

    fn dave_pending_media_dropped(&self, _event: DavePendingMediaEvent) {}
}

impl ConnectionObserver for NoopConnectionObserver {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
}

#[derive(Debug)]
pub struct ConnectionErrorEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub error: &'a dyn fmt::Debug,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSocketFrameKind {
    Text,
    Binary,
}

#[derive(Debug)]
pub struct WebSocketCommandFailedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub opcode: u64,
    pub frame_kind: WebSocketFrameKind,
    pub error: &'a dyn fmt::Debug,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebSocketTextEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub opcode: u64,
    pub seq: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebSocketBinaryEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub bytes: usize,
    pub first_byte: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketClosedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub frame: Option<WebSocketCloseFrame>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketCloseFrame {
    pub code: String,
    pub reason: String,
    pub discord_call_terminated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientsConnectedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub user_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectStage {
    WebSocketConnect,
    Hello,
    Ready,
    UdpDiscovery,
    SessionDescription,
}

impl ConnectStage {
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
pub struct ConnectStageCompletedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub stage: ConnectStage,
    pub elapsed: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectStageFailedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub stage: ConnectStage,
    pub elapsed: Duration,
    pub error: &'a Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPacketReceivedEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub bytes: usize,
    pub elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPacketSentEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub dave: bool,
    pub payload_bytes: usize,
    pub packet_bytes: usize,
    pub build_elapsed: Duration,
    pub send_elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtcpHeader {
    pub version: u8,
    pub padding: bool,
    pub report_count: u8,
    pub packet_type: u8,
    pub length_words: u16,
    pub ssrc: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtcpPacketEvent<'a> {
    pub endpoint: &'a str,
    pub guild_id: u64,
    pub user_id: u64,
    pub bytes: &'a [u8],
    pub header: Option<RtcpHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReceiveRtpPacketEvent {
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
pub struct ReceiveRtpPacketLossEvent {
    pub ssrc: u32,
    pub user_id: Option<u64>,
    pub first_seq: u16,
    pub last_seq: u16,
    pub missing_packets: u16,
    pub age_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveDecodeStage {
    Rtp,
    Codec,
    Transport,
    DaveFrame,
    DaveDecrypt,
    Opus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveDecodeErrorKind {
    MalformedRtp,
    UnsupportedCodec,
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

#[derive(Clone, Copy)]
pub struct DisplayValue<'a> {
    value: &'a dyn fmt::Display,
}

impl<'a> DisplayValue<'a> {
    pub fn new(value: &'a dyn fmt::Display) -> Self {
        Self { value }
    }
}

impl fmt::Debug for DisplayValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.value, formatter)
    }
}

impl fmt::Display for DisplayValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

impl Serialize for DisplayValue<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self.value)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ReceiveDecodeErrorEvent<'a> {
    pub stage: ReceiveDecodeStage,
    pub kind: ReceiveDecodeErrorKind,
    pub ssrc: Option<u32>,
    pub user_id: Option<u64>,
    pub seq: Option<u16>,
    pub detail: DisplayValue<'a>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReceiveDecodeContext {
    pub(crate) ssrc: Option<u32>,
    pub(crate) user_id: Option<u64>,
    pub(crate) seq: Option<u16>,
}

pub(crate) fn observe_receive_decode_error<O, E>(
    observer: &O,
    stage: ReceiveDecodeStage,
    kind: ReceiveDecodeErrorKind,
    context: ReceiveDecodeContext,
    error: &E,
) where
    O: ConnectionObserver,
    E: fmt::Display + ?Sized,
{
    if O::ENABLE_RECEIVE_TELEMETRY {
        observer.receive_decode_error(ReceiveDecodeErrorEvent {
            stage,
            kind,
            ssrc: context.ssrc,
            user_id: context.user_id,
            seq: context.seq,
            detail: DisplayValue::new(&error),
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveFrameDropReason {
    ReadyQueueOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReceiveFrameDroppedEvent {
    pub reason: ReceiveFrameDropReason,
    pub ssrc: Option<u32>,
    pub user_id: Option<u64>,
    pub seq: Option<u16>,
    pub queued_frames: usize,
    pub dropped_error: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DavePendingMediaReason {
    MissingUser,
    SessionNotReady,
    GatewayPending,
    DecryptStatePending,
    NoValidCryptorPending,
    StableDecryptFailure,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DavePendingMediaEvent {
    pub reason: DavePendingMediaReason,
    pub ssrc: u32,
    pub user_id: Option<u64>,
    pub seq: u16,
    pub pending_packets: usize,
    pub age_ms: u64,
}
