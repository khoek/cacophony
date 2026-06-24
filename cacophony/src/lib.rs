use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream as TungsteniteWebSocketStream,
    tungstenite::{Message as WsMessage, handshake::client::Response as WebSocketResponse},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const WEBSOCKET_ADDRESS_STAGGER: Duration = Duration::from_millis(125);
const WEBSOCKET_ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_DESCRIPTION_TIMEOUT: Duration = Duration::from_secs(10);
const DAVE_SEND_MEDIA_READY_TIMEOUT: Duration = Duration::from_secs(20);
const AEAD_TAG_LEN: usize = 16;
const RTPSIZE_NONCE_LEN: usize = 4;
const RTP_VERSION: u8 = 2;
const JS_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

type GatewayWebSocketStream = TungsteniteWebSocketStream<MaybeTlsStream<TcpStream>>;
type GatewayWebSocketConnectResult = (GatewayWebSocketStream, WebSocketResponse);
type GatewayWebSocketRead = SplitStream<GatewayWebSocketStream>;
type GatewayWebSocketWrite = SplitSink<GatewayWebSocketStream, WsMessage>;

mod buffer;
mod connection;
mod dave;
mod errors;
mod gateway;
mod media;
mod observer;
pub mod opus;
pub mod pcm;
mod queue;
mod state;
mod stats;

pub use ::dave::MediaType;
pub use connection::{
    Connection, DurationDistribution, FrameStream, OpusPlayout, OpusPlayoutStats,
};
pub use dave::{
    DaveGatewayStateEvent, DaveIgnoredProposalsEvent, DaveKeyPackageEvent, DaveMediaStatus,
    DaveProposalsEvent, DaveTransitionEvent,
};
pub use errors::{
    BackpressureError, ConnectionJoinError, DaveDecryptError, DaveError, DaveGatewayPayloadError,
    DaveProposalsPayloadError, Error, InvalidInputError, OpusError, OpusOperation, PayloadKind,
    PcmError, ProtocolError, Result, RtpError, TransportCryptoDirection, TransportCryptoError,
    UnsupportedCodecError,
};
pub use gateway::{SpeakingFlags, SpeakingUpdate};
pub use media::{
    DecodedFrame, DecodedFrameMetadata, FrameRaw, NoRawPackets, OutboundPacket, ReceivedFrame,
};
pub use observer::{
    ClientsConnectedEvent, ConnectStage, ConnectStageCompletedEvent, ConnectStageFailedEvent,
    ConnectionErrorEvent, ConnectionEvent, ConnectionObserver, DavePendingMediaEvent,
    DavePendingMediaReason, NoopConnectionObserver, ReceiveDecodeErrorEvent,
    ReceiveDecodeErrorKind, ReceiveDecodeStage, ReceiveFrameDropReason, ReceiveFrameDroppedEvent,
    ReceiveRtpPacketEvent, ReceiveRtpPacketLossEvent, RtcpHeader, RtcpPacketEvent,
    UdpPacketReceivedEvent, UdpPacketSentEvent, WebSocketBinaryEvent, WebSocketCloseFrame,
    WebSocketClosedEvent, WebSocketCommandFailedEvent, WebSocketFrameKind, WebSocketTextEvent,
};
pub use state::{
    ConnectionConfig, ConnectionInfo, ConnectionOptions, ConnectionRequest, ConnectionState,
    ConnectionStateSnapshot, ConnectionTuning, DaveMlsState, DavePendingMlsState, DaveState,
    EncryptionMode, SessionState, ValidatedConnectionConfig,
};

pub mod low_level {
    pub use crate::gateway::{DiscordId, GatewayReady, UdpDiscoveryPacket};
    pub use crate::media::{
        EncryptedMediaCodec, MediaCodec, RawFramePackets, RawUdpPacket, RawUdpPacketInfo,
        RtpHeader, RtpPayload, RtpPayloadCodec,
    };
    pub use crate::state::SessionDescription;
}

#[cfg(test)]
mod tests;
