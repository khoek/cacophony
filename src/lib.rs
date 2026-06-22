use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};
use serde_json::Value;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot, watch},
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
const RTP_REORDER_TTL: Duration = Duration::from_millis(60);
const RTP_REORDER_BUFFER_MAX_FRAMES: usize = 32;
const VOICE_UDP_PACKET_MAX_BYTES: usize = 4096;
const VOICE_READY_FRAME_BUFFER_MAX: usize = 4096;

type VoiceWebSocketStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type VoiceWebSocketConnectResult = (VoiceWebSocketStream, WebSocketResponse);
type VoiceWebSocketRead = SplitStream<VoiceWebSocketStream>;
type VoiceWebSocketWrite = SplitSink<VoiceWebSocketStream, WsMessage>;

mod connection;
mod dave;
mod errors;
mod gateway;
mod media;
mod observer;
mod state;

pub use connection::*;
pub use dave::*;
pub use errors::*;
pub use gateway::*;
pub use media::*;
pub use observer::*;
pub use state::*;

#[cfg(test)]
mod tests;
