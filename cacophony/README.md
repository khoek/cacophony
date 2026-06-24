# cacophony

`cacophony` is a high-performance Discord voice transport for Rust, and is built for applications that want direct control over voice performance. It owns the low-level voice path: Discord voice gateway negotiation, UDP discovery, RTP packet construction, AEAD transport crypto, Opus encode/decode helpers, DAVE MLS coordination, and typed connection-state callbacks. Consumers provide a Discord voice session token/configuration and receive a `Connection` for sending Discord Opus packets through a bounded media sink, receiving decrypted voice frames, and observing voice gateway state.

## Design

- **End-to-end Discord voice transport**: websocket identify/select-protocol, heartbeat handling, UDP discovery, RTP send/receive, Opus voice frame assembly, and speaking state commands.
- **Modern encryption modes**: `aead_aes256_gcm_rtpsize` first, with `aead_xchacha20_poly1305_rtpsize` support when selected by Discord.
- **DAVE support**: protocol-version negotiation, prepare-transition, prepare-epoch, external sender, proposals, commit/welcome, transition-ready, currently supported Opus audio encryption/decryption, and reset-aware epoch handling.
- **Opus utilities**: 48 kHz stereo 20 ms PCM frame validation, CBR Discord Opus encoding with `Application::Audio` by default, and caller-buffer decode helpers.
- **Modular codec boundary**: codec-neutral RTP/transport code uses `RtpPayloadCodec` and `RtpPayload`; `cacophony::opus` is the only implemented codec module today, and non-Opus Discord media is intentionally unsupported.
- **Typed observability**: the voice connection emits strongly typed observer callbacks through a generic `ConnectionObserver`; applications can map those events into logs, metrics, traces, or tests without coupling `cacophony` to any tracing backend.
- **Compile-time receive policy**: normal media receive returns compact frame metadata and bytes; raw UDP/RTP packet retention is selected explicitly with the `FrameRaw` type parameter.
- **Curated public surface**: high-level connection, media, Opus, DAVE status, and observer types are reexported at the crate root; protocol diagnostics such as raw UDP packet snapshots live under `cacophony::low_level`.

## Minimal Use

```rust
use cacophony::{
    Result,
    ConnectionConfig,
    connect,
};
use cacophony::opus::discord::Packet;

# async fn example() -> Result<()> {
let connection = connect(ConnectionConfig::new(
    guild_id,
    channel_id,
    bot_user_id,
    session_id,
    token,
    endpoint,
)).await?;

let playout = connection.start_opus_playout().await?;
playout.push_packet_owned(Packet {
    bytes: opus_bytes,
    duration: std::time::Duration::from_millis(20),
}).await?;
let stats = playout.finish().await?;
assert_eq!(stats.packets, 1);
# Ok(())
# }
```

Use `connect_with_observer` when the application wants typed connection events without pulling logging or telemetry into the crate:

```rust
use cacophony::{
    Result,
    ConnectionConfig,
    ConnectionObserver,
    UdpPacketSentEvent,
    WebSocketClosedEvent,
    connect_with_observer,
};

#[derive(Clone)]
struct Metrics;

impl ConnectionObserver for Metrics {
    const ENABLE_TIMING: bool = true;

    fn websocket_closed(&self, event: WebSocketClosedEvent<'_>) {
        eprintln!("voice websocket closed: {:?}", event.frame);
    }

    fn udp_packet_sent(&self, event: UdpPacketSentEvent<'_>) {
        eprintln!("sent {} RTP bytes in {:?}", event.packet_bytes, event.send_elapsed);
    }
}

# async fn example() -> Result<()> {
let connection = connect_with_observer(config, Metrics).await?;
# Ok(())
# }
```

Observer callbacks execute inline on the connection driver task. Keep them O(1), nonblocking, and allocation-light; hand expensive aggregation to application-owned queues or tasks.

Use `connect_with_observer_and_raw` only when diagnostics need raw packet retention on received media frames:

```rust
use cacophony::{
    RawFramePackets,
    connect_with_observer_and_raw,
};

# async fn example(config: cacophony::ConnectionConfig) -> cacophony::Result<()> {
let connection = connect_with_observer_and_raw::<_, RawFramePackets>(
    config,
    cacophony::NoopConnectionObserver,
).await?;
let frame = connection.recv_voice_frame(4096).await?;
eprintln!("captured {} packet(s)", frame.raw.packets.len());
# Ok(())
# }
```

## DAVE

DAVE state is owned by `Connection`. Applications send and receive Opus media through the same media APIs regardless of whether Discord has DAVE enabled; the connection performs MLS coordination, supported Opus audio encryption/decryption, and pending encrypted-media retries internally. The hot send path accepts owned `opus::discord::Packet` values or borrowed packet bytes with explicit duration; payload capture is left to callers that explicitly need it.
