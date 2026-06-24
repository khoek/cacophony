# cacophony

High-performance Discord voice runtime for Rust. `cacophony` owns the Discord
voice transport path: voice gateway negotiation, UDP discovery, RTP send/receive,
AEAD transport crypto, Opus packet playout, DAVE coordination, and typed
connection observers.

It is designed for applications that need direct control over latency and media
flow without binding the runtime to a logging, metrics, bot-framework, or audio
pipeline stack.

## Features

- **Discord voice transport**: websocket identify/select-protocol, heartbeat,
  UDP discovery, RTP packet construction/parsing, speaking state commands, and
  close-aware async send/receive APIs.
- **Real-time Opus playout**: bounded driver-owned media sink, clocked 20 ms
  Discord Opus packet scheduling, stale-frame handling, and playout timing
  statistics.
- **Opus utilities**: PCM-to-Discord-Opus streaming/batch encoding, caller-buffer
  decode helpers, Ogg Opus capture, and explicit 48 kHz stereo frame validation.
- **DAVE integration**: protocol-version negotiation, MLS external sender,
  proposals, commit/welcome, transition-ready, staged sender activation, and
  pending encrypted-media retry.
- **Typed observability**: `ConnectionObserver` callbacks are generic, typed, and
  backend-agnostic. Leave them as `NoopConnectionObserver` for zero application
  telemetry work.
- **Compile-time raw capture policy**: normal receive returns compact media
  frames; raw UDP/RTP packet retention is selected explicitly with the `FrameRaw`
  type parameter.
- **Curated API boundary**: high-level connection/media types live at the crate
  root; protocol inspection types are grouped under `cacophony::low_level`.

## Current media support

`cacophony` currently supports Discord Opus voice media. The lower-level `dave`
crate implements the full DAVE frame transform codec set, but this runtime does
not yet expose Discord video packetization/depacketization or playout APIs.
Non-Opus Discord media is rejected explicitly.

## Example

```rust
use cacophony::{ConnectionConfig, Result};
use cacophony::opus::discord::Packet;

async fn play_one_packet(
    guild_id: u64,
    channel_id: u64,
    user_id: u64,
    session_id: String,
    token: String,
    endpoint: String,
    opus_packet: Vec<u8>,
) -> Result<()> {
    let connection = ConnectionConfig {
        guild_id,
        channel_id,
        user_id,
        session_id,
        token,
        endpoint,
    }
    .connect()
    .await?;

    let playout = connection.start_opus_playout().await?;
    playout.push_packet_owned(Packet {
        bytes: opus_packet,
        duration: std::time::Duration::from_millis(20),
    }).await?;

    let stats = playout.finish().await?;
    assert_eq!(stats.packets, 1);
    Ok(())
}
```

Use an observer when the application wants typed timing or protocol events
without wiring tracing into the runtime:

```rust
use cacophony::{
    ConnectionConfig, ConnectionObserver, Result, UdpPacketSentEvent,
    WebSocketClosedEvent,
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

async fn connect_with_metrics(config: ConnectionConfig) -> Result<()> {
    let connection = config.connect_with_observer(Metrics).await?;
    let _ = connection;
    Ok(())
}
```

Observer callbacks execute inline on the connection driver task. Keep them O(1),
nonblocking, and allocation-light; send expensive aggregation to application-owned
queues or tasks.

Raw packet retention is opt-in:

```rust
use cacophony::low_level::RawFramePackets;

async fn receive_with_raw_packets(
    config: cacophony::ConnectionConfig,
) -> cacophony::Result<()> {
    let connection = config
        .connect_with_observer_and_raw::<_, RawFramePackets>(cacophony::NoopConnectionObserver)
        .await?;
    let mut frames = connection.frame_stream(4096).await?;
    let frame = frames.recv().await?;
    eprintln!("captured {} RTP packet(s)", frame.raw.packets.len());
    Ok(())
}
```

## Related crates

- [`dave`](https://crates.io/crates/dave): Discord DAVE media-frame transform
  and MLS ratchet primitives used by `cacophony`.

## License

AGPL-3.0-only. See `LICENSE` for details.
