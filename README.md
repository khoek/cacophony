# cacophony

`cacophony` is a high-performance Discord voice transport for Rust, and is built for applications that want direct control over voice performance. It owns the low-level voice path: Discord voice gateway negotiation, UDP discovery, RTP packet construction, AEAD transport crypto, Opus encode/decode helpers, DAVE MLS coordination, and typed connection-state callbacks. Consumers provide a Discord voice session token/configuration and receive a `VoiceConnection` for sending Opus frames, receiving decrypted voice frames, and observing voice gateway state.

## Design

- **End-to-end Discord voice transport**: websocket identify/select-protocol, heartbeat handling, UDP discovery, RTP send/receive, frame assembly, and speaking state commands.
- **Modern encryption modes**: `aead_aes256_gcm_rtpsize` first, with `aead_xchacha20_poly1305_rtpsize` support when selected by Discord.
- **DAVE support**: protocol-version negotiation, prepare-transition, prepare-epoch, external sender, proposals, commit/welcome, transition-ready, Opus frame encryption/decryption, and reset-aware epoch handling.
- **Opus utilities**: 48 kHz stereo 20 ms PCM frame validation plus CBR Discord music encoding and caller-buffer decode helpers.
- **Typed observability**: the voice connection emits strongly typed observer callbacks through a generic `VoiceConnectionObserver`; applications can map those events into logs, metrics, traces, or tests without coupling `cacophony` to any tracing backend.

## Minimal Use

```rust
use cacophony::{
    VoiceResult,
    VoiceConnectionConfig,
    VoiceSpeakingFlags,
    connect_voice,
};

# async fn example() -> VoiceResult<()> {
let connection = connect_voice(VoiceConnectionConfig::new(
    guild_id,
    voice_channel_id,
    bot_user_id,
    session_id,
    voice_token,
    voice_endpoint,
)).await?;

connection.set_speaking(VoiceSpeakingFlags::MICROPHONE, 0)?;
let metadata = connection
    .send_opus_frame(&opus_bytes, std::time::Duration::from_millis(20))
    .await?;
assert_eq!(metadata.opus_bytes, opus_bytes.len());
# Ok(())
# }
```

Use `connect_voice_with_observer` when the application wants typed connection events without pulling logging or telemetry into the crate:

```rust
use cacophony::{
    VoiceResult,
    VoiceConnectionConfig,
    VoiceConnectionObserver,
    VoiceUdpPacketSentEvent,
    VoiceWebSocketClosedEvent,
    connect_voice_with_observer,
};

#[derive(Clone)]
struct Metrics;

impl VoiceConnectionObserver for Metrics {
    const ENABLE_TIMING: bool = true;

    fn websocket_closed(&self, event: VoiceWebSocketClosedEvent<'_>) {
        eprintln!("voice websocket closed: {:?}", event.frame);
    }

    fn udp_packet_sent(&self, event: VoiceUdpPacketSentEvent<'_>) {
        eprintln!("sent {} RTP bytes in {:?}", event.packet_bytes, event.send_elapsed);
    }
}

# async fn example() -> VoiceResult<()> {
let connection = connect_voice_with_observer(config, Metrics).await?;
# Ok(())
# }
```

## DAVE

DAVE state is owned by `VoiceConnection`. Applications send and receive Opus frames through the same media APIs regardless of whether Discord has DAVE enabled; the connection performs MLS coordination, frame encryption/decryption, and pending encrypted-media retries internally. The hot send path accepts owned `VoiceOpusFrame`/`Vec<u8>` payloads and returns compact RTP/size metadata; payload capture is left to callers that explicitly need it.
