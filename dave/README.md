# dave

Discord DAVE media-frame transform primitives for Rust. `dave` implements the
end-to-end encryption layer used by Discord audio/video sessions: OpenMLS session
setup, gateway-facilitated proposal/commit/welcome processing, keyed media
ratchets, staged sender activation, passthrough windows, and typed frame
encryption/decryption errors.

The crate deliberately stops at the DAVE layer. It does not implement Discord
gateway IO, UDP/RTP transport, codec encode/decode, packetization,
depacketization, or runtime scheduling; those belong in a media runtime such as
`cacophony`.

## Features

- **Frame-transform API**: encrypt typed `MediaFrame<C: FrameCodec>` values and
  decrypt received protocol frames with caller-provided output buffers.
- **libdave codec set**: send-side transforms for Opus audio plus VP8, VP9,
  H264, H265, and AV1 video; receive-side parsing is codec-agnostic.
- **DAVE transition model**: prepared target protocol state is separate from
  active sender media state, matching prepare/ready/execute gateway transitions.
- **Ratchet retention**: previous receive ratchets are retained for in-flight
  media during transitions and removed after their retention window.
- **Typed errors**: malformed frames, replayed nonces, missing key generations,
  AEAD failures, passthrough rejection, unsupported codecs, and missing
  decryptors are distinguishable.
- **Secret hygiene**: ratchet key material is stored in zeroizing containers.

## Codec support

The public frame API is codec typed:

- `Opus`: fully encrypted audio frames, with the standard Discord Opus silence
  frame left unchanged.
- `Vp8`: packetizer-visible payload header bytes are authenticated but left
  unencrypted.
- `Vp9`: fully encrypted video frames.
- `H264` and `H265`: NAL start/header sections are authenticated but left
  unencrypted, with nonce retry when ciphertext would create packetizer-confusing
  start codes.
- `Av1`: packetizer-visible OBU headers are authenticated but left unencrypted,
  matching libdave's size-field rewrite behavior.

Receive-side parsing handles DAVE supplemental data, unencrypted ranges,
truncated nonces, and tags before reconstructing the decrypted encoded frame.

## Example

```rust
use std::num::NonZeroU16;

use dave::{DAVE_PROTOCOL_VERSION, MediaFrame, Opus, Session};

fn new_session(user_id: u64, channel_id: u64) -> Result<Session, dave::InitError> {
    Session::new(
        NonZeroU16::new(DAVE_PROTOCOL_VERSION).unwrap(),
        user_id,
        channel_id,
    )
}

fn opus_frame(bytes: &[u8]) -> MediaFrame<'_, Opus> {
    MediaFrame::<Opus>::new(bytes)
}
```

A caller is expected to drive the Discord voice gateway DAVE messages and call
the corresponding session methods (`set_external_sender`, `process_proposals`,
`process_welcome`, `process_commit`, and `activate_staged_sender`) at the
transition points required by the gateway.

## Related crates

- `cacophony`: high-performance Discord voice runtime built on top of `dave`.

## License

AGPL-3.0-only. See `LICENSE` for details.
