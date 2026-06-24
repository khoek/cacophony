# dave

`dave` implements Discord DAVE primitives for Rust, including encrypted-frame
transform support for the codec set supported by Discord's libdave reference
implementation: Opus audio plus VP8, VP9, H264, H265, and AV1 video.

The crate owns the DAVE layer: OpenMLS session setup, proposal/welcome/commit
processing, keyed media ratchets, staged sender activation, passthrough windows, and
typed media-frame encryption/decryption errors.

It deliberately does not implement Discord gateway, UDP/RTP transport, codec
encoding/decoding, packetization, depacketization, or runtime scheduling. Those
belong in a media runtime such as `cacophony`.

## Design

- Media encryption is frame based: callers pass a typed
  `MediaFrame<C: FrameCodec>` such as `MediaFrame::<Opus>::new(bytes)`. A
  deliberate `DynamicMediaFrame` adapter exists for call sites that only know the
  codec at runtime.
- DAVE protocol transitions distinguish prepared target protocol state from active
  sender media state. Sender ratchets can be staged by MLS processing and activated
  when the gateway transition executes.
- Receive errors are typed, including malformed frames, replayed nonces, missing key
  generations, AEAD failures, passthrough rejection, and no-valid-cryptor cases.
- The hot path uses caller-provided output buffers and explicit
  `FrameEncryptResult` values, including unchanged Opus silence frames.

## Codec Support

The public API is media-frame generic and codec-typed. The implemented send-side
frame transforms are:

- `Opus`: fully encrypted audio frames, with the standard Opus silence frame left
  unchanged.
- `Vp8`: packetizer-visible payload header bytes authenticated but unencrypted.
- `Vp9`: fully encrypted video frames.
- `H264` and `H265`: NAL start/header sections authenticated but unencrypted, with
  nonce retry when ciphertext would create packetizer-confusing start codes.
- `Av1`: packetizer-visible OBU headers authenticated but unencrypted, matching
  libdave's size-field rewrite behaviour.

Receive-side parsing is frame-generic: it parses DAVE supplemental data,
unencrypted ranges, truncated nonces, and tags before reconstructing the decrypted
encoded frame.
