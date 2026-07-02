# Cacophony

Rust Discord media workspace.

## Member crates

### `cacophony`

High-performance Discord voice runtime. This crate provides voice connection setup,
gateway and UDP/RTP transport, Opus playout, and integration with DAVE media
encryption.

### `dave`

DAVE media transform primitives. This crate implements Discord media-frame
encryption, MLS-driven session transitions, and keyed ratchets without including
transport, codec, or scheduling runtime concerns.

See `cacophony/README.md` and `dave/README.md` for package-specific details.
