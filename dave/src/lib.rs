mod error;
mod frame;
mod gcm;
mod leb128;
mod ratchet;
mod session;

use std::num::NonZeroU16;

pub use error::{
    CreateKeyPackageError, DecryptError, EncryptError, Error, FrameDecryptError, InitError,
    ProcessCommitError, ProcessProposalsError, ProcessWelcomeError, SetExternalSenderError,
    UnsupportedProtocolVersion,
};
pub use frame::{
    Av1, Codec, DynamicMediaFrame, FrameCodec, H264, H265, MediaFrame, MediaType,
    OPUS_SILENCE_FRAME, Opus, Vp8, Vp9,
};
pub use session::{
    CommitWelcome, FrameEncryptResult, ProposalsOperation, Session, SessionStatus,
    validate_protocol_version,
};

pub const DAVE_PROTOCOL_VERSION: NonZeroU16 = NonZeroU16::new(1).unwrap();
