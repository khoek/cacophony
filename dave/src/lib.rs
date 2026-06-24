mod error;
mod frame;
mod gcm;
mod leb128;
mod ratchet;
mod session;

pub use error::{
    CreateKeyPackageError, DecryptError, EncryptError, Error, FrameDecryptError, InitError,
    ProcessCommitError, ProcessProposalsError, ProcessWelcomeError, SetExternalSenderError,
    UnsupportedProtocolVersion,
};
pub use frame::{
    Av1, Codec, DynamicMediaFrame, FrameCodec, H264, H265, MediaFrame, MediaType,
    OPUS_SILENCE_FRAME, Opus, Vp8, Vp9,
};
pub use session::{CommitWelcome, FrameEncryptResult, ProposalsOperation, Session, SessionStatus};

pub const DAVE_PROTOCOL_VERSION: u16 = 1;
