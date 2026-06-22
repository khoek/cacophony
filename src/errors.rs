use super::*;

#[derive(Debug)]
pub enum VoiceError {
    InvalidInput(String),
    Protocol(String),
    Timeout {
        stage: Option<VoiceConnectStage>,
        duration: Duration,
    },
    Io(std::io::Error),
    Json(serde_json::Error),
    WebSocket(tokio_tungstenite::tungstenite::Error),
    Opus(String),
    Dave(VoiceDaveError),
    Rtp(VoiceRtpError),
    TransportCrypto(VoiceTransportCryptoError),
    Backpressure(String),
    Closed,
    Join(String),
}

impl VoiceError {
    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub(crate) fn opus(message: impl Into<String>) -> Self {
        Self::Opus(message.into())
    }
}

impl fmt::Display for VoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => f.write_str(message),
            Self::Protocol(message) => f.write_str(message),
            Self::Timeout { stage, duration } => {
                if let Some(stage) = stage {
                    write!(f, "voice {} timed out after {duration:?}", stage.label())
                } else {
                    write!(f, "voice operation timed out after {duration:?}")
                }
            }
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            Self::WebSocket(error) => write!(f, "{error}"),
            Self::Opus(message) => f.write_str(message),
            Self::Dave(error) => write!(f, "{error}"),
            Self::Rtp(error) => write!(f, "{error}"),
            Self::TransportCrypto(error) => write!(f, "{error}"),
            Self::Backpressure(message) => f.write_str(message),
            Self::Closed => f.write_str("voice connection is closed"),
            Self::Join(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for VoiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::WebSocket(error) => Some(error),
            Self::Dave(error) => Some(error),
            Self::Rtp(error) => Some(error),
            Self::TransportCrypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VoiceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for VoiceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for VoiceError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(error)
    }
}

impl From<VoiceDaveError> for VoiceError {
    fn from(error: VoiceDaveError) -> Self {
        Self::Dave(error)
    }
}

impl From<VoiceRtpError> for VoiceError {
    fn from(error: VoiceRtpError) -> Self {
        Self::Rtp(error)
    }
}

impl From<VoiceTransportCryptoError> for VoiceError {
    fn from(error: VoiceTransportCryptoError) -> Self {
        Self::TransportCrypto(error)
    }
}

pub type VoiceResult<T> = Result<T, VoiceError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceRtpError {
    PacketTooShort {
        len: usize,
    },
    TruncatedCsrcList {
        len: usize,
        expected_header_len: usize,
    },
    TruncatedExtensionHeader {
        len: usize,
        expected_header_len: usize,
    },
    TruncatedExtensionPayload {
        len: usize,
        expected_header_len: usize,
    },
    TruncatedEncryptedExtension,
    EmptyPaddedPayload,
    InvalidPadding {
        padding: usize,
        payload_len: usize,
    },
}

impl fmt::Display for VoiceRtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { len } => {
                write!(f, "voice RTP packet is shorter than 12 bytes: {len}")
            }
            Self::TruncatedCsrcList {
                len,
                expected_header_len,
            } => write!(
                f,
                "voice RTP packet has truncated CSRC list: {len} bytes for {expected_header_len} byte header",
            ),
            Self::TruncatedExtensionHeader {
                len,
                expected_header_len,
            } => write!(
                f,
                "voice RTP packet has truncated extension header: {len} bytes for {expected_header_len} byte header",
            ),
            Self::TruncatedExtensionPayload {
                len,
                expected_header_len,
            } => write!(
                f,
                "voice RTP packet has truncated extension payload: {len} bytes for {expected_header_len} byte header",
            ),
            Self::TruncatedEncryptedExtension => {
                f.write_str("voice RTP packet has truncated encrypted extension")
            }
            Self::EmptyPaddedPayload => f.write_str("voice RTP packet has empty padded payload"),
            Self::InvalidPadding {
                padding,
                payload_len,
            } => write!(
                f,
                "voice RTP packet has invalid padding length {padding} for payload length {payload_len}",
            ),
        }
    }
}

impl std::error::Error for VoiceRtpError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceTransportCryptoError {
    InvalidSecretKeyLen {
        len: usize,
    },
    MissingRtpSizeNonce {
        packet_len: usize,
        min_len: usize,
    },
    InvalidAesGcmKey,
    InvalidXChaCha20Poly1305Key,
    AesGcmDecryptFailed,
    AesGcmEncryptFailed,
    XChaCha20Poly1305DecryptFailed,
    XChaCha20Poly1305EncryptFailed,
    UnsupportedMode {
        mode: VoiceEncryptionMode,
        direction: VoiceTransportCryptoDirection,
    },
}

impl fmt::Display for VoiceTransportCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKeyLen { len } => {
                write!(f, "voice secret_key must be 32 bytes, got {len}")
            }
            Self::MissingRtpSizeNonce {
                packet_len,
                min_len,
            } => write!(
                f,
                "voice RTP packet is missing the RTP-size nonce suffix: {packet_len} bytes for minimum {min_len}",
            ),
            Self::InvalidAesGcmKey => f.write_str("invalid AES-GCM voice secret key"),
            Self::InvalidXChaCha20Poly1305Key => {
                f.write_str("invalid XChaCha20-Poly1305 voice secret key")
            }
            Self::AesGcmDecryptFailed => f.write_str("failed to decrypt AES-GCM voice packet"),
            Self::AesGcmEncryptFailed => f.write_str("failed to encrypt AES-GCM voice packet"),
            Self::XChaCha20Poly1305DecryptFailed => {
                f.write_str("failed to decrypt XChaCha20-Poly1305 voice packet")
            }
            Self::XChaCha20Poly1305EncryptFailed => {
                f.write_str("failed to encrypt XChaCha20-Poly1305 voice packet")
            }
            Self::UnsupportedMode { mode, direction } => {
                write!(
                    f,
                    "unsupported voice encryption mode for {direction}: {mode:?}"
                )
            }
        }
    }
}

impl std::error::Error for VoiceTransportCryptoError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceTransportCryptoDirection {
    Send,
    Receive,
}

impl fmt::Display for VoiceTransportCryptoDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send => f.write_str("send"),
            Self::Receive => f.write_str("receive"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceDaveError {
    InvalidProtocolVersion { version: u16 },
    CreateSession { detail: String },
    SetExternalSender { detail: String },
    CreateKeyPackage { detail: String },
    ProcessProposals { detail: String },
    ProcessWelcome { detail: String },
    ProcessCommit { detail: String },
    RecoverInvalidGroup { detail: String },
    InvalidProposalsPayload { detail: String },
    Encrypt(VoiceDaveEncryptError),
    Decrypt(VoiceDaveDecryptError),
}

impl fmt::Display for VoiceDaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolVersion { version } => {
                write!(f, "unsupported DAVE protocol version {version}")
            }
            Self::CreateSession { detail } => write!(f, "failed to create DAVE session: {detail}"),
            Self::SetExternalSender { detail } => {
                write!(f, "failed to set DAVE external sender: {detail}")
            }
            Self::CreateKeyPackage { detail } => {
                write!(f, "failed to create DAVE key package: {detail}")
            }
            Self::ProcessProposals { detail } => {
                write!(f, "failed to process DAVE proposals: {detail}")
            }
            Self::ProcessWelcome { detail } => {
                write!(f, "failed to process DAVE welcome: {detail}")
            }
            Self::ProcessCommit { detail } => write!(f, "failed to process DAVE commit: {detail}"),
            Self::RecoverInvalidGroup { detail } => {
                write!(f, "failed to recover invalid DAVE group: {detail}")
            }
            Self::InvalidProposalsPayload { detail } => {
                write!(f, "invalid DAVE proposals payload: {detail}")
            }
            Self::Encrypt(error) => write!(f, "{error}"),
            Self::Decrypt(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for VoiceDaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encrypt(error) => Some(error),
            Self::Decrypt(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceDaveEncryptError {
    NotReady,
    EncryptionFailed,
}

impl fmt::Display for VoiceDaveEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => f.write_str("DAVE session is not ready to encrypt packets"),
            Self::EncryptionFailed => f.write_str("DAVE packet encryption failed"),
        }
    }
}

impl std::error::Error for VoiceDaveEncryptError {}

impl From<EncryptError> for VoiceDaveEncryptError {
    fn from(error: EncryptError) -> Self {
        match error {
            EncryptError::NotReady => Self::NotReady,
            EncryptError::EncryptionFailed => Self::EncryptionFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceDaveMediaType {
    Audio,
    Video,
}

impl fmt::Display for VoiceDaveMediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audio => f.write_str("audio"),
            Self::Video => f.write_str("video"),
        }
    }
}

impl From<MediaType> for VoiceDaveMediaType {
    fn from(media_type: MediaType) -> Self {
        match media_type {
            MediaType::AUDIO => Self::Audio,
            MediaType::VIDEO => Self::Video,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceDaveDecryptError {
    MissingUser,
    NoDecryptorForUser,
    NoValidCryptor {
        media_type: VoiceDaveMediaType,
        encrypted_size: usize,
        plaintext_size: usize,
        manager_count: usize,
    },
    UnencryptedWhenPassthroughDisabled,
}

impl VoiceDaveDecryptError {
    pub(crate) fn receive_decode_kind(&self) -> VoiceReceiveDecodeErrorKind {
        match self {
            Self::MissingUser => VoiceReceiveDecodeErrorKind::MissingDaveUser,
            Self::NoDecryptorForUser => VoiceReceiveDecodeErrorKind::DaveNoDecryptorForUser,
            Self::NoValidCryptor { .. } => VoiceReceiveDecodeErrorKind::DaveNoValidCryptor,
            Self::UnencryptedWhenPassthroughDisabled => {
                VoiceReceiveDecodeErrorKind::DaveUnencryptedWhenPassthroughDisabled
            }
        }
    }
}

impl fmt::Display for VoiceDaveDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUser => f.write_str("DAVE frame decrypt requires mapped user_id"),
            Self::NoDecryptorForUser => f.write_str("DAVE user has no decryptor"),
            Self::NoValidCryptor {
                media_type,
                encrypted_size,
                plaintext_size,
                manager_count,
            } => write!(
                f,
                "no valid DAVE cryptor found for {media_type}, encrypted size {encrypted_size}, \
                 plaintext size {plaintext_size}, manager count {manager_count}",
            ),
            Self::UnencryptedWhenPassthroughDisabled => {
                f.write_str("DAVE frame was unencrypted while passthrough was disabled")
            }
        }
    }
}

impl std::error::Error for VoiceDaveDecryptError {}

impl From<DecryptError> for VoiceDaveDecryptError {
    fn from(error: DecryptError) -> Self {
        match error {
            DecryptError::NoDecryptorForUser => Self::NoDecryptorForUser,
            DecryptError::DecryptionFailed(
                DecryptorDecryptError::UnencryptedWhenPassthroughDisabled,
            ) => Self::UnencryptedWhenPassthroughDisabled,
            DecryptError::DecryptionFailed(DecryptorDecryptError::NoValidCryptorFound {
                media_type,
                encrypted_size,
                plaintext_size,
                manager_count,
            }) => Self::NoValidCryptor {
                media_type: media_type.into(),
                encrypted_size,
                plaintext_size,
                manager_count,
            },
        }
    }
}
