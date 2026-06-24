use std::{array::TryFromSliceError, num::NonZeroU16};

use openmls::{
    framing::errors::ProtocolMessageError,
    group::{
        CommitToPendingProposalsError, ExportSecretError, MergeCommitError,
        MergePendingCommitError, NewGroupError, ProcessMessageError, RemoveProposalError,
        WelcomeError,
    },
    prelude::{CryptoError, InvalidExtensionError, KeyPackageNewError, tls_codec},
};
use openmls_rust_crypto::MemoryStorageError;
use thiserror::Error as ThisError;

use crate::{DAVE_PROTOCOL_VERSION, frame::MediaType};

#[derive(Debug, ThisError)]
#[error("unsupported DAVE protocol version {0}; max supported is {DAVE_PROTOCOL_VERSION}")]
pub struct UnsupportedProtocolVersion(pub NonZeroU16);

#[derive(Debug, ThisError)]
pub enum InitError {
    #[error("{0}")]
    UnsupportedProtocolVersion(#[from] UnsupportedProtocolVersion),
    #[error("failed to generate signature key pair: {0}")]
    KeyPairGeneration(#[from] CryptoError),
}

#[derive(Debug, ThisError)]
pub enum SetExternalSenderError {
    #[error("cannot set external sender while session is active")]
    AlreadyInGroup,
    #[error("DAVE MLS storage lock is poisoned")]
    StoragePoisoned,
    #[error("failed to delete current MLS group: {0}")]
    DeleteGroup(#[from] MemoryStorageError),
    #[error("failed to deserialize external sender: {0}")]
    DeserializeExternalSender(#[from] tls_codec::Error),
    #[error("failed to create pending MLS group: {0}")]
    PendingGroup(#[from] PendingGroupError),
}

#[derive(Debug, ThisError)]
pub enum CreateKeyPackageError {
    #[error("failed to deserialize DAVE key-package lifetime: {0}")]
    DeserializeLifetime(tls_codec::Error),
    #[error("failed to build DAVE key package: {0}")]
    Build(#[from] KeyPackageNewError),
    #[error("failed to serialize DAVE key package: {0}")]
    Serialize(tls_codec::Error),
}

#[derive(Debug, ThisError)]
pub enum PendingGroupError {
    #[error("cannot create pending group without external sender")]
    NoExternalSender,
    #[error("failed to add external sender extension: {0}")]
    AddExternalSender(#[from] InvalidExtensionError),
    #[error("failed to create pending MLS group: {0}")]
    CreateGroup(#[from] NewGroupError<MemoryStorageError>),
}

#[derive(Debug, ThisError)]
pub enum ProcessProposalsError {
    #[error("cannot process DAVE proposals without an MLS group")]
    NoGroup,
    #[error("failed to deserialize proposal vector: {0}")]
    DeserializeProposalVector(tls_codec::Error),
    #[error("failed to deserialize MLS message: {0}")]
    DeserializeMessage(tls_codec::Error),
    #[error("message was not a public or private MLS message: {0}")]
    MessageNotPublicOrPrivate(#[from] ProtocolMessageError),
    #[error("failed to process MLS message: {0}")]
    ProcessMessage(#[from] ProcessMessageError<MemoryStorageError>),
    #[error("failed to convert credential content to user ID: {0}")]
    CredentialContent(TryFromSliceError),
    #[error("unexpected proposed user {0}")]
    UnexpectedUser(u64),
    #[error("failed to store pending proposal: {0}")]
    StorePendingProposal(MemoryStorageError),
    #[error("processed MLS message was not a proposal")]
    MessageNotProposal,
    #[error("failed to deserialize proposal reference: {0}")]
    DeserializeProposalRef(tls_codec::Error),
    #[error("failed to remove pending proposal: {0}")]
    RemovePendingProposal(#[from] RemoveProposalError<MemoryStorageError>),
    #[error("failed to clear pending commit: {0}")]
    ClearPendingCommit(MemoryStorageError),
    #[error("failed to commit pending proposals: {0}")]
    CommitPendingProposals(CommitToPendingProposalsError<MemoryStorageError>),
    #[error("failed to serialize DAVE commit: {0}")]
    SerializeCommit(tls_codec::Error),
    #[error("failed to serialize DAVE welcome: {0}")]
    SerializeWelcome(tls_codec::Error),
}

#[derive(Debug, ThisError)]
pub enum ProcessWelcomeError {
    #[error("cannot process DAVE welcome while already active in a group")]
    AlreadyInGroup,
    #[error("cannot process DAVE welcome without an external sender")]
    NoExternalSender,
    #[error("failed to deserialize DAVE welcome: {0}")]
    DeserializeWelcome(#[from] tls_codec::Error),
    #[error("failed to create staged welcome: {0}")]
    StageWelcome(#[from] WelcomeError<MemoryStorageError>),
    #[error("welcome did not contain external senders extension")]
    MissingExternalSenderExtension,
    #[error("welcome contained {0} external senders; expected exactly one")]
    InvalidExternalSenderCount(usize),
    #[error("welcome external sender does not match the gateway external sender")]
    UnexpectedExternalSender,
    #[error("failed to delete pending MLS group: {0}")]
    DeletePendingGroup(MemoryStorageError),
    #[error("failed to update media ratchets: {0}")]
    UpdateRatchets(#[from] UpdateRatchetsError),
}

#[derive(Debug, ThisError)]
pub enum ProcessCommitError {
    #[error("cannot process DAVE commit without an MLS group")]
    NoGroup,
    #[error("cannot process DAVE commit for a pending MLS group")]
    PendingGroup,
    #[error("failed to deserialize DAVE commit: {0}")]
    DeserializeCommit(tls_codec::Error),
    #[error("message was not a public or private MLS message: {0}")]
    MessageNotPublicOrPrivate(#[from] ProtocolMessageError),
    #[error("DAVE commit was for a different MLS group")]
    WrongGroup,
    #[error("failed to merge own pending commit: {0}")]
    MergePendingCommit(#[from] MergePendingCommitError<MemoryStorageError>),
    #[error("failed to merge staged commit: {0}")]
    MergeStagedCommit(#[from] MergeCommitError<MemoryStorageError>),
    #[error("failed to process MLS message: {0}")]
    ProcessMessage(#[from] ProcessMessageError<MemoryStorageError>),
    #[error("processed MLS message was not a staged commit")]
    MessageNotStagedCommit,
    #[error("failed to update media ratchets: {0}")]
    UpdateRatchets(#[from] UpdateRatchetsError),
}

#[derive(Debug, ThisError)]
pub enum UpdateRatchetsError {
    #[error("cannot derive DAVE media ratchets without an established MLS group")]
    NoEstablishedGroup,
    #[error("failed to export MLS secret: {0}")]
    ExportSecret(#[from] ExportSecretError),
    #[error("failed to convert member credential content to user ID: {0}")]
    MemberCredentialContent(TryFromSliceError),
    #[error("failed to derive ratchet secret")]
    DeriveSecret,
}

#[derive(Clone, Debug, ThisError, PartialEq, Eq)]
pub enum EncryptError {
    #[error("DAVE sender ratchet is not active")]
    SenderNotReady,
    #[error("unsupported codec {codec:?} for media type {media_type:?}")]
    UnsupportedCodec {
        media_type: MediaType,
        codec: crate::frame::Codec,
    },
    #[error("encrypted output buffer is too small: need {needed} bytes, got {available}")]
    OutputTooSmall { needed: usize, available: usize },
    #[error("failed to initialize AES-GCM cipher")]
    InvalidKey,
    #[error("AES-GCM encryption failed")]
    Aead,
    #[error("failed to encode DAVE frame supplemental data")]
    FrameEncoding,
    #[error("DAVE frame supplemental data is too large")]
    SupplementalDataTooLarge,
    #[error("encrypted DAVE frame failed codec validation after retrying nonces")]
    TooManyAttempts,
    #[error("DAVE ratchet key is unavailable")]
    MissingRatchetKey,
}

#[derive(Clone, Debug, ThisError, PartialEq, Eq)]
pub enum DecryptError {
    #[error("user {user_id} has no DAVE decryptor")]
    NoDecryptorForUser { user_id: u64 },
    #[error("{0}")]
    Frame(#[from] FrameDecryptError),
}

#[derive(Clone, Debug, ThisError, PartialEq, Eq)]
pub enum FrameDecryptError {
    #[error("frame was not encrypted and passthrough is disabled")]
    PassthroughDisabled,
    #[error("encrypted DAVE frame is malformed")]
    MalformedFrame,
    #[error("frame nonce has already been processed")]
    ReplayedNonce,
    #[error("DAVE frame references an unavailable key generation {generation}")]
    MissingCryptor { generation: u32 },
    #[error("AES-GCM authentication failed for DAVE frame generation {generation}")]
    Aead { generation: u32 },
    #[error(
        "no DAVE cryptor could decrypt {media_type:?} frame; encrypted size {encrypted_size}, plaintext buffer {plaintext_capacity}, managers {manager_count}"
    )]
    NoValidCryptor {
        media_type: MediaType,
        encrypted_size: usize,
        plaintext_capacity: usize,
        manager_count: usize,
    },
    #[error("decrypted output buffer is too small: need {needed} bytes, got {available}")]
    OutputTooSmall { needed: usize, available: usize },
    #[error("failed to initialize AES-GCM cipher")]
    InvalidKey,
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("{0}")]
    Init(#[from] InitError),
    #[error("{0}")]
    SetExternalSender(#[from] SetExternalSenderError),
    #[error("{0}")]
    CreateKeyPackage(#[from] CreateKeyPackageError),
    #[error("{0}")]
    ProcessProposals(#[from] ProcessProposalsError),
    #[error("{0}")]
    ProcessWelcome(#[from] ProcessWelcomeError),
    #[error("{0}")]
    ProcessCommit(#[from] ProcessCommitError),
    #[error("{0}")]
    Encrypt(#[from] EncryptError),
    #[error("{0}")]
    Decrypt(#[from] DecryptError),
}
