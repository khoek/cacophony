use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use openmls::{
    group::{ProcessMessageError, StageCommitError},
    prelude::{hash_ref::ProposalRef, tls_codec::Serialize, *},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    DAVE_PROTOCOL_VERSION,
    error::{
        CreateKeyPackageError, DecryptError, EncryptError, InitError, PendingGroupError,
        ProcessCommitError, ProcessProposalsError, ProcessWelcomeError, SetExternalSenderError,
        UnsupportedProtocolVersion, UpdateRatchetsError,
    },
    frame::{
        Codec, DynamicMediaFrame, FrameCodec, MediaFrame, MediaType, OPUS_SILENCE_FRAME,
        TypedMediaFrame, TypedMediaFrameVisitor,
    },
    ratchet::{Decryptor, Encryptor, HashRatchet},
};

const USER_MEDIA_KEY_BASE_LABEL: &str = "Discord Secure Frames v0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalsOperation {
    Append,
    Revoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameEncryptResult {
    Unchanged,
    Encrypted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Inactive,
    Pending,
    AwaitingResponse,
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitWelcome {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

pub struct Session {
    protocol_version: NonZeroU16,
    capabilities: Capabilities,
    user_id: u64,
    channel_id: u64,
    provider: OpenMlsRustCrypto,
    ciphersuite: Ciphersuite,
    group_id: GroupId,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    external_sender: Option<ExternalSender>,
    group: Option<MlsGroup>,
    status: SessionStatus,
    receive_ready: bool,
    sender: Encryptor,
    decryptors: HashMap<u64, Decryptor>,
    passthrough_until: Option<Instant>,
}

impl Session {
    pub fn new(
        protocol_version: NonZeroU16,
        user_id: u64,
        channel_id: u64,
    ) -> Result<Self, InitError> {
        let ciphersuite = protocol_version_to_ciphersuite(protocol_version)?;
        let capabilities = protocol_version_to_capabilities(protocol_version)?;
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())?;
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(user_id.to_be_bytes().into()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            protocol_version,
            capabilities,
            user_id,
            channel_id,
            provider: OpenMlsRustCrypto::default(),
            ciphersuite,
            group_id: GroupId::from_slice(&channel_id.to_be_bytes()),
            signer,
            credential_with_key,
            external_sender: None,
            group: None,
            status: SessionStatus::Inactive,
            receive_ready: false,
            sender: Encryptor::default(),
            decryptors: HashMap::new(),
            passthrough_until: Some(Instant::now()),
        })
    }

    pub fn protocol_version(&self) -> NonZeroU16 {
        self.protocol_version
    }

    pub fn user_id(&self) -> u64 {
        self.user_id
    }

    pub fn channel_id(&self) -> u64 {
        self.channel_id
    }

    pub fn status(&self) -> SessionStatus {
        self.status
    }

    pub fn receive_ready(&self) -> bool {
        self.receive_ready
    }

    pub fn sender_ready(&self) -> bool {
        self.sender.ready()
    }

    pub fn reset(&mut self) -> Result<(), SetExternalSenderError> {
        if let Some(mut group) = self.group.take() {
            group.delete(self.provider.storage())?;
        }
        self.provider
            .storage()
            .values
            .write()
            .map_err(|_| SetExternalSenderError::StoragePoisoned)?
            .clear();
        self.status = SessionStatus::Inactive;
        self.receive_ready = false;
        self.sender.reset();
        self.decryptors.clear();
        Ok(())
    }

    pub fn set_external_sender(&mut self, bytes: &[u8]) -> Result<(), SetExternalSenderError> {
        if matches!(
            self.status,
            SessionStatus::AwaitingResponse | SessionStatus::Active
        ) {
            return Err(SetExternalSenderError::AlreadyInGroup);
        }
        if let Some(mut group) = self.group.take() {
            group.delete(self.provider.storage())?;
        }
        self.external_sender = Some(ExternalSender::tls_deserialize_exact_bytes(bytes)?);
        self.create_pending_group()?;
        Ok(())
    }

    pub fn create_key_package(&mut self) -> Result<Vec<u8>, CreateKeyPackageError> {
        let lifetime = Lifetime::tls_deserialize_exact_bytes(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ])
        .map_err(CreateKeyPackageError::DeserializeLifetime)?;
        let key_package = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .leaf_node_capabilities(self.capabilities.clone())
            .key_package_lifetime(lifetime)
            .build(
                self.ciphersuite,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )?;
        key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(CreateKeyPackageError::Serialize)
    }

    pub fn process_proposals(
        &mut self,
        operation: ProposalsOperation,
        proposals: &[u8],
        expected_user_ids: Option<&[u64]>,
    ) -> Result<Option<CommitWelcome>, ProcessProposalsError> {
        let Some(group) = &mut self.group else {
            return Err(ProcessProposalsError::NoGroup);
        };
        let proposals: Vec<u8> = VLBytes::tls_deserialize_exact_bytes(proposals)
            .map_err(ProcessProposalsError::DeserializeProposalVector)?
            .into();
        let mut commit_adds_members = false;

        match operation {
            ProposalsOperation::Append => {
                let mut remaining = proposals.as_slice();
                while !remaining.is_empty() {
                    let (message, rest) = MlsMessageIn::tls_deserialize_bytes(remaining)
                        .map_err(ProcessProposalsError::DeserializeMessage)?;
                    remaining = rest;
                    let processed = group
                        .process_message(&self.provider, message.try_into_protocol_message()?)?;
                    let ProcessedMessageContent::ProposalMessage(proposal) =
                        processed.into_content()
                    else {
                        return Err(ProcessProposalsError::MessageNotProposal);
                    };
                    if let Proposal::Add(add) = proposal.proposal() {
                        let user_id = u64::from_be_bytes(
                            add.key_package()
                                .leaf_node()
                                .credential()
                                .serialized_content()
                                .try_into()
                                .map_err(ProcessProposalsError::CredentialContent)?,
                        );
                        if let Some(expected_user_ids) = expected_user_ids
                            && !expected_user_ids.contains(&user_id)
                        {
                            return Err(ProcessProposalsError::UnexpectedUser(user_id));
                        }
                        commit_adds_members = true;
                    }
                    group
                        .store_pending_proposal(self.provider.storage(), *proposal)
                        .map_err(ProcessProposalsError::StorePendingProposal)?;
                }
            }
            ProposalsOperation::Revoke => {
                let mut remaining = proposals.as_slice();
                while !remaining.is_empty() {
                    let (proposal_ref, rest) = ProposalRef::tls_deserialize_bytes(remaining)
                        .map_err(ProcessProposalsError::DeserializeProposalRef)?;
                    remaining = rest;
                    group.remove_pending_proposal(self.provider.storage(), &proposal_ref)?;
                }
            }
        }

        if group.pending_proposals().next().is_none() {
            group
                .clear_pending_commit(self.provider.storage())
                .map_err(ProcessProposalsError::ClearPendingCommit)?;
            if self.status == SessionStatus::AwaitingResponse {
                self.status = if self.receive_ready {
                    SessionStatus::Active
                } else {
                    SessionStatus::Pending
                };
            }
            return Ok(None);
        }
        if group.pending_commit().is_some() {
            group
                .clear_pending_commit(self.provider.storage())
                .map_err(ProcessProposalsError::ClearPendingCommit)?;
        }

        let (commit, welcome, _) = group
            .commit_to_pending_proposals(&self.provider, &self.signer)
            .map_err(ProcessProposalsError::CommitPendingProposals)?;
        self.status = SessionStatus::AwaitingResponse;
        let commit = commit
            .tls_serialize_detached()
            .map_err(ProcessProposalsError::SerializeCommit)?;
        let welcome = if commit_adds_members {
            let Some(welcome) = welcome else {
                return Ok(Some(CommitWelcome {
                    commit,
                    welcome: None,
                }));
            };
            let MlsMessageBodyOut::Welcome(welcome) = welcome.body() else {
                return Ok(Some(CommitWelcome {
                    commit,
                    welcome: None,
                }));
            };
            Some(
                welcome
                    .tls_serialize_detached()
                    .map_err(ProcessProposalsError::SerializeWelcome)?,
            )
        } else {
            None
        };
        Ok(Some(CommitWelcome { commit, welcome }))
    }

    pub fn process_welcome(&mut self, welcome: &[u8]) -> Result<(), ProcessWelcomeError> {
        if self.group.is_some() && self.status == SessionStatus::Active {
            return Err(ProcessWelcomeError::AlreadyInGroup);
        }
        let Some(external_sender) = &self.external_sender else {
            return Err(ProcessWelcomeError::NoExternalSender);
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let welcome = Welcome::tls_deserialize_exact_bytes(welcome)?;
        let staged = StagedWelcome::build_from_welcome(&self.provider, &config, welcome)?
            .replace_old_group()
            .build()?;
        let Some(external_senders) = staged.group_context().extensions().external_senders() else {
            return Err(ProcessWelcomeError::MissingExternalSenderExtension);
        };
        let [join_external_sender] = external_senders.as_slice() else {
            return Err(ProcessWelcomeError::InvalidExternalSenderCount(
                external_senders.as_slice().len(),
            ));
        };
        if join_external_sender != external_sender {
            return Err(ProcessWelcomeError::UnexpectedExternalSender);
        }
        let group = staged.into_group(&self.provider)?;
        if let Some(mut pending_group) = self.group.take() {
            pending_group
                .delete(self.provider.storage())
                .map_err(ProcessWelcomeError::DeletePendingGroup)?;
        }
        self.group = Some(group);
        self.activate_established_group()?;
        Ok(())
    }

    pub fn process_commit(&mut self, commit: &[u8]) -> Result<(), ProcessCommitError> {
        let Some(group) = &mut self.group else {
            return Err(ProcessCommitError::NoGroup);
        };
        if self.status == SessionStatus::Pending {
            return Err(ProcessCommitError::PendingGroup);
        }
        let message = MlsMessageIn::tls_deserialize_exact_bytes(commit)
            .map_err(ProcessCommitError::DeserializeCommit)?;
        let protocol_message = message.try_into_protocol_message()?;
        if protocol_message.group_id().as_slice() != self.group_id.as_slice() {
            return Err(ProcessCommitError::WrongGroup);
        }
        match group.process_message(&self.provider, protocol_message) {
            Ok(message) => {
                let ProcessedMessageContent::StagedCommitMessage(staged) = message.into_content()
                else {
                    return Err(ProcessCommitError::MessageNotStagedCommit);
                };
                group.merge_staged_commit(&self.provider, *staged)?;
            }
            Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)) => {
                group.merge_pending_commit(&self.provider)?;
            }
            Err(error) => return Err(ProcessCommitError::ProcessMessage(error)),
        }
        self.activate_established_group()?;
        Ok(())
    }

    pub fn activate_staged_sender(&mut self) -> bool {
        self.sender.activate_pending()
    }

    pub fn set_passthrough_mode(&mut self, enabled: bool, transition_expiry: Duration) {
        self.passthrough_until = if enabled {
            None
        } else {
            let expiry = Instant::now() + transition_expiry;
            Some(match self.passthrough_until {
                Some(old) => old.min(expiry),
                None => expiry,
            })
        };
        for decryptor in self.decryptors.values_mut() {
            decryptor.transition_to_passthrough(enabled, transition_expiry);
        }
    }

    pub fn encrypt_into<C>(
        &mut self,
        frame: MediaFrame<'_, C>,
        output: &mut Vec<u8>,
    ) -> Result<FrameEncryptResult, EncryptError>
    where
        C: FrameCodec,
    {
        self.encrypt_supported_into(frame, output)
    }

    pub fn encrypt_dynamic_into(
        &mut self,
        frame: DynamicMediaFrame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<FrameEncryptResult, EncryptError> {
        let media_type = frame.media_type;
        let codec = frame.codec;
        self.encrypt_typed_into(
            frame
                .typed()
                .ok_or(EncryptError::UnsupportedCodec { media_type, codec })?,
            output,
        )
    }

    fn encrypt_typed_into(
        &mut self,
        frame: TypedMediaFrame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<FrameEncryptResult, EncryptError> {
        frame.visit(&mut EncryptTypedFrame {
            session: self,
            output,
        })
    }

    fn encrypt_supported_into<C>(
        &mut self,
        frame: MediaFrame<'_, C>,
        output: &mut Vec<u8>,
    ) -> Result<FrameEncryptResult, EncryptError>
    where
        C: FrameCodec,
    {
        if C::MEDIA_TYPE == MediaType::Audio
            && C::CODEC == Codec::Opus
            && frame.payload() == OPUS_SILENCE_FRAME
        {
            output.clear();
            return Ok(FrameEncryptResult::Unchanged);
        }
        self.sender.encrypt_into(frame, output)?;
        Ok(FrameEncryptResult::Encrypted)
    }

    pub fn decrypt_into(
        &mut self,
        user_id: u64,
        media_type: MediaType,
        frame: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<usize, DecryptError> {
        let Some(decryptor) = self.decryptors.get_mut(&user_id) else {
            return Err(DecryptError::NoDecryptorForUser { user_id });
        };
        decryptor
            .decrypt(media_type, frame, output)
            .map_err(DecryptError::Frame)
    }

    pub fn decrypt(
        &mut self,
        user_id: u64,
        media_type: MediaType,
        frame: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut output = Vec::with_capacity(frame.len());
        let len = self.decrypt_into(user_id, media_type, frame, &mut output)?;
        output.truncate(len);
        Ok(output)
    }

    fn create_pending_group(&mut self) -> Result<(), PendingGroupError> {
        let Some(external_sender) = &self.external_sender else {
            return Err(PendingGroupError::NoExternalSender);
        };
        let config = MlsGroupCreateConfig::builder()
            .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(vec![
                external_sender.clone(),
            ]))?)
            .ciphersuite(self.ciphersuite)
            .capabilities(self.capabilities.clone())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        self.group = Some(MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            self.group_id.clone(),
            self.credential_with_key.clone(),
        )?);
        self.status = SessionStatus::Pending;
        Ok(())
    }

    fn activate_established_group(&mut self) -> Result<(), UpdateRatchetsError> {
        self.status = SessionStatus::Active;
        self.update_receive_ratchets_and_stage_sender()
    }

    fn update_receive_ratchets_and_stage_sender(&mut self) -> Result<(), UpdateRatchetsError> {
        let Some(group) = &self.group else {
            return Err(UpdateRatchetsError::NoEstablishedGroup);
        };
        let mut current_members = HashSet::new();
        for member in group.members() {
            let user_id = u64::from_be_bytes(
                member
                    .credential
                    .serialized_content()
                    .try_into()
                    .map_err(UpdateRatchetsError::MemberCredentialContent)?,
            );
            current_members.insert(user_id);
            if user_id == self.user_id() {
                continue;
            }
            let ratchet = self.key_ratchet(user_id)?;
            let passthrough_until = self.passthrough_until;
            self.decryptors
                .entry(user_id)
                .or_insert_with(|| Decryptor::with_passthrough_until(passthrough_until))
                .transition_to_ratchet(ratchet);
        }
        self.decryptors
            .retain(|user_id, _| current_members.contains(user_id));
        let sender_ratchet = self.key_ratchet(self.user_id())?;
        self.sender.stage_ratchet(sender_ratchet);
        self.receive_ready = true;
        Ok(())
    }

    fn key_ratchet(&self, user_id: u64) -> Result<HashRatchet, UpdateRatchetsError> {
        if self.status == SessionStatus::Pending {
            return Err(UpdateRatchetsError::NoEstablishedGroup);
        }
        let Some(group) = &self.group else {
            return Err(UpdateRatchetsError::NoEstablishedGroup);
        };
        Ok(HashRatchet::new(group.export_secret(
            self.provider.crypto(),
            USER_MEDIA_KEY_BASE_LABEL,
            &user_id.to_le_bytes(),
            16,
        )?))
    }
}

struct EncryptTypedFrame<'session, 'output> {
    session: &'session mut Session,
    output: &'output mut Vec<u8>,
}

impl<'a> TypedMediaFrameVisitor<'a> for EncryptTypedFrame<'_, '_> {
    type Output = Result<FrameEncryptResult, EncryptError>;

    fn visit<C>(&mut self, frame: MediaFrame<'a, C>) -> Self::Output
    where
        C: FrameCodec,
    {
        self.session.encrypt_supported_into(frame, self.output)
    }
}

fn protocol_version_to_ciphersuite(
    protocol_version: NonZeroU16,
) -> Result<Ciphersuite, UnsupportedProtocolVersion> {
    if protocol_version == DAVE_PROTOCOL_VERSION {
        Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
    } else {
        Err(UnsupportedProtocolVersion(protocol_version))
    }
}

fn protocol_version_to_capabilities(
    protocol_version: NonZeroU16,
) -> Result<Capabilities, UnsupportedProtocolVersion> {
    Ok(Capabilities::builder()
        .versions(vec![ProtocolVersion::Mls10])
        .ciphersuites(vec![protocol_version_to_ciphersuite(protocol_version)?])
        .extensions(vec![])
        .proposals(vec![])
        .credentials(vec![CredentialType::Basic])
        .build())
}
