use std::collections::{HashMap, HashSet};

use openmls::{
    group::{ProcessMessageError, StageCommitError},
    prelude::{hash_ref::ProposalRef, tls_codec::Serialize, *},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    DAVE_PROTOCOL_VERSION, DaveProtocolVersion,
    error::{
        CreateKeyPackageError, CredentialPolicyError, DecryptError, EncryptError, GroupPolicyError,
        InitError, PendingGroupError, ProcessCommitError, ProcessProposalsError,
        ProcessWelcomeError, SetExternalSenderError, UpdateRatchetsError, VerificationError,
    },
    frame::{
        DynamicMediaFrame, FrameCodec, MediaFrame, MediaType, TypedMediaFrame,
        TypedMediaFrameVisitor,
    },
    identity::{
        IdentityPublicKey, SessionIdentity, epoch_authenticator_display_code, pairwise_fingerprint,
    },
    passthrough::{PassthroughMode, PlaintextPassthrough},
    ratchet::{Decryptor, Encryptor, HashRatchet},
};

const USER_MEDIA_KEY_BASE_LABEL: &str = "Discord Secure Frames v0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalsOperation {
    Append,
    Revoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Inactive,
    Pending,
    AwaitingInitialResponse,
    AwaitingCommit,
    Active,
}

pub trait ExpectedUserIds {
    fn contains_user_id(&self, user_id: u64) -> bool;
}

impl ExpectedUserIds for HashSet<u64> {
    fn contains_user_id(&self, user_id: u64) -> bool {
        self.contains(&user_id)
    }
}

impl ExpectedUserIds for [u64] {
    fn contains_user_id(&self, user_id: u64) -> bool {
        self.contains(&user_id)
    }
}

impl<const N: usize> ExpectedUserIds for [u64; N] {
    fn contains_user_id(&self, user_id: u64) -> bool {
        self.contains(&user_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitWelcome {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

pub struct Session {
    capabilities: Capabilities,
    user_id: u64,
    channel_id: u64,
    provider: OpenMlsRustCrypto,
    ciphersuite: Ciphersuite,
    group_id: GroupId,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    external_sender: Option<ExternalSender>,
    group: Option<SessionGroup>,
    status: SessionStatus,
    receive_ready: bool,
    sender: Encryptor,
    decryptors: HashMap<u64, Decryptor>,
    passthrough: PlaintextPassthrough,
    pending_commit: Option<Vec<u8>>,
}

struct SessionGroup {
    group: MlsGroup,
    state: SessionGroupState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionGroupState {
    Pending,
    Established,
}

impl SessionGroup {
    fn pending(group: MlsGroup) -> Self {
        Self {
            group,
            state: SessionGroupState::Pending,
        }
    }

    fn established(group: MlsGroup) -> Self {
        Self {
            group,
            state: SessionGroupState::Established,
        }
    }

    fn is_pending(&self) -> bool {
        self.state == SessionGroupState::Pending
    }

    fn is_established(&self) -> bool {
        self.state == SessionGroupState::Established
    }

    fn establish(&mut self) {
        self.state = SessionGroupState::Established;
    }
}

#[derive(Debug, Default)]
pub struct SessionOptions {
    pub identity: SessionIdentity,
}

#[derive(Debug)]
pub struct SessionConfig {
    pub self_user_id: u64,
    pub channel_id: u64,
    pub options: SessionOptions,
}

impl Session {
    pub fn new(config: SessionConfig) -> Result<Self, InitError> {
        let ciphersuite = supported_ciphersuite();
        let capabilities = supported_capabilities();
        let signer = match config.options.identity {
            SessionIdentity::Ephemeral => SignatureKeyPair::new(ciphersuite.signature_algorithm())?,
            SessionIdentity::KeyPair(key_pair) => key_pair.into_signer(),
        };
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(config.self_user_id.to_be_bytes().into()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            capabilities,
            user_id: config.self_user_id,
            channel_id: config.channel_id,
            provider: OpenMlsRustCrypto::default(),
            ciphersuite,
            group_id: GroupId::from_slice(&config.channel_id.to_be_bytes()),
            signer,
            credential_with_key,
            external_sender: None,
            group: None,
            status: SessionStatus::Inactive,
            receive_ready: false,
            sender: Encryptor::default(),
            decryptors: HashMap::new(),
            passthrough: PlaintextPassthrough::disabled(),
            pending_commit: None,
        })
    }

    pub fn protocol_version(&self) -> DaveProtocolVersion {
        DAVE_PROTOCOL_VERSION
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

    pub fn local_identity_public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            user_id: self.user_id,
            public_key: self.signer.public().to_vec(),
        }
    }

    pub fn participant_identity_public_keys(
        &self,
    ) -> Result<Vec<IdentityPublicKey>, VerificationError> {
        let group = self.established_group_for_verification()?;
        group
            .group
            .members()
            .map(|member| {
                Ok(IdentityPublicKey {
                    user_id: Self::credential_user_id(&member.credential)?,
                    public_key: member.signature_key,
                })
            })
            .collect()
    }

    pub fn epoch_authenticator(&self) -> Result<Vec<u8>, VerificationError> {
        Ok(self
            .established_group_for_verification()?
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec())
    }

    pub fn epoch_authenticator_display_code(&self) -> Result<String, VerificationError> {
        Ok(epoch_authenticator_display_code(
            &self.epoch_authenticator()?,
        )?)
    }

    pub fn pairwise_fingerprint(
        &self,
        remote: &IdentityPublicKey,
    ) -> Result<[u8; crate::PAIRWISE_FINGERPRINT_BYTES], VerificationError> {
        Ok(pairwise_fingerprint(
            &self.local_identity_public_key(),
            remote,
        )?)
    }

    pub fn reset(&mut self) -> Result<(), SetExternalSenderError> {
        if let Some(mut group) = self.group.take() {
            group.group.delete(self.provider.storage())?;
        }
        self.provider
            .storage()
            .values
            .write()
            .map_err(|_| SetExternalSenderError::StoragePoisoned)?
            .clear();
        self.status = SessionStatus::Inactive;
        self.reset_media_transform_state();
        self.pending_commit = None;
        Ok(())
    }

    pub fn reset_media_transform_state(&mut self) {
        self.receive_ready = false;
        self.sender.reset();
        self.decryptors.clear();
        self.passthrough = PlaintextPassthrough::disabled();
    }

    pub fn set_external_sender(&mut self, bytes: &[u8]) -> Result<(), SetExternalSenderError> {
        if self
            .group
            .as_ref()
            .is_some_and(SessionGroup::is_established)
        {
            return Err(SetExternalSenderError::AlreadyInGroup);
        }
        if let Some(mut group) = self.group.take() {
            group.group.delete(self.provider.storage())?;
        }
        self.external_sender = Some(ExternalSender::tls_deserialize_exact_bytes(bytes)?);
        self.pending_commit = None;
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

    pub fn process_proposals<E>(
        &mut self,
        operation: ProposalsOperation,
        proposals: &[u8],
        expected_user_ids: &E,
    ) -> Result<Option<CommitWelcome>, ProcessProposalsError>
    where
        E: ExpectedUserIds + ?Sized,
    {
        let Some(group_state) = &mut self.group else {
            return Err(ProcessProposalsError::NoGroup);
        };
        let group_was_established = group_state.is_established();
        let group = &mut group_state.group;
        let proposals: Vec<u8> = VLBytes::tls_deserialize_exact_bytes(proposals)
            .map_err(ProcessProposalsError::DeserializeProposalVector)?
            .into();
        let mut commit_adds_members = false;

        match operation {
            ProposalsOperation::Append => {
                let mut remaining = proposals.as_slice();
                let mut validated_proposals = Vec::new();
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
                    if Self::validate_gateway_proposal(&proposal, expected_user_ids)? {
                        commit_adds_members = true;
                    }
                    validated_proposals.push(*proposal);
                }
                for proposal in validated_proposals {
                    group
                        .store_pending_proposal(self.provider.storage(), proposal)
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
            self.pending_commit = None;
            self.status = match self.status {
                SessionStatus::AwaitingCommit => SessionStatus::Active,
                SessionStatus::AwaitingInitialResponse => SessionStatus::Pending,
                status => status,
            };
            return Ok(None);
        }
        if group.pending_commit().is_some() {
            group
                .clear_pending_commit(self.provider.storage())
                .map_err(ProcessProposalsError::ClearPendingCommit)?;
            self.pending_commit = None;
        }

        let (commit, welcome, _) = group
            .commit_to_pending_proposals(&self.provider, &self.signer)
            .map_err(ProcessProposalsError::CommitPendingProposals)?;
        self.status = if group_was_established {
            SessionStatus::AwaitingCommit
        } else {
            SessionStatus::AwaitingInitialResponse
        };
        let commit = commit
            .tls_serialize_detached()
            .map_err(ProcessProposalsError::SerializeCommit)?;
        self.pending_commit = Some(commit.clone());
        let welcome = if let (true, Some(welcome)) = (commit_adds_members, welcome) {
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
        if self
            .group
            .as_ref()
            .is_some_and(SessionGroup::is_established)
        {
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
        Self::validate_group_context_policy(staged.group_context(), external_sender)?;
        Self::validate_group_member_policy(staged.members())?;
        let group = staged.into_group(&self.provider)?;
        Self::validate_group_policy(&group, external_sender)?;
        if let Some(mut pending_group) = self.group.take() {
            pending_group
                .group
                .delete(self.provider.storage())
                .map_err(ProcessWelcomeError::DeletePendingGroup)?;
        }
        self.group = Some(SessionGroup::established(group));
        self.pending_commit = None;
        self.activate_established_group()?;
        Ok(())
    }

    pub fn process_commit(&mut self, commit: &[u8]) -> Result<(), ProcessCommitError> {
        let external_sender = match (&self.group, &self.external_sender) {
            (None, _) => return Err(ProcessCommitError::NoGroup),
            (_, None) => return Err(ProcessCommitError::NoExternalSender),
            (_, Some(external_sender)) => external_sender.clone(),
        };
        let pending_commit_matches = self.pending_commit.as_deref() == Some(commit);
        let was_pending = {
            let Some(group_state) = &mut self.group else {
                return Err(ProcessCommitError::NoGroup);
            };
            let was_pending = group_state.is_pending();
            if was_pending && self.status == SessionStatus::Pending {
                return Err(ProcessCommitError::PendingGroup);
            }
            let group = &mut group_state.group;
            let message = MlsMessageIn::tls_deserialize_exact_bytes(commit)
                .map_err(ProcessCommitError::DeserializeCommit)?;
            let protocol_message = message.try_into_protocol_message()?;
            if protocol_message.group_id().as_slice() != self.group_id.as_slice() {
                return Err(ProcessCommitError::WrongGroup);
            }
            match group.process_message(&self.provider, protocol_message) {
                Ok(message) => {
                    let sender = message.sender().clone();
                    let ProcessedMessageContent::StagedCommitMessage(staged) =
                        message.into_content()
                    else {
                        return Err(ProcessCommitError::MessageNotStagedCommit);
                    };
                    Self::validate_staged_commit(group, &external_sender, &sender, &staged)?;
                    group.merge_staged_commit(&self.provider, *staged)?;
                }
                Err(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)) => {
                    if !pending_commit_matches {
                        return Err(ProcessCommitError::UnexpectedOwnCommit);
                    }
                    if let Some(staged) = group.pending_commit() {
                        Self::validate_staged_commit(
                            group,
                            &external_sender,
                            &Sender::Member(group.own_leaf_index()),
                            staged,
                        )?;
                    }
                    group.merge_pending_commit(&self.provider)?;
                }
                Err(error) => return Err(ProcessCommitError::ProcessMessage(error)),
            }
            was_pending
        };
        self.pending_commit = None;
        if was_pending && let Some(group) = &mut self.group {
            group.establish();
        }
        if let Some(group) = &self.group {
            Self::validate_group_policy(&group.group, &external_sender)?;
        }
        self.activate_established_group()?;
        Ok(())
    }

    pub fn activate_staged_sender(&mut self) -> bool {
        self.sender.activate_pending()
    }

    #[cfg(test)]
    fn external_sender_for_test(&self) -> Vec<u8> {
        ExternalSender::new(
            self.signer.public().into(),
            self.credential_with_key.credential.clone(),
        )
        .tls_serialize_detached()
        .unwrap()
    }

    pub fn set_passthrough_mode(&mut self, mode: PassthroughMode) {
        self.passthrough.apply(mode);
        for decryptor in self.decryptors.values_mut() {
            decryptor.transition_to_passthrough(mode);
        }
    }

    pub fn encrypt_into<C>(
        &mut self,
        frame: MediaFrame<'_, C>,
        output: &mut Vec<u8>,
    ) -> Result<(), EncryptError>
    where
        C: FrameCodec,
    {
        self.encrypt_supported_into(frame, output)
    }

    pub fn encrypt_dynamic_into(
        &mut self,
        frame: DynamicMediaFrame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<(), EncryptError> {
        self.encrypt_typed_into(frame.typed(), output)
    }

    fn encrypt_typed_into(
        &mut self,
        frame: TypedMediaFrame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<(), EncryptError> {
        frame.visit(&mut EncryptTypedFrame {
            session: self,
            output,
        })
    }

    fn encrypt_supported_into<C>(
        &mut self,
        frame: MediaFrame<'_, C>,
        output: &mut Vec<u8>,
    ) -> Result<(), EncryptError>
    where
        C: FrameCodec,
    {
        self.sender.encrypt_into(frame, output)?;
        Ok(())
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
        self.group = Some(SessionGroup::pending(MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            self.group_id.clone(),
            self.credential_with_key.clone(),
        )?));
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
        if !group.is_established() {
            return Err(UpdateRatchetsError::NoEstablishedGroup);
        }
        let mut current_members = HashSet::new();
        for member in group.group.members() {
            let user_id = Self::member_user_id(&member)?;
            current_members.insert(user_id);
            if user_id == self.user_id() {
                continue;
            }
            let ratchet = self.key_ratchet(user_id)?;
            let passthrough = PlaintextPassthrough::from_until(self.passthrough.until());
            self.decryptors
                .entry(user_id)
                .or_insert_with(|| Decryptor::with_plaintext_passthrough(passthrough))
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
        if !self
            .group
            .as_ref()
            .is_some_and(SessionGroup::is_established)
        {
            return Err(UpdateRatchetsError::NoEstablishedGroup);
        }
        let Some(group) = &self.group else {
            return Err(UpdateRatchetsError::NoEstablishedGroup);
        };
        Ok(HashRatchet::new(group.group.export_secret(
            self.provider.crypto(),
            USER_MEDIA_KEY_BASE_LABEL,
            &user_id.to_le_bytes(),
            16,
        )?))
    }

    fn validate_gateway_proposal<E>(
        proposal: &QueuedProposal,
        expected_user_ids: &E,
    ) -> Result<bool, ProcessProposalsError>
    where
        E: ExpectedUserIds + ?Sized,
    {
        if proposal.sender() != &Sender::External(SenderExtensionIndex::new(0)) {
            return Err(ProcessProposalsError::UnexpectedProposalSender);
        }
        match proposal.proposal() {
            Proposal::Add(add) => {
                Self::validate_leaf_node_policy(add.key_package().leaf_node())?;
                let user_id = Self::credential_user_id(add.key_package().leaf_node().credential())?;
                if !expected_user_ids.contains_user_id(user_id) {
                    return Err(ProcessProposalsError::UnexpectedUser(user_id));
                }
                Ok(true)
            }
            Proposal::Remove(_) => Ok(false),
            _ => Err(ProcessProposalsError::UnexpectedProposalType),
        }
    }

    fn validate_staged_commit(
        group: &MlsGroup,
        external_sender: &ExternalSender,
        sender: &Sender,
        staged: &StagedCommit,
    ) -> Result<(), ProcessCommitError> {
        for proposal in staged.queued_proposals() {
            if proposal.proposal_or_ref_type() != ProposalOrRefType::Reference {
                return Err(ProcessCommitError::InlineProposal);
            }
            match proposal.proposal() {
                Proposal::Add(add) => {
                    Self::validate_leaf_node_policy(add.key_package().leaf_node())?
                }
                Proposal::Remove(_) => {}
                _ => return Err(ProcessCommitError::UnexpectedProposalType),
            }
        }
        if let Some(leaf_node) = staged.update_path_leaf_node() {
            Self::validate_leaf_node_policy(leaf_node)?;
        }
        Self::validate_group_context_policy(staged.group_context(), external_sender)?;
        Self::validate_resulting_member_credentials(group, sender, staged)
    }

    fn validate_resulting_member_credentials(
        group: &MlsGroup,
        sender: &Sender,
        staged: &StagedCommit,
    ) -> Result<(), ProcessCommitError> {
        let removed_members: HashSet<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|proposal| proposal.remove_proposal().removed())
            .collect();
        let update_path_member = if let Some(leaf_node) = staged.update_path_leaf_node() {
            let Sender::Member(member) = sender else {
                return Err(ProcessCommitError::UnexpectedCommitSender);
            };
            Some((*member, Self::credential_user_id(leaf_node.credential())?))
        } else {
            None
        };

        let mut user_ids =
            Vec::with_capacity(group.members().count() + staged.add_proposals().count());
        for member in group.members() {
            if removed_members.contains(&member.index) {
                continue;
            }
            let user_id = match update_path_member {
                Some((leaf_index, user_id)) if leaf_index == member.index => user_id,
                _ => Self::credential_user_id(&member.credential)?,
            };
            user_ids.push(user_id);
        }
        for add in staged.add_proposals() {
            user_ids.push(Self::credential_user_id(
                add.add_proposal().key_package().leaf_node().credential(),
            )?);
        }
        Self::ensure_distinct_user_ids(user_ids)
    }

    fn ensure_distinct_user_ids(
        user_ids: impl IntoIterator<Item = u64>,
    ) -> Result<(), ProcessCommitError> {
        let mut seen = HashSet::new();
        for user_id in user_ids {
            if !seen.insert(user_id) {
                return Err(ProcessCommitError::GroupPolicy(
                    GroupPolicyError::DuplicateMemberCredential(user_id),
                ));
            }
        }
        Ok(())
    }

    fn validate_group_policy(
        group: &MlsGroup,
        external_sender: &ExternalSender,
    ) -> Result<(), GroupPolicyError> {
        if group.ciphersuite() != supported_ciphersuite() {
            return Err(GroupPolicyError::UnexpectedCiphersuite {
                actual: group.ciphersuite(),
                expected: supported_ciphersuite(),
            });
        }
        Self::validate_group_context_extensions(group.extensions(), external_sender)?;
        Self::validate_group_member_policy(group.members())
    }

    fn validate_group_context_policy(
        context: &GroupContext,
        external_sender: &ExternalSender,
    ) -> Result<(), GroupPolicyError> {
        if context.protocol_version() != ProtocolVersion::Mls10 {
            return Err(GroupPolicyError::UnexpectedProtocolVersion {
                actual: context.protocol_version(),
            });
        }
        if context.ciphersuite() != supported_ciphersuite() {
            return Err(GroupPolicyError::UnexpectedCiphersuite {
                actual: context.ciphersuite(),
                expected: supported_ciphersuite(),
            });
        }
        Self::validate_group_context_extensions(context.extensions(), external_sender)
    }

    fn validate_group_context_extensions(
        extensions: &Extensions<GroupContext>,
        external_sender: &ExternalSender,
    ) -> Result<(), GroupPolicyError> {
        let extension_count = extensions.iter().count();
        if extension_count != 1 {
            return Err(GroupPolicyError::UnexpectedGroupExtensionCount {
                actual: extension_count,
            });
        }
        let external_senders = extensions
            .external_senders()
            .ok_or(GroupPolicyError::MissingExternalSenderExtension)?;
        let [join_external_sender] = external_senders.as_slice() else {
            return Err(GroupPolicyError::InvalidExternalSenderCount(
                external_senders.as_slice().len(),
            ));
        };
        if join_external_sender != external_sender {
            return Err(GroupPolicyError::UnexpectedExternalSender);
        }
        Ok(())
    }

    fn validate_group_member_policy(
        members: impl IntoIterator<Item = Member>,
    ) -> Result<(), GroupPolicyError> {
        let mut seen = HashSet::new();
        for member in members {
            let user_id = Self::credential_user_id(&member.credential)?;
            if !seen.insert(user_id) {
                return Err(GroupPolicyError::DuplicateMemberCredential(user_id));
            }
        }
        Ok(())
    }

    fn validate_leaf_node_policy(leaf_node: &LeafNode) -> Result<(), GroupPolicyError> {
        Self::credential_user_id(leaf_node.credential())?;
        let extension_count = leaf_node.extensions().iter().count();
        if extension_count != 0 {
            return Err(GroupPolicyError::UnexpectedLeafExtensionCount {
                actual: extension_count,
            });
        }
        if leaf_node.capabilities() != &supported_capabilities() {
            return Err(GroupPolicyError::UnexpectedLeafCapabilities);
        }
        Ok(())
    }

    fn credential_user_id(credential: &Credential) -> Result<u64, CredentialPolicyError> {
        if credential.credential_type() != CredentialType::Basic {
            return Err(CredentialPolicyError::UnexpectedType {
                actual: credential.credential_type(),
            });
        }
        Ok(u64::from_be_bytes(
            credential
                .serialized_content()
                .try_into()
                .map_err(CredentialPolicyError::UserIdContent)?,
        ))
    }

    fn member_user_id(member: &Member) -> Result<u64, UpdateRatchetsError> {
        Ok(Self::credential_user_id(&member.credential)?)
    }

    fn established_group_for_verification(&self) -> Result<&SessionGroup, VerificationError> {
        let Some(group) = &self.group else {
            return Err(VerificationError::NoEstablishedGroup);
        };
        if !group.is_established() {
            return Err(VerificationError::NoEstablishedGroup);
        }
        Ok(group)
    }
}

struct EncryptTypedFrame<'session, 'output> {
    session: &'session mut Session,
    output: &'output mut Vec<u8>,
}

impl<'a> TypedMediaFrameVisitor<'a> for EncryptTypedFrame<'_, '_> {
    type Output = Result<(), EncryptError>;

    fn visit<C>(&mut self, frame: MediaFrame<'a, C>) -> Self::Output
    where
        C: FrameCodec,
    {
        self.session.encrypt_supported_into(frame, self.output)
    }
}

fn supported_ciphersuite() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
}

fn supported_capabilities() -> Capabilities {
    Capabilities::builder()
        .versions(vec![ProtocolVersion::Mls10])
        .ciphersuites(vec![supported_ciphersuite()])
        .extensions(vec![])
        .proposals(vec![])
        .credentials(vec![CredentialType::Basic])
        .build()
}

#[cfg(test)]
mod tests {
    use super::{
        HashRatchet, PassthroughMode, ProcessCommitError, ProcessProposalsError,
        ProcessWelcomeError, ProposalsOperation, Session, SessionConfig, SessionGroup,
        SessionOptions, SessionStatus,
    };
    use crate::frame::{MediaFrame, OPUS_SILENCE_FRAME, Opus};
    use crate::{
        DisplayableCodeError, GroupPolicyError, IdentityKeyPair, IdentityKeyPersistence,
        IdentityPublicKey, SessionIdentity, VerificationError, displayable_code,
        pairwise_fingerprint, pairwise_fingerprint_display_code,
    };
    use openmls::prelude::{
        tls_codec::{Deserialize, Serialize},
        *,
    };
    use openmls_rust_crypto::OpenMlsRustCrypto;

    fn proposal_vector(messages: impl IntoIterator<Item = MlsMessageOut>) -> Vec<u8> {
        let mut proposals = Vec::new();
        for message in messages {
            proposals.extend_from_slice(&message.tls_serialize_detached().unwrap());
        }
        VLBytes::new(proposals).tls_serialize_detached().unwrap()
    }

    fn pending_session_with_gateway() -> (Session, Session) {
        let gateway = Session::new(SessionConfig {
            self_user_id: 999,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        let mut session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        session
            .set_external_sender(&gateway.external_sender_for_test())
            .unwrap();
        (session, gateway)
    }

    fn force_established(session: &mut Session) {
        let group = session.group.take().unwrap().group;
        session.group = Some(SessionGroup::established(group));
        session.status = SessionStatus::Active;
    }

    #[test]
    fn reset_media_transform_state_disables_plaintext_receive() {
        let mut session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();

        session.set_passthrough_mode(PassthroughMode::enabled());
        assert!(session.passthrough.allows_plaintext());

        session.reset_media_transform_state();

        assert!(!session.passthrough.allows_plaintext());
    }

    #[test]
    fn encrypting_opus_silence_does_not_passthrough() {
        let mut session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        session.sender.stage_ratchet(HashRatchet::new(vec![7; 16]));
        assert!(session.activate_staged_sender());

        let mut encrypted = Vec::new();
        session
            .encrypt_into(MediaFrame::<Opus>::new(&OPUS_SILENCE_FRAME), &mut encrypted)
            .unwrap();

        assert_ne!(encrypted, OPUS_SILENCE_FRAME);
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn supplied_identity_key_is_used_for_mls_signature_key() {
        let key_pair =
            IdentityKeyPair::from_p256_private_key(vec![1; 32], IdentityKeyPersistence::Persistent)
                .unwrap();
        let expected_public_key = key_pair.public_key().to_vec();
        let session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions {
                identity: SessionIdentity::key_pair(key_pair),
            },
        })
        .unwrap();

        assert_eq!(
            session.local_identity_public_key(),
            IdentityPublicKey {
                user_id: 1,
                public_key: expected_public_key,
            }
        );
    }

    #[test]
    fn pairwise_fingerprint_is_order_independent_and_displayable() {
        let alice = IdentityPublicKey {
            user_id: 1,
            public_key: vec![1, 2, 3],
        };
        let bob = IdentityPublicKey {
            user_id: 2,
            public_key: vec![4, 5, 6],
        };

        let fingerprint = pairwise_fingerprint(&alice, &bob).unwrap();

        assert_eq!(fingerprint, pairwise_fingerprint(&bob, &alice).unwrap());
        let code = pairwise_fingerprint_display_code(&fingerprint).unwrap();
        assert_eq!(code.len(), 45);
        assert!(code.chars().all(|character| character.is_ascii_digit()));
    }

    #[test]
    fn displayable_code_rejects_invalid_lengths() {
        assert!(matches!(
            displayable_code(&[0; 4], 5, 5),
            Err(DisplayableCodeError::InputTooShort {
                actual: 4,
                required: 5
            })
        ));
        assert!(matches!(
            displayable_code(&[0; 5], 6, 5),
            Err(DisplayableCodeError::InvalidDigitCount {
                digit_count: 6,
                group_digits: 5
            })
        ));
    }

    #[test]
    fn verification_state_requires_established_group() {
        let session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();

        assert!(matches!(
            session.epoch_authenticator(),
            Err(VerificationError::NoEstablishedGroup)
        ));
    }

    #[test]
    fn process_proposals_rejects_gateway_proposal_types_outside_dave_policy() {
        let (mut session, gateway) = pending_session_with_gateway();
        let group = &session.group.as_ref().unwrap().group;
        let proposal = ExternalProposal::new_group_context_extensions::<OpenMlsRustCrypto>(
            Extensions::empty(),
            group.group_id().clone(),
            group.epoch(),
            &gateway.signer,
            SenderExtensionIndex::new(0),
        )
        .unwrap();
        let proposals = proposal_vector([proposal]);

        assert!(matches!(
            session.process_proposals(ProposalsOperation::Append, &proposals, &[]),
            Err(ProcessProposalsError::UnexpectedProposalType)
        ));
    }

    #[test]
    fn process_proposals_rejects_invalid_vector_without_storing_earlier_proposals() {
        let (mut session, gateway) = pending_session_with_gateway();
        let mut new_member = Session::new(SessionConfig {
            self_user_id: 2,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        let key_package =
            KeyPackageIn::tls_deserialize(&mut new_member.create_key_package().unwrap().as_slice())
                .unwrap()
                .validate(session.provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
        let group = &session.group.as_ref().unwrap().group;
        let add = ExternalProposal::new_add::<OpenMlsRustCrypto>(
            key_package,
            group.group_id().clone(),
            group.epoch(),
            &gateway.signer,
            SenderExtensionIndex::new(0),
        )
        .unwrap();
        let invalid = ExternalProposal::new_group_context_extensions::<OpenMlsRustCrypto>(
            Extensions::empty(),
            group.group_id().clone(),
            group.epoch(),
            &gateway.signer,
            SenderExtensionIndex::new(0),
        )
        .unwrap();
        let proposals = proposal_vector([add, invalid]);

        assert!(matches!(
            session.process_proposals(ProposalsOperation::Append, &proposals, &[2]),
            Err(ProcessProposalsError::UnexpectedProposalType)
        ));
        assert!(
            session
                .group
                .as_ref()
                .unwrap()
                .group
                .pending_proposals()
                .next()
                .is_none()
        );
    }

    #[test]
    fn process_commit_rejects_inline_proposals() {
        let (mut session, _) = pending_session_with_gateway();
        force_established(&mut session);
        let group = &mut session.group.as_mut().unwrap().group;
        let bundle = group
            .commit_builder()
            .propose_group_context_extensions(Extensions::empty())
            .unwrap()
            .load_psks(session.provider.storage())
            .unwrap()
            .build(
                session.provider.rand(),
                session.provider.crypto(),
                &session.signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&session.provider)
            .unwrap();
        let (commit, _, _) = bundle.into_contents();
        let commit = commit.tls_serialize_detached().unwrap();
        session.pending_commit = Some(commit.clone());

        assert!(matches!(
            session.process_commit(&commit),
            Err(ProcessCommitError::InlineProposal)
        ));
    }

    #[test]
    fn process_commit_rejects_duplicate_resulting_credentials() {
        let (mut session, gateway) = pending_session_with_gateway();
        let mut duplicate = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        let duplicate_key_package =
            KeyPackageIn::tls_deserialize(&mut duplicate.create_key_package().unwrap().as_slice())
                .unwrap()
                .validate(session.provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
        let group = &session.group.as_ref().unwrap().group;
        let proposal = ExternalProposal::new_add::<OpenMlsRustCrypto>(
            duplicate_key_package,
            group.group_id().clone(),
            group.epoch(),
            &gateway.signer,
            SenderExtensionIndex::new(0),
        )
        .unwrap();
        let proposals = proposal_vector([proposal]);
        let commit = session
            .process_proposals(ProposalsOperation::Append, &proposals, &[1])
            .unwrap()
            .unwrap()
            .commit;

        assert!(matches!(
            session.process_commit(&commit),
            Err(ProcessCommitError::GroupPolicy(
                GroupPolicyError::DuplicateMemberCredential(1)
            ))
        ));
    }

    #[test]
    fn pending_group_is_not_media_ready() {
        let mut session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        let external_sender = Session::new(SessionConfig {
            self_user_id: 3,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap()
        .external_sender_for_test();

        session.set_external_sender(&external_sender).unwrap();
        assert_eq!(session.status(), SessionStatus::Pending);
        assert!(!session.receive_ready());
        assert!(!session.sender_ready());
    }

    #[test]
    fn pending_group_welcome_is_not_rejected_as_already_established() {
        let mut session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        let external_sender = Session::new(SessionConfig {
            self_user_id: 3,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap()
        .external_sender_for_test();

        session.set_external_sender(&external_sender).unwrap();

        assert!(matches!(
            session.process_welcome(&[0xde, 0xad, 0xbe, 0xef]),
            Err(ProcessWelcomeError::DeserializeWelcome(_))
        ));
    }

    #[test]
    fn established_group_rejects_welcome_while_awaiting_commit() {
        let mut session = Session::new(SessionConfig {
            self_user_id: 1,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap();
        let external_sender = Session::new(SessionConfig {
            self_user_id: 3,
            channel_id: 2,
            options: SessionOptions::default(),
        })
        .unwrap()
        .external_sender_for_test();

        session.set_external_sender(&external_sender).unwrap();
        let group = session.group.take().unwrap().group;
        session.group = Some(SessionGroup::established(group));
        session.status = SessionStatus::AwaitingCommit;

        assert!(matches!(
            session.process_welcome(&[0xde, 0xad, 0xbe, 0xef]),
            Err(ProcessWelcomeError::AlreadyInGroup)
        ));
    }
}
