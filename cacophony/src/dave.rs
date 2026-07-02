use std::{
    collections::{HashMap, HashSet},
    fmt,
    num::NonZeroU16,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

use ::dave::{
    DaveProtocolVersion, DynamicMediaFrame, IdentityKeyError, IdentityKeyPair,
    IdentityKeyPersistence, MediaType, PassthroughMode, ProposalsOperation, Session, SessionConfig,
    SessionIdentity, SessionOptions,
};
use serde::Serialize;

use crate::{
    errors::{DaveDecryptError, DaveError, DaveProposalsPayloadError, Result},
    gateway::{DaveInvalidCommitWelcomeCommand, DaveTransitionReadyCommand, GatewayCommand},
    observer::{ConnectionObserver, DisplayValue, ReceiveDecodeErrorKind},
    state::{
        ConnectionState, DaveInternalState, DaveMlsMessageKind, DaveMlsSlots, DaveMlsState,
        DaveState, PendingDaveMlsMessage,
    },
};

const DAVE_PLAINTEXT_RECEIVE_GRACE: Duration = Duration::from_secs(10);

static SHARED_EPHEMERAL_IDENTITIES: OnceLock<Mutex<HashMap<u64, Weak<IdentityKeyPair>>>> =
    OnceLock::new();

#[derive(Clone)]
pub struct DaveIdentityKey {
    key_pair: Arc<IdentityKeyPair>,
}

impl DaveIdentityKey {
    pub fn generate(persistence: IdentityKeyPersistence) -> Self {
        Self {
            key_pair: Arc::new(IdentityKeyPair::generate(persistence)),
        }
    }

    pub fn generate_ephemeral() -> Self {
        Self::generate(IdentityKeyPersistence::Ephemeral)
    }

    pub fn from_p256_private_key(
        private_key: Vec<u8>,
        persistence: IdentityKeyPersistence,
    ) -> std::result::Result<Self, IdentityKeyError> {
        Ok(Self {
            key_pair: Arc::new(IdentityKeyPair::from_p256_private_key(
                private_key,
                persistence,
            )?),
        })
    }

    pub fn public_key(&self) -> &[u8] {
        self.key_pair.public_key()
    }

    pub fn persistence(&self) -> IdentityKeyPersistence {
        self.key_pair.persistence()
    }

    pub(crate) fn shared_ephemeral(user_id: u64) -> Self {
        let identities = SHARED_EPHEMERAL_IDENTITIES.get_or_init(Mutex::default);
        let mut identities = identities
            .lock()
            .expect("shared DAVE identity cache lock poisoned");
        identities.retain(|_, key_pair| key_pair.strong_count() > 0);
        if let Some(key_pair) = identities.get(&user_id).and_then(Weak::upgrade) {
            return Self { key_pair };
        }

        let key_pair = Arc::new(IdentityKeyPair::generate(IdentityKeyPersistence::Ephemeral));
        identities.insert(user_id, Arc::downgrade(&key_pair));
        Self { key_pair }
    }

    pub(crate) fn session_identity(&self) -> SessionIdentity {
        SessionIdentity::key_pair(self.key_pair.duplicate_for_session())
    }
}

impl fmt::Debug for DaveIdentityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaveIdentityKey")
            .field("private_key", &"***")
            .field("public_key", &self.public_key())
            .field("persistence", &self.persistence())
            .finish()
    }
}

impl PartialEq for DaveIdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.persistence() == other.persistence() && self.public_key() == other.public_key()
    }
}

impl Eq for DaveIdentityKey {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DavePassthroughController {
    last_applied: Option<PassthroughMode>,
}

impl DavePassthroughController {
    fn apply(&mut self, session: &mut Session, mode: PassthroughMode) {
        if self.last_applied == Some(mode) {
            return;
        }
        session.set_passthrough_mode(mode);
        self.last_applied = Some(mode);
    }

    fn force_apply(&mut self, session: &mut Session, mode: PassthroughMode) {
        session.set_passthrough_mode(mode);
        self.last_applied = Some(mode);
    }

    fn allow_for(&mut self, session: &mut Session, duration: Duration) {
        session.set_passthrough_mode(PassthroughMode::enabled());
        self.force_apply(session, PassthroughMode::disabled_after(duration));
    }

    fn invalidate(&mut self) {
        self.last_applied = None;
    }
}

pub(crate) struct DaveCoordinator {
    session: Session,
    identity: DaveIdentityKey,
    user_id: u64,
    channel_id: u64,
    external_sender_set: bool,
    sent_key_package_for: Option<DaveKeyPackageScope>,
    processed_proposals: usize,
    processed_mls: DaveMlsSlots<PendingDaveMlsMessage>,
    transition_ready: Option<u16>,
    prepared_epoch: Option<DavePreparedEpoch>,
    last_gateway_state: Option<DaveGatewayStateEvent>,
    passthrough: DavePassthroughController,
}

impl DaveCoordinator {
    pub(crate) fn new(user_id: u64, channel_id: u64) -> Result<Self> {
        Self::new_with_identity(
            user_id,
            channel_id,
            DaveIdentityKey::shared_ephemeral(user_id),
        )
    }

    pub(crate) fn new_with_identity(
        user_id: u64,
        channel_id: u64,
        identity: DaveIdentityKey,
    ) -> Result<Self> {
        Ok(Self {
            session: Session::new(SessionConfig {
                self_user_id: user_id,
                channel_id,
                options: SessionOptions {
                    identity: identity.session_identity(),
                },
            })
            .map_err(DaveError::CreateSession)?,
            identity,
            user_id,
            channel_id,
            external_sender_set: false,
            sent_key_package_for: None,
            processed_proposals: 0,
            processed_mls: DaveMlsSlots::default(),
            transition_ready: None,
            prepared_epoch: None,
            last_gateway_state: None,
            passthrough: DavePassthroughController::default(),
        })
    }

    fn new_session(
        user_id: u64,
        channel_id: u64,
        identity: &DaveIdentityKey,
    ) -> std::result::Result<Session, DaveError> {
        Session::new(SessionConfig {
            self_user_id: user_id,
            channel_id,
            options: SessionOptions {
                identity: identity.session_identity(),
            },
        })
        .map_err(DaveError::CreateSession)
    }

    pub(crate) fn ready(&self) -> bool {
        self.session.receive_ready()
    }

    pub(crate) fn send_ready(&self) -> bool {
        self.session.sender_ready()
    }

    pub(crate) fn transition_ready(&self) -> Option<u16> {
        self.transition_ready
    }

    pub(crate) fn encrypt_dynamic_media_frame_into(
        &mut self,
        codec: dave::Codec,
        frame: &[u8],
        output: &mut Vec<u8>,
    ) -> std::result::Result<(), DaveError> {
        self.session
            .encrypt_dynamic_into(DynamicMediaFrame::new(codec, frame), output)
            .map_err(DaveError::Encrypt)
    }

    pub(crate) fn decrypt_media_frame_into(
        &mut self,
        user_id: Option<u64>,
        media_type: MediaType,
        frame: &[u8],
        output: &mut Vec<u8>,
    ) -> std::result::Result<usize, DaveDecryptError> {
        self.session
            .decrypt_into(
                user_id.ok_or(DaveDecryptError::MissingUser)?,
                media_type,
                frame,
                output,
            )
            .map_err(DaveDecryptError::from)
    }

    pub(crate) fn set_passthrough_mode(&mut self, mode: PassthroughMode) {
        self.passthrough.apply(&mut self.session, mode);
    }

    pub(crate) fn allow_plaintext_receive_grace(&mut self) {
        self.passthrough
            .allow_for(&mut self.session, DAVE_PLAINTEXT_RECEIVE_GRACE);
    }

    pub(crate) fn pump<D>(
        &mut self,
        dave: &DaveInternalState,
        connected_user_ids: &HashSet<u64>,
        roster_authoritative: bool,
        observer: &D,
    ) -> Result<Vec<GatewayCommand>>
    where
        D: ConnectionObserver,
    {
        let mut commands = Vec::new();
        self.observe_gateway_state(observer, dave);
        self.sync_prepared_epoch(dave)?;
        self.activate_sender_if_transition_executed(dave);

        if dave.protocol_version().unwrap_or(0) == 0 {
            self.set_passthrough_mode(PassthroughMode::enabled());
            self.mark_transition_ready(
                &mut commands,
                observer,
                dave.transition_id(),
                dave.protocol_version(),
            );
            return Ok(commands);
        }

        self.set_passthrough_mode(PassthroughMode::disabled_after(
            DAVE_PLAINTEXT_RECEIVE_GRACE,
        ));

        if let Some(external_sender) = dave.external_sender.as_deref()
            && !self.external_sender_set
        {
            self.session
                .set_external_sender(external_sender)
                .map_err(DaveError::SetExternalSender)?;
            self.external_sender_set = true;
            observer.dave_external_sender_set(DaveKeyPackageEvent {
                protocol_version: dave.protocol_version(),
            });
        }

        if let Some(key_package_scope) = DaveKeyPackageScope::from_state(dave, self.prepared_epoch)
            && self.sent_key_package_for != Some(key_package_scope)
        {
            commands.push(GatewayCommand::DaveMlsKeyPackage {
                key_package: self
                    .session
                    .create_key_package()
                    .map_err(DaveError::CreateKeyPackage)?,
            });
            self.sent_key_package_for = Some(key_package_scope);
            observer.dave_key_package_sent(DaveKeyPackageEvent {
                protocol_version: Some(key_package_scope.protocol_version()),
            });
        }

        if !self.external_sender_set {
            return Ok(commands);
        }
        self.activate_sender_if_transition_executed(dave);

        if self.processed_proposals > dave.proposals.len() {
            self.processed_proposals = 0;
        }
        if dave.proposals.len() > self.processed_proposals && !roster_authoritative {
            return Ok(commands);
        }
        for proposals in dave.proposals.iter().skip(self.processed_proposals) {
            let (operation, proposal_bytes) = DaveProposalsOperation::parse(proposals)?;
            let mut commit_sent = false;
            let mut welcome_sent = false;
            match self
                .session
                .process_proposals(operation.kind, proposal_bytes, connected_user_ids)
            {
                Ok(Some(commit_welcome)) => {
                    welcome_sent = commit_welcome.welcome.is_some();
                    commands.push(GatewayCommand::DaveMlsCommitWelcome {
                        commit: commit_welcome.commit,
                        welcome: commit_welcome.welcome,
                    });
                    commit_sent = true;
                }
                Ok(None) => {}
                Err(error) => {
                    self.processed_proposals += 1;
                    observer.dave_proposals_ignored(DaveIgnoredProposalsEvent {
                        operation: operation.label,
                        proposal_bytes: proposal_bytes.len(),
                        error: DisplayValue::new(&error),
                    });
                    continue;
                }
            }
            self.processed_proposals += 1;
            observer.dave_proposals_processed(DaveProposalsEvent {
                operation: operation.label,
                proposal_bytes: proposal_bytes.len(),
                commit_sent,
                welcome_sent,
            });
        }

        for message in dave.pending_mls.welcome_then_commit() {
            self.process_mls_message(&mut commands, observer, dave, message)?;
        }

        self.activate_sender_if_transition_zero_ready(dave);
        self.activate_sender_if_transition_executed(dave);
        Ok(commands)
    }

    fn activate_sender_if_transition_executed(&mut self, dave: &DaveInternalState) {
        if dave.transition_id().is_none()
            && dave.active_send_protocol_version().unwrap_or(0) > 0
            && self.session.activate_staged_sender()
        {
            self.transition_ready = None;
        }
    }

    fn activate_sender_if_transition_zero_ready(&mut self, dave: &DaveInternalState) {
        if dave.transition_zero_media_ready(self.transition_ready) {
            self.session.activate_staged_sender();
        }
    }

    pub(crate) fn sync_prepared_epoch(&mut self, dave: &DaveInternalState) -> Result<()> {
        let prepared_epoch = DavePreparedEpoch::from_state(dave);
        if self.prepared_epoch == prepared_epoch {
            return Ok(());
        }

        if let Some(prepared_epoch) = prepared_epoch {
            self.sent_key_package_for = None;
            self.processed_proposals = 0;
            self.processed_mls.clear();
            if prepared_epoch.epoch == 1 && !self.ready() {
                self.transition_ready = None;
                self.replace_session(prepared_epoch.protocol_version)?;
            }
        }
        self.prepared_epoch = prepared_epoch;
        Ok(())
    }

    fn process_mls_message(
        &mut self,
        commands: &mut Vec<GatewayCommand>,
        observer: &impl ConnectionObserver,
        dave: &DaveInternalState,
        message: &PendingDaveMlsMessage,
    ) -> Result<()> {
        if self.processed_mls.get(message.identity.kind) == Some(message) {
            return Ok(());
        }

        let result = match message.identity.kind {
            DaveMlsMessageKind::Commit => self
                .session
                .process_commit(&message.payload)
                .map_err(DaveError::ProcessCommit),
            DaveMlsMessageKind::Welcome => self
                .session
                .process_welcome(&message.payload)
                .map_err(DaveError::ProcessWelcome),
        };
        self.processed_mls.set_message(message.clone());

        match result {
            Ok(()) => {
                self.mark_transition_ready(
                    commands,
                    observer,
                    dave.transition_id(),
                    dave.protocol_version(),
                );
                Ok(())
            }
            Err(error) => {
                if let Some(transition_id) = dave.transition_id() {
                    commands.push(GatewayCommand::DaveMlsInvalidCommitWelcome(
                        DaveInvalidCommitWelcomeCommand { transition_id },
                    ));
                }
                if let Err(recovery_error) = self.recover_after_invalid_group(commands, dave) {
                    return Err(DaveError::recover_invalid_group(
                        message.identity.kind.operation_label(),
                        error,
                        recovery_error,
                    ));
                }
                Err(error.into())
            }
        }
    }

    pub(crate) fn replace_session(&mut self, protocol_version: u16) -> Result<()> {
        let protocol_version =
            NonZeroU16::new(protocol_version).ok_or(DaveError::InvalidProtocolVersion {
                version: protocol_version,
            })?;
        DaveProtocolVersion::try_from(protocol_version).map_err(|error| {
            DaveError::InvalidProtocolVersion {
                version: error.0.get(),
            }
        })?;
        self.session = Self::new_session(self.user_id, self.channel_id, &self.identity)?;
        self.passthrough.invalidate();
        self.external_sender_set = false;
        Ok(())
    }

    pub(crate) fn recover_after_invalid_group(
        &mut self,
        commands: &mut Vec<GatewayCommand>,
        dave: &DaveInternalState,
    ) -> Result<()> {
        let Some(protocol_version) = dave.protocol_version() else {
            return Ok(());
        };
        if protocol_version == 0 {
            self.set_passthrough_mode(PassthroughMode::enabled());
            return Ok(());
        }

        self.replace_session(protocol_version)?;
        if let Some(external_sender) = dave.external_sender.as_deref() {
            self.session
                .set_external_sender(external_sender)
                .map_err(DaveError::SetExternalSender)?;
            self.external_sender_set = true;
        }
        if let Some(key_package_scope) = DaveKeyPackageScope::from_state(dave, self.prepared_epoch)
        {
            commands.push(GatewayCommand::DaveMlsKeyPackage {
                key_package: self
                    .session
                    .create_key_package()
                    .map_err(DaveError::CreateKeyPackage)?,
            });
            self.sent_key_package_for = Some(key_package_scope);
        }
        self.processed_proposals = dave.proposals.len();
        Ok(())
    }

    pub(crate) fn observe_gateway_state(
        &mut self,
        observer: &impl ConnectionObserver,
        dave: &DaveInternalState,
    ) {
        let gateway_state = DaveGatewayStateEvent::from_state(dave);
        if self.last_gateway_state.as_ref() == Some(&gateway_state) {
            return;
        }
        self.last_gateway_state = Some(gateway_state.clone());
        observer.dave_gateway_state(gateway_state);
    }

    pub(crate) fn mark_transition_ready<D>(
        &mut self,
        commands: &mut Vec<GatewayCommand>,
        observer: &D,
        transition_id: Option<u16>,
        protocol_version: Option<u16>,
    ) where
        D: ConnectionObserver,
    {
        let Some(transition_id) = transition_id else {
            return;
        };
        if self.transition_ready == Some(transition_id) {
            return;
        }
        let protocol_version = protocol_version.unwrap_or(0);
        self.transition_ready = Some(transition_id);
        if transition_id == 0 {
            if protocol_version > 0 {
                self.allow_plaintext_receive_grace();
            }
            return;
        }
        commands.push(GatewayCommand::DaveProtocolTransitionReady(
            DaveTransitionReadyCommand { transition_id },
        ));
        observer.dave_transition_ready_sent(DaveTransitionEvent {
            transition_id,
            protocol_version,
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DavePreparedEpoch {
    epoch: u64,
    protocol_version: u16,
    seq: u64,
}

impl DavePreparedEpoch {
    pub(crate) fn from_state(dave: &DaveInternalState) -> Option<Self> {
        let protocol_version = dave.protocol_version()?;
        if protocol_version == 0 {
            return None;
        }
        Some(Self {
            epoch: dave.epoch()?,
            protocol_version,
            seq: dave.prepare_epoch_seq(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DaveKeyPackageScope {
    Session { protocol_version: u16 },
    Epoch(DavePreparedEpoch),
}

impl DaveKeyPackageScope {
    pub(crate) fn from_state(
        dave: &DaveInternalState,
        prepared_epoch: Option<DavePreparedEpoch>,
    ) -> Option<Self> {
        if let Some(prepared_epoch) = prepared_epoch
            && prepared_epoch.epoch == 1
        {
            return Some(Self::Epoch(prepared_epoch));
        }
        let protocol_version = dave.protocol_version()?;
        (protocol_version > 0).then_some(Self::Session { protocol_version })
    }

    pub(crate) fn protocol_version(&self) -> u16 {
        match self {
            Self::Session { protocol_version } => *protocol_version,
            Self::Epoch(prepared_epoch) => prepared_epoch.protocol_version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DaveGatewayStateEvent {
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub epoch: Option<u64>,
    pub prepare_epoch_seq: u64,
    pub passthrough: bool,
    pub mls: DaveMlsState,
}

impl DaveGatewayStateEvent {
    pub(crate) fn from_state(dave: &DaveInternalState) -> Self {
        Self {
            protocol_version: dave.protocol_version(),
            transition_id: dave.transition_id(),
            epoch: dave.epoch(),
            prepare_epoch_seq: dave.prepare_epoch_seq(),
            passthrough: dave.passthrough(),
            mls: dave.mls_state(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DaveKeyPackageEvent {
    pub protocol_version: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DaveTransitionEvent {
    pub transition_id: u16,
    pub protocol_version: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DaveProposalsEvent {
    pub operation: &'static str,
    pub proposal_bytes: usize,
    pub commit_sent: bool,
    pub welcome_sent: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct DaveIgnoredProposalsEvent<'a> {
    pub operation: &'static str,
    pub proposal_bytes: usize,
    pub error: DisplayValue<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DaveMediaStatus {
    pub requires_dave: bool,
    pub active_send_protocol_version: Option<u16>,
    pub active_receive_protocol_version: Option<u16>,
    pub media_ready: bool,
    pub session_ready: bool,
    pub send_ready: bool,
    pub transition_ready: Option<u16>,
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub mls: DaveMlsState,
}

impl DaveMediaStatus {
    pub(crate) fn from_public_state(state: &ConnectionState) -> Self {
        let requires_dave = state.dave.send_requires_dave();
        Self {
            requires_dave,
            active_send_protocol_version: state.dave.active_send_protocol_version,
            active_receive_protocol_version: state.dave.active_receive_protocol_version,
            media_ready: !requires_dave,
            session_ready: false,
            send_ready: false,
            transition_ready: None,
            protocol_version: state.dave.protocol_version,
            transition_id: state.dave.transition_id,
            mls: state.dave.mls,
        }
    }

    pub(crate) const fn ready_from(
        requires_dave: bool,
        session_ready: bool,
        send_ready: bool,
        gateway_ready: bool,
    ) -> bool {
        !requires_dave || (session_ready && send_ready && gateway_ready)
    }
}

pub(crate) struct DaveProposalsOperation {
    kind: ProposalsOperation,
    label: &'static str,
}

impl DaveProposalsOperation {
    pub(crate) fn parse(payload: &[u8]) -> std::result::Result<(Self, &[u8]), DaveError> {
        let Some((&operation, proposals)) = payload.split_first() else {
            return Err(DaveError::InvalidProposalsPayload(
                DaveProposalsPayloadError::MissingOperation,
            ));
        };
        let (kind, label) = match operation {
            0 => (ProposalsOperation::Append, "append"),
            1 => (ProposalsOperation::Revoke, "revoke"),
            other => {
                return Err(DaveError::InvalidProposalsPayload(
                    DaveProposalsPayloadError::InvalidOperation { operation: other },
                ));
            }
        };
        Ok((Self { kind, label }, proposals))
    }
}

impl DaveInternalState {
    pub(crate) fn gateway_media_ready(&self) -> bool {
        self.transition_id().is_none() && self.pending_mls.is_empty() && self.proposals.is_empty()
    }

    pub(crate) fn send_requires_dave(&self) -> bool {
        self.active.send_active()
            || self.transition_zero_dave_pending()
            || self.initial_dave_negotiation_pending()
    }

    pub(crate) fn receive_transform_active(&self) -> bool {
        self.active.receive_active()
            || self.transition_zero_dave_pending()
            || self.initial_dave_negotiation_pending()
    }

    pub(crate) fn transition_zero_media_ready(&self, transition_ready: Option<u16>) -> bool {
        self.transition_id() == Some(0) && transition_ready == Some(0)
    }

    fn transition_zero_dave_pending(&self) -> bool {
        self.transition_id() == Some(0) && self.protocol_version().unwrap_or(0) > 0
    }

    fn initial_dave_negotiation_pending(&self) -> bool {
        self.active_send_protocol_version().is_none() && self.protocol_version().unwrap_or(0) > 0
    }
}

impl DaveState {
    pub(crate) fn send_requires_dave(&self) -> bool {
        self.active_send_protocol_version.unwrap_or(0) > 0
            || (self.active_send_protocol_version.is_none()
                && self.protocol_version.unwrap_or(0) > 0)
            || (self.transition_id == Some(0) && self.protocol_version.unwrap_or(0) > 0)
    }
}

impl ReceiveDecodeErrorKind {
    pub(crate) fn dave_decrypt_failure_can_become_recoverable(self) -> bool {
        matches!(
            self,
            Self::DaveNoDecryptorForUser | Self::DaveNoValidCryptor | Self::DaveOtherDecryptError
        )
    }

    pub(crate) fn should_retry_dave_decrypt(self, state_can_still_change: bool) -> bool {
        self.dave_decrypt_failure_can_become_recoverable() && state_can_still_change
    }
}
