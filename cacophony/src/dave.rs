use std::{collections::HashSet, num::NonZeroU16, time::Duration};

use dave::{
    DAVE_PROTOCOL_VERSION, FrameEncryptResult, MediaFrame, MediaType, Opus, ProposalsOperation,
    Session,
};
use serde::Serialize;

use crate::{
    errors::{DaveDecryptError, DaveError, DaveProposalsPayloadError, Error, Result},
    gateway::{DaveInvalidCommitWelcomeCommand, DaveTransitionReadyCommand, GatewayCommand},
    observer::{ConnectionObserver, DisplayValue, ReceiveDecodeErrorKind},
    state::{DaveInternalState, DaveMlsState},
};

const DAVE_TRANSITION_PASSTHROUGH_WINDOW: Duration = Duration::from_secs(10);
const DAVE_RESET_PASSTHROUGH_WINDOW: Duration = Duration::from_secs(120);

fn create_dave_session(
    protocol_version: u16,
    user_id: u64,
    channel_id: u64,
) -> std::result::Result<Session, DaveError> {
    let protocol_version =
        NonZeroU16::new(protocol_version).ok_or(DaveError::InvalidProtocolVersion {
            version: protocol_version,
        })?;
    new_dave_session(protocol_version, user_id, channel_id)
}

fn new_dave_session(
    protocol_version: NonZeroU16,
    user_id: u64,
    channel_id: u64,
) -> std::result::Result<Session, DaveError> {
    Session::new(protocol_version, user_id, channel_id).map_err(DaveError::CreateSession)
}

pub(crate) struct DaveCoordinator {
    session: Session,
    bot_user_id: u64,
    channel_id: u64,
    external_sender_set: bool,
    sent_key_package_for: Option<DaveKeyPackageScope>,
    processed_proposals: usize,
    processed_welcome: Option<Vec<u8>>,
    processed_commit: Option<Vec<u8>>,
    transition_ready: Option<u16>,
    prepared_epoch: Option<DavePreparedEpoch>,
    last_gateway_state: Option<DaveGatewayStateEvent>,
    passthrough_enabled: bool,
}

impl DaveCoordinator {
    pub(crate) fn new(bot_user_id: u64, channel_id: u64) -> Result<Self> {
        Ok(Self {
            session: create_dave_session(DAVE_PROTOCOL_VERSION, bot_user_id, channel_id)?,
            bot_user_id,
            channel_id,
            external_sender_set: false,
            sent_key_package_for: None,
            processed_proposals: 0,
            processed_welcome: None,
            processed_commit: None,
            transition_ready: None,
            prepared_epoch: None,
            last_gateway_state: None,
            passthrough_enabled: false,
        })
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

    pub(crate) fn encrypt_discord_voice_frame_into(
        &mut self,
        frame: &[u8],
        output: &mut Vec<u8>,
    ) -> std::result::Result<FrameEncryptResult, DaveError> {
        self.session
            .encrypt_into(MediaFrame::<Opus>::new(frame), output)
            .map_err(DaveError::Encrypt)
    }

    pub(crate) fn decrypt_discord_voice_frame_into(
        &mut self,
        user_id: Option<u64>,
        frame: &[u8],
        output: &mut Vec<u8>,
    ) -> std::result::Result<usize, DaveDecryptError> {
        self.session
            .decrypt_into(
                user_id.ok_or(DaveDecryptError::MissingUser)?,
                MediaType::Audio,
                frame,
                output,
            )
            .map_err(DaveDecryptError::from)
    }

    pub(crate) fn set_passthrough_mode(&mut self, enabled: bool, transition_expiry: Duration) {
        if self.passthrough_enabled == enabled {
            return;
        }
        self.session
            .set_passthrough_mode(enabled, transition_expiry);
        self.passthrough_enabled = enabled;
    }

    pub(crate) fn allow_transition_receive_passthrough(&mut self) {
        self.session
            .set_passthrough_mode(false, DAVE_TRANSITION_PASSTHROUGH_WINDOW);
        self.passthrough_enabled = false;
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

        if dave.protocol_version.unwrap_or(0) == 0 {
            self.set_passthrough_mode(true, DAVE_RESET_PASSTHROUGH_WINDOW);
            self.send_transition_ready(
                &mut commands,
                observer,
                dave.transition_id,
                dave.protocol_version,
            )?;
            return Ok(commands);
        }

        let transition_zero_ready = dave_transition_zero_media_ready(dave, self.transition_ready);
        self.set_passthrough_mode(
            transition_zero_ready && !dave_gateway_media_ready(dave),
            DAVE_TRANSITION_PASSTHROUGH_WINDOW,
        );

        if let Some(external_sender) = dave.external_sender.as_deref()
            && !self.external_sender_set
        {
            self.session
                .set_external_sender(external_sender)
                .map_err(DaveError::SetExternalSender)?;
            self.external_sender_set = true;
            observer.dave_external_sender_set(DaveKeyPackageEvent {
                protocol_version: dave.protocol_version,
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

        if self.processed_proposals > dave.proposals.len() {
            self.processed_proposals = 0;
        }
        if dave.proposals.len() > self.processed_proposals && !roster_authoritative {
            return Ok(commands);
        }
        let expected_user_ids = connected_user_ids.iter().copied().collect::<Vec<_>>();
        for proposals in dave.proposals.iter().skip(self.processed_proposals) {
            let (operation, proposal_bytes) = DaveProposalsOperation::parse(proposals)?;
            let mut commit_sent = false;
            let mut welcome_sent = false;
            match self.session.process_proposals(
                operation.kind,
                proposal_bytes,
                Some(expected_user_ids.as_slice()),
            ) {
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

        if let Some(welcome) = dave.pending_welcome.as_ref()
            && self.processed_welcome.as_ref() != Some(welcome)
        {
            match self.session.process_welcome(welcome) {
                Ok(()) => {
                    self.processed_welcome = Some(welcome.clone());
                    self.send_transition_ready(
                        &mut commands,
                        observer,
                        dave.transition_id,
                        dave.protocol_version,
                    )?;
                }
                Err(error) => {
                    let error = DaveError::ProcessWelcome(error);
                    self.processed_welcome = Some(welcome.clone());
                    if let Some(transition_id) = dave.transition_id {
                        commands.push(GatewayCommand::DaveMlsInvalidCommitWelcome(
                            DaveInvalidCommitWelcomeCommand { transition_id },
                        ));
                    }
                    if let Err(recovery_error) =
                        self.recover_after_invalid_group(&mut commands, dave)
                    {
                        return Err(dave_recovery_error(
                            "welcome processing",
                            error,
                            recovery_error,
                        ));
                    }
                    return Err(error.into());
                }
            }
        }

        if let Some(commit) = dave.pending_commit.as_ref()
            && self.processed_commit.as_ref() != Some(commit)
        {
            match self.session.process_commit(commit) {
                Ok(()) => {
                    self.processed_commit = Some(commit.clone());
                    self.send_transition_ready(
                        &mut commands,
                        observer,
                        dave.transition_id,
                        dave.protocol_version,
                    )?;
                }
                Err(error) => {
                    let error = DaveError::ProcessCommit(error);
                    self.processed_commit = Some(commit.clone());
                    if let Some(transition_id) = dave.transition_id {
                        commands.push(GatewayCommand::DaveMlsInvalidCommitWelcome(
                            DaveInvalidCommitWelcomeCommand { transition_id },
                        ));
                    }
                    if let Err(recovery_error) =
                        self.recover_after_invalid_group(&mut commands, dave)
                    {
                        return Err(dave_recovery_error(
                            "commit processing",
                            error,
                            recovery_error,
                        ));
                    }
                    return Err(error.into());
                }
            }
        }

        self.activate_sender_if_transition_executed(dave);
        Ok(commands)
    }

    fn activate_sender_if_transition_executed(&mut self, dave: &DaveInternalState) {
        if dave.transition_id.is_none()
            && dave.active_send_protocol_version.unwrap_or(0) > 0
            && self.session.activate_staged_sender()
        {
            self.transition_ready = None;
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
            self.processed_welcome = None;
            self.processed_commit = None;
            self.transition_ready = None;
            if prepared_epoch.epoch == 1 {
                self.replace_session(prepared_epoch.protocol_version)?;
            }
        }
        self.prepared_epoch = prepared_epoch;
        Ok(())
    }

    pub(crate) fn replace_session(&mut self, protocol_version: u16) -> Result<()> {
        let protocol_version =
            NonZeroU16::new(protocol_version).ok_or(DaveError::InvalidProtocolVersion {
                version: protocol_version,
            })?;
        self.session = new_dave_session(protocol_version, self.bot_user_id, self.channel_id)?;
        self.external_sender_set = false;
        Ok(())
    }

    pub(crate) fn recover_after_invalid_group(
        &mut self,
        commands: &mut Vec<GatewayCommand>,
        dave: &DaveInternalState,
    ) -> Result<()> {
        let Some(protocol_version) = dave.protocol_version else {
            return Ok(());
        };
        if protocol_version == 0 {
            self.set_passthrough_mode(true, DAVE_RESET_PASSTHROUGH_WINDOW);
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

    pub(crate) fn send_transition_ready<D>(
        &mut self,
        commands: &mut Vec<GatewayCommand>,
        observer: &D,
        transition_id: Option<u16>,
        protocol_version: Option<u16>,
    ) -> Result<()>
    where
        D: ConnectionObserver,
    {
        let Some(transition_id) = transition_id else {
            return Ok(());
        };
        if self.transition_ready == Some(transition_id) {
            return Ok(());
        }
        let protocol_version = protocol_version.unwrap_or(0);
        commands.push(GatewayCommand::DaveProtocolTransitionReady(
            DaveTransitionReadyCommand { transition_id },
        ));
        self.transition_ready = Some(transition_id);
        observer.dave_transition_ready_sent(DaveTransitionEvent {
            transition_id,
            protocol_version,
        });
        Ok(())
    }
}

pub(crate) fn dave_recovery_error(
    operation: &'static str,
    original: DaveError,
    recovery: Error,
) -> Error {
    match recovery {
        Error::Dave(_) => DaveError::RecoverInvalidGroup {
            operation,
            original: Box::new(original),
            recovery: Box::new(recovery),
        }
        .into(),
        _ => recovery,
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
        let protocol_version = dave.protocol_version?;
        if protocol_version == 0 {
            return None;
        }
        Some(Self {
            epoch: dave.epoch?,
            protocol_version,
            seq: dave.prepare_epoch_seq,
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
        let protocol_version = dave.protocol_version?;
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
            protocol_version: dave.protocol_version,
            transition_id: dave.transition_id,
            epoch: dave.epoch,
            prepare_epoch_seq: dave.prepare_epoch_seq,
            passthrough: dave.passthrough,
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
    pub active: bool,
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

pub(crate) fn dave_gateway_media_ready(dave: &DaveInternalState) -> bool {
    dave.transition_id.is_none()
        && dave.pending_commit.is_none()
        && dave.pending_welcome.is_none()
        && dave.proposals.is_empty()
}

pub(crate) fn dave_send_active(dave: &DaveInternalState) -> bool {
    dave.active_send_protocol_version.unwrap_or(0) > 0
}

pub(crate) fn dave_send_media_ready(
    active: bool,
    session_ready: bool,
    send_ready: bool,
    gateway_ready: bool,
) -> bool {
    !active || (session_ready && send_ready && gateway_ready)
}

pub(crate) fn dave_receive_transform_active(dave: &DaveInternalState) -> bool {
    dave.active_receive_protocol_version.unwrap_or(0) > 0
}

pub(crate) fn dave_transition_zero_media_ready(
    dave: &DaveInternalState,
    transition_ready: Option<u16>,
) -> bool {
    dave.transition_id == Some(0) && transition_ready == Some(0)
}

pub(crate) fn dave_decrypt_failure_can_become_recoverable(kind: ReceiveDecodeErrorKind) -> bool {
    matches!(
        kind,
        ReceiveDecodeErrorKind::DaveNoDecryptorForUser
            | ReceiveDecodeErrorKind::DaveNoValidCryptor
            | ReceiveDecodeErrorKind::DaveOtherDecryptError
    )
}

pub(crate) fn dave_decrypt_failure_should_retry(
    kind: ReceiveDecodeErrorKind,
    state_can_still_change: bool,
) -> bool {
    dave_decrypt_failure_can_become_recoverable(kind) && state_can_still_change
}
