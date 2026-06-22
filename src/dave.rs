use super::*;

pub(crate) struct VoiceDaveySession {
    session: DaveSession,
}

impl VoiceDaveySession {
    pub(crate) fn new(
        protocol_version: NonZeroU16,
        user_id: u64,
        channel_id: u64,
    ) -> Result<Self, VoiceDaveError> {
        Ok(Self {
            session: DaveSession::new(protocol_version, user_id, channel_id, None).map_err(
                |error| VoiceDaveError::CreateSession {
                    detail: error.to_string(),
                },
            )?,
        })
    }

    pub(crate) fn discord_default(user_id: u64, channel_id: u64) -> Result<Self, VoiceDaveError> {
        let protocol_version = NonZeroU16::new(DAVE_PROTOCOL_VERSION).ok_or(
            VoiceDaveError::InvalidProtocolVersion {
                version: DAVE_PROTOCOL_VERSION,
            },
        )?;
        Self::new(protocol_version, user_id, channel_id)
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.session.is_ready()
    }

    pub(crate) fn set_external_sender(
        &mut self,
        external_sender: &[u8],
    ) -> Result<(), VoiceDaveError> {
        self.session
            .set_external_sender(external_sender)
            .map_err(|error| VoiceDaveError::SetExternalSender {
                detail: error.to_string(),
            })
    }

    pub(crate) fn create_key_package(&mut self) -> Result<Vec<u8>, VoiceDaveError> {
        self.session
            .create_key_package()
            .map_err(|error| VoiceDaveError::CreateKeyPackage {
                detail: error.to_string(),
            })
    }

    pub(crate) fn process_welcome(&mut self, welcome: &[u8]) -> Result<(), VoiceDaveError> {
        self.session
            .process_welcome(welcome)
            .map_err(|error| VoiceDaveError::ProcessWelcome {
                detail: error.to_string(),
            })
    }

    pub(crate) fn process_commit(&mut self, commit: &[u8]) -> Result<(), VoiceDaveError> {
        self.session
            .process_commit(commit)
            .map_err(|error| VoiceDaveError::ProcessCommit {
                detail: error.to_string(),
            })
    }

    pub(crate) fn process_proposals(
        &mut self,
        operation_type: ProposalsOperationType,
        proposals: &[u8],
        expected_user_ids: Option<&[u64]>,
    ) -> Result<Option<davey::CommitWelcome>, VoiceDaveError> {
        self.session
            .process_proposals(operation_type, proposals, expected_user_ids)
            .map_err(|error| VoiceDaveError::ProcessProposals {
                detail: error.to_string(),
            })
    }

    pub(crate) fn set_passthrough_mode(&mut self, enabled: bool, transition_expiry: Option<u32>) {
        self.session
            .set_passthrough_mode(enabled, transition_expiry);
    }

    pub(crate) fn encrypt_opus_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, VoiceDaveError> {
        self.session
            .encrypt_opus(frame)
            .map(|frame| frame.into_owned())
            .map_err(|error| VoiceDaveError::Encrypt(error.into()))
    }

    pub(crate) fn decrypt_frame(
        &mut self,
        user_id: Option<u64>,
        frame: &[u8],
    ) -> Result<Vec<u8>, VoiceDaveDecryptError> {
        self.session
            .decrypt(
                user_id.ok_or(VoiceDaveDecryptError::MissingUser)?,
                MediaType::AUDIO,
                frame,
            )
            .map_err(VoiceDaveDecryptError::from)
    }
}

pub(crate) struct VoiceDaveCoordinator {
    session: VoiceDaveySession,
    bot_user_id: u64,
    voice_channel_id: u64,
    external_sender_set: bool,
    sent_key_package_for: Option<VoiceDaveKeyPackageScope>,
    processed_proposals: usize,
    processed_welcome: Option<Vec<u8>>,
    processed_commit: Option<Vec<u8>>,
    transition_ready: Option<u16>,
    prepared_epoch: Option<VoiceDavePreparedEpoch>,
    last_gateway_state: Option<VoiceDaveGatewayStateEvent>,
    passthrough_enabled: bool,
}

impl VoiceDaveCoordinator {
    pub(crate) fn new(bot_user_id: u64, voice_channel_id: u64) -> VoiceResult<Self> {
        Ok(Self {
            session: VoiceDaveySession::discord_default(bot_user_id, voice_channel_id)?,
            bot_user_id,
            voice_channel_id,
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
        self.session.is_ready()
    }

    pub(crate) fn transition_ready(&self) -> Option<u16> {
        self.transition_ready
    }

    pub(crate) fn session_mut(&mut self) -> &mut VoiceDaveySession {
        &mut self.session
    }

    pub(crate) fn set_passthrough_mode(&mut self, enabled: bool, transition_expiry: Option<u32>) {
        if self.passthrough_enabled == enabled {
            return;
        }
        self.session
            .set_passthrough_mode(enabled, transition_expiry);
        self.passthrough_enabled = enabled;
    }

    pub(crate) fn pump<D>(
        &mut self,
        dave: &VoiceDaveInternalState,
        connected_user_ids: &HashSet<u64>,
        roster_authoritative: bool,
        observer: &D,
    ) -> VoiceResult<Vec<VoiceGatewayCommand>>
    where
        D: VoiceConnectionObserver,
    {
        let mut commands = Vec::new();
        self.observe_gateway_state(observer, dave);
        self.sync_prepared_epoch(dave)?;

        if dave.protocol_version.unwrap_or(0) == 0 {
            self.set_passthrough_mode(true, Some(120));
            self.send_transition_ready(
                &mut commands,
                observer,
                dave.transition_id,
                dave.protocol_version,
            )?;
            return Ok(commands);
        }

        let transition_zero_ready =
            voice_dave_transition_zero_media_ready(dave, self.transition_ready);
        self.set_passthrough_mode(
            transition_zero_ready && !voice_dave_gateway_media_ready(dave),
            Some(10),
        );

        if let Some(external_sender) = dave.external_sender.as_deref()
            && !self.external_sender_set
        {
            self.session.set_external_sender(external_sender)?;
            self.external_sender_set = true;
            observer.dave_external_sender_set(VoiceDaveKeyPackageEvent {
                protocol_version: dave.protocol_version,
            });
        }

        if let Some(key_package_scope) =
            VoiceDaveKeyPackageScope::from_state(dave, self.prepared_epoch)
            && self.sent_key_package_for != Some(key_package_scope)
        {
            commands.push(VoiceGatewayCommand::DaveMlsKeyPackage {
                key_package: self.session.create_key_package()?,
            });
            self.sent_key_package_for = Some(key_package_scope);
            observer.dave_key_package_sent(VoiceDaveKeyPackageEvent {
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
            let (operation, proposal_bytes) = VoiceDaveProposalsOperation::parse(proposals)?;
            let mut commit_sent = false;
            let mut welcome_sent = false;
            match self.session.process_proposals(
                operation.kind,
                proposal_bytes,
                Some(expected_user_ids.as_slice()),
            ) {
                Ok(Some(commit_welcome)) => {
                    welcome_sent = commit_welcome.welcome.is_some();
                    commands.push(VoiceGatewayCommand::DaveMlsCommitWelcome {
                        commit: commit_welcome.commit,
                        welcome: commit_welcome.welcome,
                    });
                    commit_sent = true;
                }
                Ok(None) => {}
                Err(error) => {
                    self.processed_proposals += 1;
                    observer.dave_proposals_ignored(VoiceDaveIgnoredProposalsEvent {
                        operation: operation.label,
                        proposal_bytes: proposal_bytes.len(),
                        error: error.to_string(),
                    });
                    continue;
                }
            }
            self.processed_proposals += 1;
            observer.dave_proposals_processed(VoiceDaveProposalsEvent {
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
                    self.processed_welcome = Some(welcome.clone());
                    if let Some(transition_id) = dave.transition_id {
                        commands.push(VoiceGatewayCommand::DaveMlsInvalidCommitWelcome(
                            VoiceDaveInvalidCommitWelcomeCommand { transition_id },
                        ));
                    }
                    if let Err(recovery_error) =
                        self.recover_after_invalid_group(&mut commands, dave)
                    {
                        return Err(voice_dave_recovery_error(
                            "welcome processing",
                            &error,
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
                    self.processed_commit = Some(commit.clone());
                    if let Some(transition_id) = dave.transition_id {
                        commands.push(VoiceGatewayCommand::DaveMlsInvalidCommitWelcome(
                            VoiceDaveInvalidCommitWelcomeCommand { transition_id },
                        ));
                    }
                    if let Err(recovery_error) =
                        self.recover_after_invalid_group(&mut commands, dave)
                    {
                        return Err(voice_dave_recovery_error(
                            "commit processing",
                            &error,
                            recovery_error,
                        ));
                    }
                    return Err(error.into());
                }
            }
        }

        Ok(commands)
    }

    pub(crate) fn sync_prepared_epoch(&mut self, dave: &VoiceDaveInternalState) -> VoiceResult<()> {
        let prepared_epoch = VoiceDavePreparedEpoch::from_state(dave);
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

    pub(crate) fn replace_session(&mut self, protocol_version: u16) -> VoiceResult<()> {
        let protocol_version =
            NonZeroU16::new(protocol_version).ok_or(VoiceDaveError::InvalidProtocolVersion {
                version: protocol_version,
            })?;
        self.session =
            VoiceDaveySession::new(protocol_version, self.bot_user_id, self.voice_channel_id)?;
        self.external_sender_set = false;
        Ok(())
    }

    pub(crate) fn recover_after_invalid_group(
        &mut self,
        commands: &mut Vec<VoiceGatewayCommand>,
        dave: &VoiceDaveInternalState,
    ) -> VoiceResult<()> {
        let Some(protocol_version) = dave.protocol_version else {
            return Ok(());
        };
        if protocol_version == 0 {
            self.set_passthrough_mode(true, Some(120));
            return Ok(());
        }

        self.replace_session(protocol_version)?;
        if let Some(external_sender) = dave.external_sender.as_deref() {
            self.session.set_external_sender(external_sender)?;
            self.external_sender_set = true;
        }
        if let Some(key_package_scope) =
            VoiceDaveKeyPackageScope::from_state(dave, self.prepared_epoch)
        {
            commands.push(VoiceGatewayCommand::DaveMlsKeyPackage {
                key_package: self.session.create_key_package()?,
            });
            self.sent_key_package_for = Some(key_package_scope);
        }
        self.processed_proposals = dave.proposals.len();
        Ok(())
    }

    pub(crate) fn observe_gateway_state(
        &mut self,
        observer: &impl VoiceConnectionObserver,
        dave: &VoiceDaveInternalState,
    ) {
        let gateway_state = VoiceDaveGatewayStateEvent::from_state(dave);
        if self.last_gateway_state.as_ref() == Some(&gateway_state) {
            return;
        }
        self.last_gateway_state = Some(gateway_state.clone());
        observer.dave_gateway_state(gateway_state);
    }

    pub(crate) fn send_transition_ready<D>(
        &mut self,
        commands: &mut Vec<VoiceGatewayCommand>,
        observer: &D,
        transition_id: Option<u16>,
        protocol_version: Option<u16>,
    ) -> VoiceResult<()>
    where
        D: VoiceConnectionObserver,
    {
        let Some(transition_id) = transition_id else {
            return Ok(());
        };
        if self.transition_ready == Some(transition_id) {
            return Ok(());
        }
        let protocol_version = protocol_version.unwrap_or(0);
        commands.push(VoiceGatewayCommand::DaveProtocolTransitionReady(
            VoiceDaveTransitionReadyCommand { transition_id },
        ));
        self.transition_ready = Some(transition_id);
        observer.dave_transition_ready_sent(VoiceDaveTransitionEvent {
            transition_id,
            protocol_version,
        });
        Ok(())
    }
}

pub(crate) fn voice_dave_recovery_error(
    operation: &'static str,
    original: &VoiceDaveError,
    recovery: VoiceError,
) -> VoiceError {
    let detail = format!("after {operation} error ({original}): {recovery}");
    match recovery {
        VoiceError::Dave(_) => VoiceDaveError::RecoverInvalidGroup { detail }.into(),
        _ => recovery,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VoiceDavePreparedEpoch {
    epoch: u64,
    protocol_version: u16,
    seq: u64,
}

impl VoiceDavePreparedEpoch {
    pub(crate) fn from_state(dave: &VoiceDaveInternalState) -> Option<Self> {
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
pub(crate) enum VoiceDaveKeyPackageScope {
    Session { protocol_version: u16 },
    Epoch(VoiceDavePreparedEpoch),
}

impl VoiceDaveKeyPackageScope {
    pub(crate) fn from_state(
        dave: &VoiceDaveInternalState,
        prepared_epoch: Option<VoiceDavePreparedEpoch>,
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
pub struct VoiceDaveGatewayStateEvent {
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub epoch: Option<u64>,
    pub prepare_epoch_seq: u64,
    pub passthrough: bool,
    pub mls: VoiceDaveMlsState,
}

impl VoiceDaveGatewayStateEvent {
    pub(crate) fn from_state(dave: &VoiceDaveInternalState) -> Self {
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
pub struct VoiceDaveKeyPackageEvent {
    pub protocol_version: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveTransitionEvent {
    pub transition_id: u16,
    pub protocol_version: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveProposalsEvent {
    pub operation: &'static str,
    pub proposal_bytes: usize,
    pub commit_sent: bool,
    pub welcome_sent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveIgnoredProposalsEvent {
    pub operation: &'static str,
    pub proposal_bytes: usize,
    pub error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceDaveMediaStatus {
    pub active: bool,
    pub media_ready: bool,
    pub session_ready: bool,
    pub transition_ready: Option<u16>,
    pub protocol_version: Option<u16>,
    pub transition_id: Option<u16>,
    pub mls: VoiceDaveMlsState,
}

pub(crate) struct VoiceDaveProposalsOperation {
    kind: ProposalsOperationType,
    label: &'static str,
}

impl VoiceDaveProposalsOperation {
    pub(crate) fn parse(payload: &[u8]) -> Result<(Self, &[u8]), VoiceDaveError> {
        let Some((&operation, proposals)) = payload.split_first() else {
            return Err(VoiceDaveError::InvalidProposalsPayload {
                detail: "payload was empty".to_string(),
            });
        };
        let (kind, label) = match operation {
            0 => (ProposalsOperationType::APPEND, "append"),
            1 => (ProposalsOperationType::REVOKE, "revoke"),
            other => {
                return Err(VoiceDaveError::InvalidProposalsPayload {
                    detail: format!("unknown proposals operation type {other}"),
                });
            }
        };
        Ok((Self { kind, label }, proposals))
    }
}

pub(crate) fn voice_dave_gateway_media_ready(dave: &VoiceDaveInternalState) -> bool {
    dave.transition_id.is_none()
        && dave.pending_commit.is_none()
        && dave.pending_welcome.is_none()
        && dave.proposals.is_empty()
}

pub(crate) fn voice_dave_transition_zero_media_ready(
    dave: &VoiceDaveInternalState,
    transition_ready: Option<u16>,
) -> bool {
    dave.transition_id == Some(0) && transition_ready == Some(0)
}

pub(crate) fn voice_dave_decrypt_failure_can_become_recoverable(
    kind: VoiceReceiveDecodeErrorKind,
) -> bool {
    matches!(
        kind,
        VoiceReceiveDecodeErrorKind::DaveNoDecryptorForUser
            | VoiceReceiveDecodeErrorKind::DaveNoValidCryptor
            | VoiceReceiveDecodeErrorKind::DaveOtherDecryptError
    )
}

pub(crate) fn voice_dave_decrypt_failure_should_retry(
    kind: VoiceReceiveDecodeErrorKind,
    state_can_still_change: bool,
) -> bool {
    voice_dave_decrypt_failure_can_become_recoverable(kind) && state_can_still_change
}
