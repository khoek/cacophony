use super::*;

#[derive(Clone)]
pub struct VoiceConnection<O: VoiceConnectionObserver = NoopVoiceConnectionObserver> {
    pub(crate) inner: Arc<VoiceConnectionInner<O>>,
}

#[derive(Clone)]
pub(crate) struct VoiceConnectionStateChannels {
    internal_tx: watch::Sender<VoiceConnectionInternalState>,
    public_tx: watch::Sender<VoiceConnectionState>,
}

impl VoiceConnectionStateChannels {
    pub(crate) fn new(initial: VoiceConnectionInternalState) -> Self {
        let public = initial.public_state();
        let (internal_tx, _) = watch::channel(initial);
        let (public_tx, _) = watch::channel(public);
        Self {
            internal_tx,
            public_tx,
        }
    }

    pub(crate) fn internal(&self) -> watch::Ref<'_, VoiceConnectionInternalState> {
        self.internal_tx.borrow()
    }

    pub(crate) fn subscribe_public(&self) -> watch::Receiver<VoiceConnectionState> {
        self.public_tx.subscribe()
    }

    pub(crate) fn update(&self, update: impl FnOnce(&mut VoiceConnectionInternalState)) {
        self.internal_tx.send_modify(update);
        self.public_tx
            .send_replace(self.internal_tx.borrow().public_state());
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VoiceConnectionClose {
    closed: watch::Sender<bool>,
    closed_once: Arc<AtomicBool>,
}

impl VoiceConnectionClose {
    pub(crate) fn new() -> Self {
        let (closed, _) = watch::channel(false);
        Self {
            closed,
            closed_once: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn close(&self) -> bool {
        if !self.closed_once.swap(true, Ordering::AcqRel) {
            self.closed.send_replace(true);
            true
        } else {
            false
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed_once.load(Ordering::Acquire)
    }

    pub(crate) async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        loop {
            if *closed.borrow_and_update() {
                return;
            }
            if closed.changed().await.is_err() {
                return;
            }
        }
    }
}

pub(crate) struct VoiceConnectionInner<O: VoiceConnectionObserver> {
    pub(crate) state_rx: watch::Receiver<VoiceConnectionState>,
    pub(crate) command_tx: mpsc::Sender<VoiceConnectionCommand>,
    pub(crate) close: VoiceConnectionClose,
    pub(crate) join_tx: mpsc::Sender<VoiceConnectionJoinCommand>,
    pub(crate) abort: tokio::task::AbortHandle,
    pub(crate) observer: O,
}

pub(crate) enum VoiceConnectionJoinCommand {
    Wait {
        reply: oneshot::Sender<VoiceResult<()>>,
    },
}

pub(crate) fn spawn_voice_connection_join_task(
    task: JoinHandle<VoiceResult<()>>,
) -> mpsc::Sender<VoiceConnectionJoinCommand> {
    let (join_tx, mut join_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut task = Some(task);
        while let Some(command) = join_rx.recv().await {
            match command {
                VoiceConnectionJoinCommand::Wait { reply } => {
                    let result = match task.take() {
                        Some(task) => match task.await {
                            Ok(result) => result,
                            Err(error) => Err(VoiceError::Join(format!(
                                "voice control task join failed: {error}"
                            ))),
                        },
                        None => Ok(()),
                    };
                    let _ = reply.send(result);
                }
            }
        }
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        Ok::<(), VoiceError>(())
    });
    join_tx
}

impl<O: VoiceConnectionObserver> Drop for VoiceConnectionInner<O> {
    fn drop(&mut self) {
        let state = self.state_rx.borrow();
        self.observer
            .connection_dropped(state.connection.connection_event());
        self.close.close();
        self.abort.abort();
    }
}

impl<O: VoiceConnectionObserver> VoiceConnection<O> {
    pub fn state(&self) -> VoiceConnectionState {
        self.inner.state_rx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<VoiceConnectionState> {
        self.inner.state_rx.clone()
    }

    pub fn running(&self) -> bool {
        !self.inner.close.is_closed()
    }

    pub fn close(&self) -> bool {
        self.inner.close.close()
    }

    pub async fn close_and_wait(&self) -> VoiceResult<()> {
        self.close();
        let _ = self
            .inner
            .command_tx
            .try_send(VoiceConnectionCommand::Close);
        let (reply, response) = oneshot::channel();
        self.inner
            .join_tx
            .send(VoiceConnectionJoinCommand::Wait { reply })
            .await
            .map_err(|_| VoiceError::Join("voice join task is closed".to_string()))?;
        response
            .await
            .map_err(|_| VoiceError::Join("voice join task stopped before replying".to_string()))?
    }

    fn ensure_open(&self) -> VoiceResult<()> {
        if self.inner.close.is_closed() {
            Err(VoiceError::Closed)
        } else {
            Ok(())
        }
    }

    pub async fn dave_media_status(&self) -> VoiceDaveMediaStatus {
        let (response, receive) = oneshot::channel();
        if self
            .send_command(VoiceConnectionCommand::DaveMediaStatus { response })
            .is_ok()
            && let Ok(status) = receive.await
        {
            return status;
        }
        voice_dave_media_status_from_public_state(&self.state())
    }

    pub async fn wait_until_media_ready(
        &self,
        max_wait: Duration,
    ) -> VoiceResult<VoiceDaveMediaStatus> {
        self.request_result(|response| VoiceConnectionCommand::WaitUntilMediaReady {
            max_wait,
            response,
        })
        .await
    }

    pub async fn recv_raw_udp_packet(&self, max_len: usize) -> VoiceResult<VoiceRawUdpPacket> {
        if max_len == 0 {
            return Err(VoiceError::invalid_input(
                "max_len must be greater than zero",
            ));
        }
        self.request_result(|response| VoiceConnectionCommand::RecvRawUdpPacket {
            max_len,
            response,
        })
        .await
    }

    pub async fn recv_rtp_udp_packet(&self, max_len: usize) -> VoiceResult<VoiceRawUdpPacket> {
        if max_len == 0 {
            return Err(VoiceError::invalid_input(
                "max_len must be greater than zero",
            ));
        }
        self.request_result(|response| VoiceConnectionCommand::RecvRtpUdpPacket {
            max_len,
            response,
        })
        .await
    }

    pub async fn recv_voice_frame(&self, max_len: usize) -> VoiceResult<VoiceReceivedFrame> {
        if max_len == 0 {
            return Err(VoiceError::invalid_input(
                "max_len must be greater than zero",
            ));
        }
        self.request_result(|response| VoiceConnectionCommand::RecvVoiceFrame { max_len, response })
            .await
    }

    pub async fn recv_voice_frame_timeout(
        &self,
        max_len: usize,
        max_wait: Duration,
    ) -> VoiceResult<Option<VoiceReceivedFrame>> {
        if max_len == 0 {
            return Err(VoiceError::invalid_input(
                "max_len must be greater than zero",
            ));
        }
        match self
            .request_result(|response| VoiceConnectionCommand::RecvVoiceFrameTimeout {
                max_len,
                max_wait,
                response,
            })
            .await
        {
            Ok(frame) => Ok(Some(frame)),
            Err(VoiceError::Timeout {
                stage: None,
                duration,
            }) if duration == max_wait => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn recv_decoded_voice_frame(
        &self,
        decoder: &mut VoiceOpusDecoder,
        max_len: usize,
    ) -> VoiceResult<VoiceDecodedFrame> {
        let frame = self.recv_voice_frame(max_len).await?;
        let ssrc = frame.rtp.ssrc;
        let user_id = frame.user_id;
        let seq = frame.rtp.seq;
        match decoder.decode_frame(frame) {
            Ok(decoded) => Ok(decoded),
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Opus,
                    VoiceReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(seq),
                    error.to_string(),
                );
                Err(error)
            }
        }
    }

    pub async fn recv_decoded_voice_frame_timeout(
        &self,
        decoder: &mut VoiceOpusDecoder,
        max_len: usize,
        max_wait: Duration,
    ) -> VoiceResult<Option<VoiceDecodedFrame>> {
        let Some(frame) = self.recv_voice_frame_timeout(max_len, max_wait).await? else {
            return Ok(None);
        };
        let ssrc = frame.rtp.ssrc;
        let user_id = frame.user_id;
        let seq = frame.rtp.seq;
        match decoder.decode_frame(frame) {
            Ok(decoded) => Ok(Some(decoded)),
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Opus,
                    VoiceReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(seq),
                    error.to_string(),
                );
                Err(error)
            }
        }
    }

    pub async fn recv_decoded_voice_frame_into(
        &self,
        decoder: &mut VoiceOpusDecoder,
        max_len: usize,
        pcm: &mut Vec<i16>,
    ) -> VoiceResult<VoiceDecodedFrameMetadata> {
        let frame = self.recv_voice_frame(max_len).await?;
        let ssrc = frame.rtp.ssrc;
        let user_id = frame.user_id;
        let seq = frame.rtp.seq;
        match decoder.decode_frame_into(frame, pcm) {
            Ok(decoded) => Ok(decoded),
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Opus,
                    VoiceReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(seq),
                    error.to_string(),
                );
                Err(error)
            }
        }
    }

    fn observe_decode_error(
        &self,
        stage: VoiceReceiveDecodeStage,
        kind: VoiceReceiveDecodeErrorKind,
        ssrc: Option<u32>,
        user_id: Option<u64>,
        seq: Option<u16>,
        detail: String,
    ) {
        if O::ENABLE_RECEIVE_TELEMETRY {
            self.inner
                .observer
                .receive_decode_error(VoiceReceiveDecodeErrorEvent {
                    stage,
                    kind,
                    ssrc,
                    user_id,
                    seq,
                    detail,
                });
        }
    }

    fn send_command(&self, command: VoiceConnectionCommand) -> VoiceResult<()> {
        self.ensure_open()?;
        match self.inner.command_tx.try_send(command) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(VoiceError::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => Err(VoiceError::Backpressure(
                "voice connection command queue is full".to_string(),
            )),
        }
    }

    async fn request_result<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<VoiceResult<T>>) -> VoiceConnectionCommand,
    ) -> VoiceResult<T> {
        let (response, receive) = oneshot::channel();
        self.send_command(build(response))?;
        receive.await.map_err(|_| VoiceError::Closed)?
    }

    pub fn set_speaking(&self, flags: VoiceSpeakingFlags, delay: u32) -> VoiceResult<()> {
        self.send_command(VoiceConnectionCommand::SetSpeaking { flags, delay })
    }

    pub async fn send_opus_frame(
        &self,
        frame: &[u8],
        duration: Duration,
    ) -> VoiceResult<VoiceOutboundPacket> {
        self.send_opus_bytes_owned(frame.to_vec(), duration).await
    }

    pub async fn send_opus_frame_owned(
        &self,
        frame: VoiceOpusFrame,
    ) -> VoiceResult<VoiceOutboundPacket> {
        self.send_opus_bytes_owned(frame.bytes, frame.duration)
            .await
    }

    pub async fn send_opus_bytes_owned(
        &self,
        frame: Vec<u8>,
        duration: Duration,
    ) -> VoiceResult<VoiceOutboundPacket> {
        self.request_result(|response| VoiceConnectionCommand::SendOpusFrame {
            frame,
            duration,
            response,
        })
        .await
    }
}

pub(crate) enum VoiceConnectionCommand {
    SetSpeaking {
        flags: VoiceSpeakingFlags,
        delay: u32,
    },
    SendOpusFrame {
        frame: Vec<u8>,
        duration: Duration,
        response: oneshot::Sender<VoiceResult<VoiceOutboundPacket>>,
    },
    RecvRawUdpPacket {
        max_len: usize,
        response: oneshot::Sender<VoiceResult<VoiceRawUdpPacket>>,
    },
    RecvRtpUdpPacket {
        max_len: usize,
        response: oneshot::Sender<VoiceResult<VoiceRawUdpPacket>>,
    },
    RecvVoiceFrame {
        max_len: usize,
        response: oneshot::Sender<VoiceResult<VoiceReceivedFrame>>,
    },
    RecvVoiceFrameTimeout {
        max_len: usize,
        max_wait: Duration,
        response: oneshot::Sender<VoiceResult<VoiceReceivedFrame>>,
    },
    DaveMediaStatus {
        response: oneshot::Sender<VoiceDaveMediaStatus>,
    },
    WaitUntilMediaReady {
        max_wait: Duration,
        response: oneshot::Sender<VoiceResult<VoiceDaveMediaStatus>>,
    },
    Close,
}

impl VoiceConnectionCommand {
    pub(crate) fn complete_closed(self) {
        match self {
            Self::SendOpusFrame { response, .. } => {
                let _ = response.send(Err(VoiceError::Closed));
            }
            Self::RecvRawUdpPacket { response, .. } | Self::RecvRtpUdpPacket { response, .. } => {
                let _ = response.send(Err(VoiceError::Closed));
            }
            Self::RecvVoiceFrame { response, .. }
            | Self::RecvVoiceFrameTimeout { response, .. } => {
                let _ = response.send(Err(VoiceError::Closed));
            }
            Self::DaveMediaStatus { response } => {
                let _ = response.send(VoiceDaveMediaStatus {
                    active: false,
                    media_ready: false,
                    session_ready: false,
                    transition_ready: None,
                    protocol_version: None,
                    transition_id: None,
                    mls: VoiceDaveMlsState::default(),
                });
            }
            Self::WaitUntilMediaReady { response, .. } => {
                let _ = response.send(Err(VoiceError::Closed));
            }
            Self::SetSpeaking { .. } | Self::Close => {}
        }
    }
}

pub(crate) struct PendingSendOpusFrame {
    frame: Vec<u8>,
    duration: Duration,
    response: oneshot::Sender<VoiceResult<VoiceOutboundPacket>>,
    deadline: Instant,
}

pub(crate) struct PendingMediaReadyWait {
    response: oneshot::Sender<VoiceResult<VoiceDaveMediaStatus>>,
    deadline: Instant,
    max_wait: Duration,
}

pub(crate) enum PendingReceive {
    Raw {
        max_len: usize,
        response: oneshot::Sender<VoiceResult<VoiceRawUdpPacket>>,
    },
    Rtp {
        max_len: usize,
        response: oneshot::Sender<VoiceResult<VoiceRawUdpPacket>>,
    },
    Frame {
        max_len: usize,
        deadline: Option<Instant>,
        max_wait: Option<Duration>,
        response: oneshot::Sender<VoiceResult<VoiceReceivedFrame>>,
    },
}

impl PendingReceive {
    fn max_len(&self) -> usize {
        match self {
            Self::Raw { max_len, .. } | Self::Rtp { max_len, .. } | Self::Frame { max_len, .. } => {
                *max_len
            }
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Raw { .. } | Self::Rtp { .. } => None,
            Self::Frame { deadline, .. } => *deadline,
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Self::Raw { response, .. } | Self::Rtp { response, .. } => response.is_closed(),
            Self::Frame { response, .. } => response.is_closed(),
        }
    }

    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|deadline| now >= deadline)
    }

    fn complete_closed(self) {
        match self {
            Self::Raw { response, .. } | Self::Rtp { response, .. } => {
                let _ = response.send(Err(VoiceError::Closed));
            }
            Self::Frame { response, .. } => {
                let _ = response.send(Err(VoiceError::Closed));
            }
        }
    }

    pub(crate) fn complete_timeout(self) {
        match self {
            Self::Frame {
                response,
                max_wait: Some(duration),
                ..
            } => {
                let _ = response.send(Err(VoiceError::Timeout {
                    stage: None,
                    duration,
                }));
            }
            request => request.complete_closed(),
        }
    }
}

pub(crate) struct VoiceConnectionDriver<O: VoiceConnectionObserver> {
    write: VoiceWebSocketWrite,
    read: VoiceWebSocketRead,
    command_rx: mpsc::Receiver<VoiceConnectionCommand>,
    close: VoiceConnectionClose,
    state: VoiceConnectionStateChannels,
    observer: O,
    udp_socket: UdpSocket,
    outbound_rtp: VoiceOutboundRtpState,
    dave: VoiceDaveCoordinator,
    receive: VoiceReceiveState,
    receive_buffer: Vec<u8>,
    pending_receives: VecDeque<PendingReceive>,
    pending_sends: VecDeque<PendingSendOpusFrame>,
    pending_media_ready_waits: VecDeque<PendingMediaReadyWait>,
}

impl<O: VoiceConnectionObserver> VoiceConnectionDriver<O> {
    async fn run(mut self) -> VoiceResult<()> {
        let result = self.run_loop().await;
        self.close.close();
        self.complete_pending_closed();
        if let Err(error) = &result {
            let connection = self.state.internal().config.public_info();
            self.observer
                .control_task_failed(VoiceConnectionErrorEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.server_id,
                    user_id: connection.user_id,
                    error,
                });
        }
        result
    }

    async fn run_loop(&mut self) -> VoiceResult<()> {
        let mut heartbeat = interval(Duration::from_millis(
            self.state.internal().heartbeat_interval_ms,
        ));
        heartbeat.tick().await;
        let mut heartbeat_nonce = initial_voice_heartbeat_nonce();
        let mut heartbeat_ack_pending = false;
        let mut heartbeat_sent_at: Option<Instant> = None;
        let heartbeat_ack_timeout =
            voice_heartbeat_ack_timeout(self.state.internal().heartbeat_interval_ms);

        self.pump_dave().await?;
        self.resolve_pending_media_ready_waits();

        loop {
            self.discard_inactive_pending_receives();
            self.resolve_pending_receives()?;
            self.discard_inactive_pending_receives();
            self.resolve_pending_media_ready_waits();
            self.resolve_pending_sends().await?;

            let pending_receive_max_len =
                self.pending_receives.front().map(PendingReceive::max_len);
            if let Some(max_len) = pending_receive_max_len {
                self.receive_buffer.resize(max_len, 0);
            }
            let wake_deadline = self.next_driver_wake_deadline();

            tokio::select! {
                _ = heartbeat.tick() => {
                    if heartbeat_ack_pending {
                        if heartbeat_sent_at.is_some_and(|sent_at| {
                            sent_at.elapsed() >= heartbeat_ack_timeout
                        }) {
                            return Err(VoiceError::protocol("voice heartbeat ACK timed out"));
                        }
                        continue;
                    }
                    let heartbeat_command = VoiceGatewayCommand::Heartbeat(VoiceHeartbeatCommand {
                        t: next_voice_heartbeat_nonce(&mut heartbeat_nonce),
                        seq_ack: self.state.internal().last_seq,
                    });
                    self.send_voice_gateway_command(heartbeat_command).await?;
                    heartbeat_ack_pending = true;
                    heartbeat_sent_at = Some(Instant::now());
                }
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => self.handle_command(command).await?,
                        None => {
                            self.close.close();
                            let _ = self.write.send(WsMessage::Close(None)).await;
                            break;
                        }
                    }
                }
                () = self.close.closed() => {
                    let _ = self.write.send(WsMessage::Close(None)).await;
                    break;
                }
                received = self.udp_socket.recv(&mut self.receive_buffer), if pending_receive_max_len.is_some() => {
                    let started = O::ENABLE_TIMING.then(Instant::now);
                    let received = received?;
                    let bytes = self.receive_buffer[..received].to_vec();
                    if let Some(started) = started {
                        let connection = self.state.internal().config.public_info();
                        self.observer.udp_packet_received(VoiceUdpPacketReceivedEvent {
                            endpoint: &connection.endpoint,
                            guild_id: connection.server_id,
                            user_id: connection.user_id,
                            bytes: received,
                            elapsed: started.elapsed(),
                        });
                    }
                    self.handle_received_udp_packet(VoiceRawUdpPacket::from_bytes(bytes))?;
                }
                () = async {
                    if let Some(deadline) = wake_deadline {
                        tokio::time::sleep_until(deadline).await;
                    }
                }, if wake_deadline.is_some() => {}
                message = self.read.next() => {
                    if !self.handle_websocket_message(message, &mut heartbeat_ack_pending, &mut heartbeat_sent_at).await? {
                        break;
                    }
                    self.pump_dave().await?;
                    self.resolve_pending_media_ready_waits();
                    self.resolve_pending_receives()?;
                }
            }
        }

        Ok(())
    }

    async fn handle_command(&mut self, command: VoiceConnectionCommand) -> VoiceResult<()> {
        match command {
            VoiceConnectionCommand::SetSpeaking { flags, delay } => {
                let ssrc = self.state.internal().ready.ssrc;
                self.send_voice_gateway_command(VoiceGatewayCommand::Speaking(
                    VoiceSpeakingCommand {
                        speaking: flags.bits(),
                        delay: Some(delay),
                        ssrc,
                        user_id: None,
                    },
                ))
                .await?;
            }
            VoiceConnectionCommand::SendOpusFrame {
                frame,
                duration,
                response,
            } => {
                self.pending_sends.push_back(PendingSendOpusFrame {
                    frame,
                    duration,
                    response,
                    deadline: Instant::now() + DAVE_SEND_MEDIA_READY_TIMEOUT,
                });
                self.resolve_pending_sends().await?;
            }
            VoiceConnectionCommand::RecvRawUdpPacket { max_len, response } => {
                self.pending_receives
                    .push_back(PendingReceive::Raw { max_len, response });
            }
            VoiceConnectionCommand::RecvRtpUdpPacket { max_len, response } => {
                self.pending_receives
                    .push_back(PendingReceive::Rtp { max_len, response });
            }
            VoiceConnectionCommand::RecvVoiceFrame { max_len, response } => {
                self.pending_receives.push_back(PendingReceive::Frame {
                    max_len,
                    deadline: None,
                    max_wait: None,
                    response,
                });
                self.resolve_pending_receives()?;
            }
            VoiceConnectionCommand::RecvVoiceFrameTimeout {
                max_len,
                max_wait,
                response,
            } => {
                self.pending_receives.push_back(PendingReceive::Frame {
                    max_len,
                    deadline: Some(Instant::now() + max_wait),
                    max_wait: Some(max_wait),
                    response,
                });
                self.resolve_pending_receives()?;
            }
            VoiceConnectionCommand::DaveMediaStatus { response } => {
                let _ = response.send(self.current_dave_media_status());
            }
            VoiceConnectionCommand::WaitUntilMediaReady { max_wait, response } => {
                self.pending_media_ready_waits
                    .push_back(PendingMediaReadyWait {
                        response,
                        deadline: Instant::now() + max_wait,
                        max_wait,
                    });
                self.resolve_pending_media_ready_waits();
            }
            VoiceConnectionCommand::Close => {
                self.close.close();
                let _ = self.write.send(WsMessage::Close(None)).await;
            }
        }
        Ok(())
    }

    async fn handle_websocket_message(
        &mut self,
        message: Option<Result<WsMessage, tokio_tungstenite::tungstenite::Error>>,
        heartbeat_ack_pending: &mut bool,
        heartbeat_sent_at: &mut Option<Instant>,
    ) -> VoiceResult<bool> {
        let connection = self.state.internal().config.public_info();
        match message {
            Some(Ok(WsMessage::Text(text))) => {
                let event = parse_voice_event_text(&text)?;
                self.observer.websocket_text_event(VoiceWebSocketTextEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.server_id,
                    user_id: connection.user_id,
                    opcode: event.opcode,
                    seq: event.seq,
                });
                if let Some(seq) = event.seq {
                    update_state(&self.state, |state| {
                        state.last_seq = Some(seq);
                    });
                }
                handle_voice_text_event(
                    &self.state,
                    event,
                    heartbeat_ack_pending,
                    heartbeat_sent_at,
                    &self.observer,
                )?;
                Ok(true)
            }
            Some(Ok(WsMessage::Binary(bytes))) => {
                self.observer
                    .websocket_binary_event(VoiceWebSocketBinaryEvent {
                        endpoint: &connection.endpoint,
                        guild_id: connection.server_id,
                        user_id: connection.user_id,
                        bytes: bytes.len(),
                        first_byte: bytes.first().copied(),
                    });
                handle_voice_binary_event(&self.state, &bytes)?;
                Ok(true)
            }
            Some(Ok(WsMessage::Close(frame))) => {
                self.observer.websocket_closed(VoiceWebSocketClosedEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.server_id,
                    user_id: connection.user_id,
                    frame: frame.as_ref().map(VoiceWebSocketCloseFrame::from_frame),
                });
                self.close.close();
                Ok(false)
            }
            Some(Ok(_)) => Ok(true),
            Some(Err(error)) => {
                self.observer
                    .websocket_read_failed(VoiceConnectionErrorEvent {
                        endpoint: &connection.endpoint,
                        guild_id: connection.server_id,
                        user_id: connection.user_id,
                        error: &error,
                    });
                Err(error.into())
            }
            None => {
                self.observer
                    .websocket_stream_ended(connection.connection_event());
                self.close.close();
                Ok(false)
            }
        }
    }

    async fn pump_dave(&mut self) -> VoiceResult<()> {
        let commands = {
            let state = self.state.internal();
            self.dave.pump(
                &state.dave,
                &state.connected_user_ids,
                state.roster_authoritative,
                &self.observer,
            )?
        };
        for command in commands {
            self.send_voice_gateway_command(command).await?;
        }
        Ok(())
    }

    async fn send_voice_gateway_command(
        &mut self,
        command: VoiceGatewayCommand,
    ) -> VoiceResult<()> {
        let connection = self.state.internal().config.public_info();
        if let Some(bytes) = command.binary_payload() {
            if let Err(error) = self.write.send(WsMessage::Binary(bytes.into())).await {
                self.observer
                    .websocket_command_failed(VoiceWebSocketCommandFailedEvent {
                        endpoint: &connection.endpoint,
                        guild_id: connection.server_id,
                        user_id: connection.user_id,
                        frame_kind: VoiceWebSocketFrameKind::Binary,
                        opcode: command.opcode().code(),
                        error: &error,
                    });
                return Err(error.into());
            }
        } else {
            let payload = command.text_payload()?;
            if let Err(error) = self.write.send(WsMessage::Text(payload.into())).await {
                self.observer
                    .websocket_command_failed(VoiceWebSocketCommandFailedEvent {
                        endpoint: &connection.endpoint,
                        guild_id: connection.server_id,
                        user_id: connection.user_id,
                        opcode: command.opcode().code(),
                        frame_kind: VoiceWebSocketFrameKind::Text,
                        error: &error,
                    });
                return Err(error.into());
            }
        }
        Ok(())
    }

    async fn resolve_pending_sends(&mut self) -> VoiceResult<()> {
        loop {
            let Some(send) = self.pending_sends.front() else {
                return Ok(());
            };
            if self.dave_active() && !self.current_dave_media_status().media_ready {
                if Instant::now() >= send.deadline {
                    let send = self.pending_sends.pop_front().expect("front checked");
                    let _ = send.response.send(Err(VoiceError::Timeout {
                        stage: None,
                        duration: DAVE_SEND_MEDIA_READY_TIMEOUT,
                    }));
                    continue;
                }
                return Ok(());
            }

            let send = self.pending_sends.pop_front().expect("front checked");
            let result = self.send_ready_opus_frame(send.frame, send.duration).await;
            let _ = send.response.send(result);
        }
    }

    async fn send_ready_opus_frame(
        &mut self,
        frame: Vec<u8>,
        duration: Duration,
    ) -> VoiceResult<VoiceOutboundPacket> {
        let requires_dave = self.dave_active();
        let opus_payload = if requires_dave {
            self.dave.session_mut().encrypt_opus_frame(&frame)?
        } else {
            frame
        };
        let packet = {
            let state = self.state.internal();
            let session_description = state
                .session_description
                .as_ref()
                .ok_or_else(|| VoiceError::protocol("missing voice session description"))?;
            let build_started = O::ENABLE_TIMING.then(Instant::now);
            let packet = self.outbound_rtp.build_packet(
                &opus_payload,
                duration,
                &session_description.mode,
                session_description.secret_key.as_slice(),
            )?;
            let build_elapsed = build_started.map(|started| started.elapsed());
            (packet, build_elapsed, state.config.public_info())
        };
        let (packet, build_elapsed, connection) = packet;
        let send_started = O::ENABLE_TIMING.then(Instant::now);
        tokio::select! {
            sent = self.udp_socket.send(&packet.bytes) => {
                sent?;
            }
            () = self.close.closed() => return Err(VoiceError::Closed),
        }
        if let (Some(build_elapsed), Some(send_started)) = (build_elapsed, send_started) {
            self.observer.udp_packet_sent(VoiceUdpPacketSentEvent {
                endpoint: &connection.endpoint,
                guild_id: connection.server_id,
                user_id: connection.user_id,
                dave: requires_dave,
                opus_bytes: opus_payload.len(),
                packet_bytes: packet.bytes.len(),
                build_elapsed,
                send_elapsed: send_started.elapsed(),
            });
        }
        Ok(packet.metadata)
    }

    fn resolve_pending_receives(&mut self) -> VoiceResult<()> {
        while matches!(
            self.pending_receives.front(),
            Some(PendingReceive::Frame { .. })
        ) {
            let Some(packet) = self.drain_ready_voice_frame()? else {
                return Ok(());
            };
            let Some(PendingReceive::Frame { response, .. }) = self.pending_receives.pop_front()
            else {
                unreachable!("front checked");
            };
            let _ = response.send(Ok(packet));
        }
        Ok(())
    }

    fn discard_inactive_pending_receives(&mut self) {
        let now = Instant::now();
        let mut retained = VecDeque::new();
        while let Some(receive) = self.pending_receives.pop_front() {
            if receive.is_closed() {
                continue;
            }
            if receive.is_expired(now) {
                receive.complete_timeout();
                continue;
            }
            retained.push_back(receive);
        }
        self.pending_receives = retained;
    }

    fn handle_received_udp_packet(&mut self, raw: VoiceRawUdpPacket) -> VoiceResult<()> {
        let request = loop {
            let Some(request) = self.pending_receives.pop_front() else {
                return Ok(());
            };
            if request.is_closed() {
                continue;
            }
            if request.is_expired(Instant::now()) {
                request.complete_timeout();
                continue;
            }
            break request;
        };
        match request {
            PendingReceive::Raw { response, .. } => {
                let _ = response.send(Ok(raw));
            }
            PendingReceive::Rtp { max_len, response } => {
                if raw.is_rtcp() {
                    self.observe_rtcp_packet(&raw);
                    self.pending_receives
                        .push_front(PendingReceive::Rtp { max_len, response });
                } else {
                    let _ = response.send(Ok(raw));
                }
            }
            PendingReceive::Frame {
                max_len,
                deadline,
                max_wait,
                response,
            } => {
                if raw.is_rtcp() {
                    self.observe_rtcp_packet(&raw);
                    self.pending_receives.push_front(PendingReceive::Frame {
                        max_len,
                        deadline,
                        max_wait,
                        response,
                    });
                    return Ok(());
                }
                match self.decode_received_voice_packet(raw) {
                    Ok(Some(packet)) => {
                        let _ = response.send(Ok(packet));
                    }
                    Ok(None) => {
                        self.pending_receives.push_front(PendingReceive::Frame {
                            max_len,
                            deadline,
                            max_wait,
                            response,
                        });
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
        }
        Ok(())
    }

    fn decode_received_voice_packet(
        &mut self,
        raw: VoiceRawUdpPacket,
    ) -> VoiceResult<Option<VoiceReceivedFrame>> {
        let rtp = match parse_rtp_header(&raw.bytes) {
            Ok(rtp) => rtp,
            Err(error) => {
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::Rtp,
                    VoiceReceiveDecodeErrorKind::MalformedRtp,
                    raw.ssrc,
                    None,
                    raw.seq,
                    error.to_string(),
                );
                return Err(error.into());
            }
        };
        let (encrypted_frame, user_id, dave_active) = {
            let state = self.state.internal();
            let session_description = state
                .session_description
                .as_ref()
                .ok_or_else(|| VoiceError::protocol("missing voice session description"))?;
            let user_id = state.ssrc_users.get(&rtp.ssrc).copied();
            let encrypted_frame = match decrypt_transport_payload(
                &raw.bytes,
                &rtp,
                &session_description.mode,
                session_description.secret_key.as_slice(),
            ) {
                Ok(frame) => frame,
                Err(error) => {
                    let detail = error.to_string();
                    drop(state);
                    self.observe_decode_error(
                        VoiceReceiveDecodeStage::Transport,
                        VoiceReceiveDecodeErrorKind::TransportDecryptFailed,
                        Some(rtp.ssrc),
                        user_id,
                        Some(rtp.seq),
                        detail,
                    );
                    return Err(error);
                }
            };
            (
                encrypted_frame,
                user_id,
                state.dave.protocol_version.unwrap_or(0) > 0,
            )
        };
        let media = PendingVoiceMediaFrame {
            raw,
            rtp,
            user_id,
            encrypted_frame,
            dave: dave_active,
            enqueued_at: Instant::now(),
            reason: VoiceDavePendingMediaReason::DecryptStatePending,
            was_pending: false,
        };
        let Some(media) = self.receive.push_media_frame(&self.observer, media) else {
            return Ok(None);
        };
        self.decode_ordered_media_frame(media)
    }

    fn drain_ready_voice_frame(&mut self) -> VoiceResult<Option<VoiceReceivedFrame>> {
        if let Some(packet) = self.drain_pending_dave_media()? {
            return Ok(Some(packet));
        }
        while let Some(media) = self.receive.drain_ordered_media(&self.observer) {
            if let Some(packet) = self.decode_ordered_media_frame(media)? {
                return Ok(Some(packet));
            }
        }
        Ok(None)
    }

    fn decode_ordered_media_frame(
        &mut self,
        media: PendingVoiceMediaFrame,
    ) -> VoiceResult<Option<VoiceReceivedFrame>> {
        if media.dave {
            return self.decode_or_enqueue_dave_media(media);
        }
        Ok(Some(VoiceReceivedFrame {
            raw: media.raw,
            rtp: media.rtp,
            user_id: media.user_id,
            media_type: VoiceDaveMediaType::Audio,
            codec: VoiceCodec::Opus,
            frame: media.encrypted_frame,
        }))
    }

    fn drain_pending_dave_media(&mut self) -> VoiceResult<Option<VoiceReceivedFrame>> {
        for _ in 0..self.receive.pending_dave_media.len() {
            let Some(mut media) = self.receive.pending_dave_media.pop_front() else {
                return Ok(None);
            };
            media.was_pending = true;
            if media.enqueued_at.elapsed() >= DAVE_PENDING_MEDIA_TTL {
                self.observe_pending_dave_media(
                    &media,
                    VoiceDavePendingMediaReason::Expired,
                    false,
                );
                continue;
            }
            if let Some(decoded) = self.decode_or_enqueue_dave_media(media)? {
                return Ok(Some(decoded));
            }
        }
        Ok(None)
    }

    fn decode_or_enqueue_dave_media(
        &mut self,
        mut media: PendingVoiceMediaFrame,
    ) -> VoiceResult<Option<VoiceReceivedFrame>> {
        media.user_id = self
            .state
            .internal()
            .ssrc_users
            .get(&media.rtp.ssrc)
            .copied();
        if media.user_id.is_none() {
            self.enqueue_dave_media(media, VoiceDavePendingMediaReason::MissingUser);
            return Ok(None);
        }
        let (gateway_pending, transition_zero_ready) = {
            let state = self.state.internal();
            (
                !voice_dave_gateway_media_ready(&state.dave),
                voice_dave_transition_zero_media_ready(&state.dave, self.dave.transition_ready()),
            )
        };
        if !self.dave.ready() {
            self.enqueue_dave_media(media, VoiceDavePendingMediaReason::SessionNotReady);
            return Ok(None);
        }
        if gateway_pending && !transition_zero_ready {
            self.enqueue_dave_media(media, VoiceDavePendingMediaReason::GatewayPending);
            return Ok(None);
        }
        match self
            .dave
            .session_mut()
            .decrypt_frame(media.user_id, &media.encrypted_frame)
        {
            Ok(frame) => {
                if media.was_pending {
                    self.observe_pending_dave_media(&media, media.reason, true);
                }
                Ok(Some(VoiceReceivedFrame {
                    raw: media.raw,
                    rtp: media.rtp,
                    user_id: media.user_id,
                    media_type: VoiceDaveMediaType::Audio,
                    codec: VoiceCodec::Opus,
                    frame,
                }))
            }
            Err(error) => {
                let kind = error.receive_decode_kind();
                self.observe_decode_error(
                    VoiceReceiveDecodeStage::DaveDecrypt,
                    kind,
                    Some(media.rtp.ssrc),
                    media.user_id,
                    Some(media.rtp.seq),
                    error.to_string(),
                );
                if media.enqueued_at.elapsed() < DAVE_PENDING_MEDIA_TTL
                    && voice_dave_decrypt_failure_should_retry(
                        kind,
                        self.dave_decrypt_state_can_still_change(),
                    )
                {
                    let reason = if matches!(error, VoiceDaveDecryptError::NoValidCryptor { .. }) {
                        VoiceDavePendingMediaReason::NoValidCryptorPending
                    } else {
                        VoiceDavePendingMediaReason::DecryptStatePending
                    };
                    self.enqueue_dave_media(media, reason);
                    return Ok(None);
                }
                self.observe_pending_dave_media(
                    &media,
                    VoiceDavePendingMediaReason::StableDecryptFailure,
                    false,
                );
                Ok(None)
            }
        }
    }

    fn enqueue_dave_media(
        &mut self,
        mut media: PendingVoiceMediaFrame,
        reason: VoiceDavePendingMediaReason,
    ) {
        let was_pending = media.was_pending;
        media.reason = reason;
        self.receive.pending_dave_media.push_back(media);
        if O::ENABLE_RECEIVE_TELEMETRY
            && !was_pending
            && let Some(packet) = self.receive.pending_dave_media.back()
        {
            self.observer.dave_pending_media_enqueued(
                packet.event(self.receive.pending_dave_media.len(), reason),
            );
        }
    }

    fn observe_pending_dave_media(
        &self,
        media: &PendingVoiceMediaFrame,
        reason: VoiceDavePendingMediaReason,
        drained: bool,
    ) {
        if !O::ENABLE_RECEIVE_TELEMETRY {
            return;
        }
        let event = media.event(self.receive.pending_dave_media.len(), reason);
        if drained {
            self.observer.dave_pending_media_drained(event);
        } else if matches!(
            reason,
            VoiceDavePendingMediaReason::StableDecryptFailure
                | VoiceDavePendingMediaReason::Expired
        ) {
            self.observer.dave_pending_media_dropped(event);
        } else {
            self.observer.dave_pending_media_enqueued(event);
        }
    }

    fn observe_rtcp_packet(&self, raw: &VoiceRawUdpPacket) {
        if !O::ENABLE_RTCP {
            return;
        }
        let connection = self.state.internal().config.public_info();
        self.observer.rtcp_packet_received(VoiceRtcpPacketEvent {
            endpoint: &connection.endpoint,
            guild_id: connection.server_id,
            user_id: connection.user_id,
            bytes: &raw.bytes,
            header: raw.rtcp_header(),
        });
    }

    fn observe_decode_error(
        &self,
        stage: VoiceReceiveDecodeStage,
        kind: VoiceReceiveDecodeErrorKind,
        ssrc: Option<u32>,
        user_id: Option<u64>,
        seq: Option<u16>,
        detail: String,
    ) {
        if O::ENABLE_RECEIVE_TELEMETRY {
            self.observer
                .receive_decode_error(VoiceReceiveDecodeErrorEvent {
                    stage,
                    kind,
                    ssrc,
                    user_id,
                    seq,
                    detail,
                });
        }
    }

    fn resolve_pending_media_ready_waits(&mut self) {
        let status = self.current_dave_media_status();
        if status.media_ready {
            while let Some(wait) = self.pending_media_ready_waits.pop_front() {
                let _ = wait.response.send(Ok(status));
            }
            return;
        }
        let now = Instant::now();
        let mut retained = VecDeque::new();
        while let Some(wait) = self.pending_media_ready_waits.pop_front() {
            if now >= wait.deadline {
                let _ = wait.response.send(Err(VoiceError::Timeout {
                    stage: None,
                    duration: wait.max_wait,
                }));
            } else {
                retained.push_back(wait);
            }
        }
        self.pending_media_ready_waits = retained;
    }

    fn current_dave_media_status(&self) -> VoiceDaveMediaStatus {
        let state = self.state.internal();
        let active = state.dave.protocol_version.unwrap_or(0) > 0;
        let gateway_ready = voice_dave_gateway_media_ready(&state.dave);
        let session_ready = self.dave.ready();
        let transition_ready = self.dave.transition_ready();
        let transition_zero_ready =
            voice_dave_transition_zero_media_ready(&state.dave, transition_ready);
        VoiceDaveMediaStatus {
            active,
            media_ready: !active
                || (session_ready && transition_zero_ready)
                || (session_ready && transition_ready.is_some() && gateway_ready),
            session_ready,
            transition_ready,
            protocol_version: state.dave.protocol_version,
            transition_id: state.dave.transition_id,
            mls: state.dave.mls_state(),
        }
    }

    fn dave_active(&self) -> bool {
        self.state.internal().dave.protocol_version.unwrap_or(0) > 0
    }

    fn dave_decrypt_state_can_still_change(&self) -> bool {
        let state = self.state.internal();
        let transition_zero_ready =
            voice_dave_transition_zero_media_ready(&state.dave, self.dave.transition_ready());
        !self.dave.ready()
            || (!transition_zero_ready && !voice_dave_gateway_media_ready(&state.dave))
    }

    fn next_driver_wake_deadline(&self) -> Option<Instant> {
        self.receive
            .pending_dave_media_deadline()
            .into_iter()
            .chain(self.receive.pending_rtp_reorder_deadline())
            .chain(self.pending_sends.front().map(|send| send.deadline))
            .chain(
                self.pending_receives
                    .iter()
                    .filter_map(PendingReceive::deadline),
            )
            .chain(
                self.pending_media_ready_waits
                    .iter()
                    .map(|wait| wait.deadline),
            )
            .min()
    }

    fn complete_pending_closed(&mut self) {
        while let Ok(command) = self.command_rx.try_recv() {
            command.complete_closed();
        }
        while let Some(receive) = self.pending_receives.pop_front() {
            receive.complete_closed();
        }
        while let Some(send) = self.pending_sends.pop_front() {
            let _ = send.response.send(Err(VoiceError::Closed));
        }
        while let Some(wait) = self.pending_media_ready_waits.pop_front() {
            let _ = wait.response.send(Err(VoiceError::Closed));
        }
    }
}

pub(crate) fn voice_dave_media_status_from_public_state(
    state: &VoiceConnectionState,
) -> VoiceDaveMediaStatus {
    let active = state.dave.protocol_version.unwrap_or(0) > 0;
    VoiceDaveMediaStatus {
        active,
        media_ready: !active,
        session_ready: false,
        transition_ready: None,
        protocol_version: state.dave.protocol_version,
        transition_id: state.dave.transition_id,
        mls: state.dave.mls,
    }
}

pub async fn connect_voice(
    config: VoiceConnectionConfig,
) -> VoiceResult<VoiceConnection<NoopVoiceConnectionObserver>> {
    connect_voice_with_observer(config, NoopVoiceConnectionObserver).await
}

pub async fn connect_voice_with_observer<O>(
    config: VoiceConnectionConfig,
    observer: O,
) -> VoiceResult<VoiceConnection<O>>
where
    O: VoiceConnectionObserver,
{
    let websocket_url = config.websocket_url()?;
    let voice_endpoint = config.endpoint.clone();
    let voice_guild_id = config.server_id;
    let voice_channel_id = config.channel_id;
    let voice_user_id = config.user_id;
    let (ws_stream, _) = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::WebSocketConnect,
        VOICE_CONNECT_TIMEOUT,
        connect_voice_websocket(&websocket_url),
    )
    .await?;
    let (mut write, mut read) = ws_stream.split();

    let hello = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::Hello,
        VOICE_HELLO_TIMEOUT,
        read_voice_event(&mut read),
    )
    .await?;
    let hello_data: VoiceHelloData = parse_voice_data(hello.data)?;

    write
        .send(WsMessage::Text(
            VoiceGatewayCommand::Identify(VoiceIdentifyCommand::from_config(&config))
                .text_payload()?
                .into(),
        ))
        .await?;

    let mut last_seq = hello.seq;
    let ready_event = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::Ready,
        VOICE_READY_TIMEOUT,
        wait_for_voice_opcode(&mut read, VoiceOpcode::Ready, &mut last_seq),
    )
    .await?;
    let ready: VoiceGatewayReady = parse_voice_data(ready_event.data)?;

    let udp_socket = bind_voice_udp_socket(&ready.ip).await?;
    udp_socket.connect((&*ready.ip, ready.port)).await?;
    udp_socket
        .send(&VoiceUdpDiscoveryPacket::request(ready.ssrc))
        .await?;

    let mut discovery_buffer = [0_u8; VoiceUdpDiscoveryPacket::LEN];
    let received = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::UdpDiscovery,
        VOICE_UDP_DISCOVERY_TIMEOUT,
        async { Ok(udp_socket.recv(&mut discovery_buffer).await?) },
    )
    .await?;
    let discovery = VoiceUdpDiscoveryPacket::decode(&discovery_buffer[..received])?;
    let selected_mode = select_encryption_mode(&config, &ready)?;

    write
        .send(WsMessage::Text(
            VoiceGatewayCommand::SelectProtocol(VoiceSelectProtocolCommand::udp(
                discovery.address.clone(),
                discovery.port,
                selected_mode.clone(),
            ))
            .text_payload()?
            .into(),
        ))
        .await?;

    let (session_description_event, pending_events) = observed_voice_stage_timeout(
        &observer,
        VoiceConnectionEvent {
            endpoint: &voice_endpoint,
            guild_id: voice_guild_id,
            user_id: voice_user_id,
        },
        VoiceConnectStage::SessionDescription,
        VOICE_SESSION_DESCRIPTION_TIMEOUT,
        wait_for_session_description(&mut read, &mut last_seq),
    )
    .await?;
    let session_description: VoiceSessionDescription =
        parse_voice_data(session_description_event.data)?;
    let dave_protocol_version = session_description.dave_protocol_version;

    let initial_state = VoiceConnectionInternalState {
        config,
        heartbeat_interval_ms: hello_data.heartbeat_interval_ms(),
        last_seq,
        ready,
        discovery,
        selected_mode,
        session_description: Some(session_description),
        connected_user_ids: HashSet::from([voice_user_id]),
        ssrc_users: HashMap::new(),
        speaking: HashMap::new(),
        dave: VoiceDaveInternalState {
            protocol_version: dave_protocol_version,
            passthrough: dave_protocol_version.unwrap_or(0) == 0,
            ..VoiceDaveInternalState::default()
        },
        roster_authoritative: false,
        resumed: false,
    };
    let state = VoiceConnectionStateChannels::new(initial_state);
    replay_pending_voice_events(&state, pending_events, &observer)?;
    let (command_tx, command_rx) = mpsc::channel::<VoiceConnectionCommand>(128);
    let close = VoiceConnectionClose::new();
    let task = tokio::spawn(
        VoiceConnectionDriver {
            write,
            read,
            command_rx,
            close: close.clone(),
            outbound_rtp: VoiceOutboundRtpState::new(state.internal().ready.ssrc),
            dave: VoiceDaveCoordinator::new(voice_user_id, voice_channel_id)?,
            receive: VoiceReceiveState::default(),
            receive_buffer: Vec::new(),
            pending_receives: VecDeque::new(),
            pending_sends: VecDeque::new(),
            pending_media_ready_waits: VecDeque::new(),
            state: state.clone(),
            observer: observer.clone(),
            udp_socket,
        }
        .run(),
    );
    let abort = task.abort_handle();
    let join_tx = spawn_voice_connection_join_task(task);

    Ok(VoiceConnection {
        inner: Arc::new(VoiceConnectionInner {
            state_rx: state.subscribe_public(),
            command_tx,
            close,
            join_tx,
            abort,
            observer,
        }),
    })
}

pub(crate) async fn voice_stage_timeout<T>(
    stage: VoiceConnectStage,
    duration: Duration,
    future: impl Future<Output = VoiceResult<T>>,
) -> VoiceResult<T> {
    match timeout(duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(VoiceError::Timeout {
            stage: Some(stage),
            duration,
        }),
    }
}

pub(crate) async fn observed_voice_stage_timeout<O, T>(
    observer: &O,
    connection: VoiceConnectionEvent<'_>,
    stage: VoiceConnectStage,
    duration: Duration,
    future: impl Future<Output = VoiceResult<T>>,
) -> VoiceResult<T>
where
    O: VoiceConnectionObserver,
{
    let started = Instant::now();
    let result = voice_stage_timeout(stage, duration, future).await;
    match &result {
        Ok(_) => observer.connect_stage_completed(VoiceConnectStageCompletedEvent {
            endpoint: connection.endpoint,
            guild_id: connection.guild_id,
            user_id: connection.user_id,
            stage,
            elapsed: started.elapsed(),
        }),
        Err(error) => observer.connect_stage_failed(VoiceConnectStageFailedEvent {
            endpoint: connection.endpoint,
            guild_id: connection.guild_id,
            user_id: connection.user_id,
            stage,
            elapsed: started.elapsed(),
            error,
        }),
    }
    result
}

pub(crate) fn voice_heartbeat_ack_timeout(heartbeat_interval_ms: u64) -> Duration {
    Duration::from_millis(heartbeat_interval_ms.saturating_mul(2)).max(Duration::from_secs(1))
}
