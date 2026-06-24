use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::{
    dave::DaveMediaStatus,
    errors::{BackpressureError, ConnectionJoinError, Error, InvalidInputError, Result},
    gateway::SpeakingFlags,
    media::{
        DecodedFrame, DecodedFrameMetadata, FrameRaw, NoRawPackets, RawUdpPacket, ReceivedFrame,
    },
    observer::{
        ConnectionObserver, NoopConnectionObserver, ReceiveDecodeContext, ReceiveDecodeErrorKind,
        ReceiveDecodeStage, observe_receive_decode_error,
    },
    opus::Decoder,
    state::{ConnectionInternalState, ConnectionState, ConnectionStateSnapshot, DaveMlsState},
};

use super::{LowLevelReceiveKind, OpusPlayout, PlayoutCommand};

#[derive(Clone)]
pub struct Connection<O: ConnectionObserver = NoopConnectionObserver, Raw: FrameRaw = NoRawPackets>
{
    pub(crate) inner: Arc<ConnectionInner<O, Raw>>,
}

pub(crate) struct ConnectionStateStore {
    internal: ConnectionInternalState,
    public_tx: watch::Sender<ConnectionStateSnapshot>,
}

impl ConnectionStateStore {
    pub(crate) fn new(initial: ConnectionInternalState) -> Self {
        let public = Arc::new(initial.public_state());
        let (public_tx, _) = watch::channel(public);
        Self {
            internal: initial,
            public_tx,
        }
    }

    pub(crate) fn internal(&self) -> &ConnectionInternalState {
        &self.internal
    }

    pub(crate) fn subscribe_public(&self) -> watch::Receiver<ConnectionStateSnapshot> {
        self.public_tx.subscribe()
    }

    pub(crate) fn update(&mut self, update: impl FnOnce(&mut ConnectionInternalState)) {
        update(&mut self.internal);
        self.public_tx
            .send_replace(Arc::new(self.internal.public_state()));
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionClose {
    closed: watch::Sender<bool>,
    closed_once: Arc<AtomicBool>,
}

impl ConnectionClose {
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

    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }

    #[cfg(test)]
    pub(crate) async fn closed(&self) {
        let mut closed = self.subscribe();
        wait_for_close(&mut closed).await;
    }
}

pub(crate) async fn wait_for_close(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

pub(crate) struct ConnectionInner<O, Raw>
where
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    pub(crate) state_rx: watch::Receiver<ConnectionStateSnapshot>,
    pub(crate) command_tx: mpsc::Sender<ConnectionCommand<Raw>>,
    pub(crate) media_tx: mpsc::Sender<PlayoutCommand>,
    pub(crate) close: ConnectionClose,
    pub(crate) join_tx: mpsc::Sender<ConnectionJoinCommand>,
    pub(crate) abort: tokio::task::AbortHandle,
    pub(crate) observer: O,
}

pub(crate) enum ConnectionJoinCommand {
    Wait { reply: oneshot::Sender<Result<()>> },
}

pub(crate) fn spawn_voice_connection_join_task(
    task: JoinHandle<Result<()>>,
) -> mpsc::Sender<ConnectionJoinCommand> {
    let (join_tx, mut join_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut task = Some(task);
        while let Some(command) = join_rx.recv().await {
            match command {
                ConnectionJoinCommand::Wait { reply } => {
                    let result = match task.take() {
                        Some(task) => match task.await {
                            Ok(result) => result,
                            Err(error) => Err(Error::Join(
                                ConnectionJoinError::ControlTaskJoinFailed(error),
                            )),
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
        Ok::<(), Error>(())
    });
    join_tx
}

impl<O, Raw> Drop for ConnectionInner<O, Raw>
where
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    fn drop(&mut self) {
        let state = self.state_rx.borrow();
        self.observer
            .connection_dropped(state.connection.connection_event());
        self.close.close();
        self.abort.abort();
    }
}

impl<O, Raw> Connection<O, Raw>
where
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    pub fn state(&self) -> ConnectionStateSnapshot {
        self.inner.state_rx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<ConnectionStateSnapshot> {
        self.inner.state_rx.clone()
    }

    pub fn running(&self) -> bool {
        !self.inner.close.is_closed()
    }

    pub fn close(&self) -> bool {
        self.inner.close.close()
    }

    pub async fn close_and_wait(&self) -> Result<()> {
        self.close();
        let _ = self.inner.command_tx.try_send(ConnectionCommand::Close);
        let (reply, response) = oneshot::channel();
        self.inner
            .join_tx
            .send(ConnectionJoinCommand::Wait { reply })
            .await
            .map_err(|_| Error::Join(ConnectionJoinError::JoinTaskClosed))?;
        response
            .await
            .map_err(|_| Error::Join(ConnectionJoinError::JoinTaskStoppedBeforeReply))?
    }

    fn ensure_open(&self) -> Result<()> {
        if self.inner.close.is_closed() {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    pub async fn dave_media_status(&self) -> DaveMediaStatus {
        let (response, receive) = oneshot::channel();
        if self
            .send_command(ConnectionCommand::DaveMediaStatus { response })
            .is_ok()
            && let Ok(status) = receive.await
        {
            return status;
        }
        dave_media_status_from_public_state(&self.state())
    }

    pub async fn wait_until_media_ready(&self, max_wait: Duration) -> Result<DaveMediaStatus> {
        self.request_result(|response| ConnectionCommand::WaitUntilMediaReady {
            max_wait,
            response,
        })
        .await
    }

    pub async fn recv_raw_udp_packet(&self, max_len: usize) -> Result<RawUdpPacket> {
        if max_len == 0 {
            return Err(Error::InvalidInput(InvalidInputError::ZeroMaxLen));
        }
        self.request_result(|response| ConnectionCommand::RecvUdpPacket {
            kind: LowLevelReceiveKind::RawUdp,
            max_len,
            response,
        })
        .await
    }

    pub async fn recv_rtp_udp_packet(&self, max_len: usize) -> Result<RawUdpPacket> {
        if max_len == 0 {
            return Err(Error::InvalidInput(InvalidInputError::ZeroMaxLen));
        }
        self.request_result(|response| ConnectionCommand::RecvUdpPacket {
            kind: LowLevelReceiveKind::RtpUdp,
            max_len,
            response,
        })
        .await
    }

    pub async fn recv_voice_frame(&self, max_len: usize) -> Result<ReceivedFrame<Raw>> {
        if max_len == 0 {
            return Err(Error::InvalidInput(InvalidInputError::ZeroMaxLen));
        }
        self.request_result(|response| ConnectionCommand::RecvVoiceFrame {
            max_len,
            max_wait: None,
            response,
        })
        .await
    }

    pub async fn recv_voice_frame_timeout(
        &self,
        max_len: usize,
        max_wait: Duration,
    ) -> Result<Option<ReceivedFrame<Raw>>> {
        if max_len == 0 {
            return Err(Error::InvalidInput(InvalidInputError::ZeroMaxLen));
        }
        match self
            .request_result(|response| ConnectionCommand::RecvVoiceFrame {
                max_len,
                max_wait: Some(max_wait),
                response,
            })
            .await
        {
            Ok(frame) => Ok(Some(frame)),
            Err(Error::Timeout {
                stage: None,
                duration,
            }) if duration == max_wait => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn recv_decoded_voice_frame(
        &self,
        decoder: &mut Decoder,
        max_len: usize,
    ) -> Result<DecodedFrame<Raw>> {
        let frame = self.recv_voice_frame(max_len).await?;
        let ssrc = frame.rtp.ssrc;
        let user_id = frame.user_id;
        let seq = frame.rtp.seq;
        match decoder.decode_frame(frame) {
            Ok(decoded) => Ok(decoded),
            Err(error) => {
                self.observe_decode_error(
                    ReceiveDecodeStage::Opus,
                    ReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(seq),
                    &error,
                );
                Err(error)
            }
        }
    }

    pub async fn recv_decoded_voice_frame_timeout(
        &self,
        decoder: &mut Decoder,
        max_len: usize,
        max_wait: Duration,
    ) -> Result<Option<DecodedFrame<Raw>>> {
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
                    ReceiveDecodeStage::Opus,
                    ReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(seq),
                    &error,
                );
                Err(error)
            }
        }
    }

    pub async fn recv_decoded_voice_frame_into(
        &self,
        decoder: &mut Decoder,
        max_len: usize,
        pcm: &mut Vec<i16>,
    ) -> Result<DecodedFrameMetadata<Raw>> {
        let frame = self.recv_voice_frame(max_len).await?;
        let ssrc = frame.rtp.ssrc;
        let user_id = frame.user_id;
        let seq = frame.rtp.seq;
        match decoder.decode_frame_into(frame, pcm) {
            Ok(decoded) => Ok(decoded),
            Err(error) => {
                self.observe_decode_error(
                    ReceiveDecodeStage::Opus,
                    ReceiveDecodeErrorKind::OpusDecodeFailed,
                    Some(ssrc),
                    user_id,
                    Some(seq),
                    &error,
                );
                Err(error)
            }
        }
    }

    fn observe_decode_error<E>(
        &self,
        stage: ReceiveDecodeStage,
        kind: ReceiveDecodeErrorKind,
        ssrc: Option<u32>,
        user_id: Option<u64>,
        seq: Option<u16>,
        error: &E,
    ) where
        E: std::fmt::Display + ?Sized,
    {
        observe_receive_decode_error(
            &self.inner.observer,
            stage,
            kind,
            ReceiveDecodeContext { ssrc, user_id, seq },
            error,
        );
    }

    fn send_command(&self, command: ConnectionCommand<Raw>) -> Result<()> {
        self.ensure_open()?;
        match self.inner.command_tx.try_send(command) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(Error::Backpressure(BackpressureError::CommandQueueFull))
            }
        }
    }

    async fn request_result<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T>>) -> ConnectionCommand<Raw>,
    ) -> Result<T> {
        let (response, receive) = oneshot::channel();
        self.send_command(build(response))?;
        receive.await.map_err(|_| Error::Closed)?
    }

    pub fn set_speaking(&self, flags: SpeakingFlags, delay: u32) -> Result<()> {
        self.send_command(ConnectionCommand::SetSpeaking { flags, delay })
    }

    pub async fn start_opus_playout(&self) -> Result<OpusPlayout> {
        self.ensure_open()?;
        let (response, receive) = oneshot::channel();
        self.inner
            .media_tx
            .send(PlayoutCommand::Start { response })
            .await
            .map_err(|_| Error::Closed)?;
        let id = receive.await.map_err(|_| Error::Closed)??;
        Ok(OpusPlayout {
            id,
            media_tx: self.inner.media_tx.clone(),
            close: self.inner.close.clone(),
            finished: false,
        })
    }
}

pub(crate) enum ConnectionCommand<Raw>
where
    Raw: FrameRaw,
{
    SetSpeaking {
        flags: SpeakingFlags,
        delay: u32,
    },
    RecvUdpPacket {
        kind: LowLevelReceiveKind,
        max_len: usize,
        response: oneshot::Sender<Result<RawUdpPacket>>,
    },
    RecvVoiceFrame {
        max_len: usize,
        max_wait: Option<Duration>,
        response: oneshot::Sender<Result<ReceivedFrame<Raw>>>,
    },
    DaveMediaStatus {
        response: oneshot::Sender<DaveMediaStatus>,
    },
    WaitUntilMediaReady {
        max_wait: Duration,
        response: oneshot::Sender<Result<DaveMediaStatus>>,
    },
    Close,
}

impl<Raw> ConnectionCommand<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn complete_closed(self) {
        match self {
            Self::RecvUdpPacket { response, .. } => {
                let _ = response.send(Err(Error::Closed));
            }
            Self::RecvVoiceFrame { response, .. } => {
                let _ = response.send(Err(Error::Closed));
            }
            Self::DaveMediaStatus { response } => {
                let _ = response.send(DaveMediaStatus {
                    active: false,
                    active_send_protocol_version: None,
                    active_receive_protocol_version: None,
                    media_ready: false,
                    session_ready: false,
                    send_ready: false,
                    transition_ready: None,
                    protocol_version: None,
                    transition_id: None,
                    mls: DaveMlsState::default(),
                });
            }
            Self::WaitUntilMediaReady { response, .. } => {
                let _ = response.send(Err(Error::Closed));
            }
            Self::SetSpeaking { .. } | Self::Close => {}
        }
    }
}

pub(crate) fn dave_media_status_from_public_state(state: &ConnectionState) -> DaveMediaStatus {
    let active = state.dave.active_send_protocol_version.unwrap_or(0) > 0;
    DaveMediaStatus {
        active,
        active_send_protocol_version: state.dave.active_send_protocol_version,
        active_receive_protocol_version: state.dave.active_receive_protocol_version,
        media_ready: !active,
        session_ready: false,
        send_ready: false,
        transition_ready: None,
        protocol_version: state.dave.protocol_version,
        transition_id: state.dave.transition_id,
        mls: state.dave.mls,
    }
}
