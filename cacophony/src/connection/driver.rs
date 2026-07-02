use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{Instant, interval, timeout},
};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::{
    CONNECT_TIMEOUT, GatewayWebSocketRead, GatewayWebSocketWrite, HELLO_TIMEOUT, READY_TIMEOUT,
    SESSION_DESCRIPTION_TIMEOUT, UDP_DISCOVERY_TIMEOUT,
    codecs::DiscordRtpCodecMap,
    dave::{DaveCoordinator, DaveMediaStatus},
    errors::{Error, ProtocolError, Result},
    gateway::{
        GatewayCommand, GatewayEventEffects, GatewayEventHandler, GatewayHeartbeatAckState,
        GatewayReady, HeartbeatCommand, HelloData, Opcode, SelectProtocolCommand, SpeakingCommand,
        UdpDiscoveryPacket, handle_voice_binary_event, identify_payload, parse_data,
        parse_event_text, read_event, replay_pending_voice_events, wait_for_opcode,
        wait_for_session_description,
    },
    media::{
        FrameRaw, HeartbeatNonce, NoRawPackets, OutboundPacket, TransportCrypto, VoiceEndpoint,
        VoiceUdpRemote,
    },
    observer::{
        ConnectStage, ConnectStageCompletedEvent, ConnectStageFailedEvent, ConnectionErrorEvent,
        ConnectionEvent, ConnectionObserver, NoopConnectionObserver, UdpPacketReceivedEvent,
        WebSocketBinaryEvent, WebSocketCloseFrame, WebSocketClosedEvent,
        WebSocketCommandFailedEvent, WebSocketFrameKind, WebSocketTextEvent,
    },
    queue::{DeadlineQueue, DriverReply},
    state::{
        ConnectionConfig, ConnectionInternalState, ConnectionRequest, DaveInternalState,
        SessionDescription, ValidatedConnectionConfig,
    },
};

use super::{
    Connection, ConnectionClose, ConnectionCommand, ConnectionInner, ConnectionStateStore,
    PendingReceive, PlayoutCommand, spawn_voice_connection_join_task, wait_for_close,
};
use super::{playout::ActiveOpusPlayout, receive::ReceivePipeline, send::SendPipeline};

pub(crate) struct PendingMediaReadyWait {
    response: DriverReply<DaveMediaStatus>,
    max_wait: Duration,
}

pub(crate) struct PendingMediaFrameSend {
    codec: ::dave::Codec,
    frame: Vec<u8>,
    duration: Duration,
    response: DriverReply<OutboundPacket>,
    max_wait: Duration,
}

pub(crate) struct ConnectionDriver<O, Raw>
where
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    pub(super) write: GatewayWebSocketWrite,
    pub(super) read: GatewayWebSocketRead,
    pub(super) command_rx: mpsc::Receiver<ConnectionCommand<Raw>>,
    pub(super) media_rx: mpsc::Receiver<PlayoutCommand>,
    pub(super) close: ConnectionClose,
    pub(super) state: ConnectionStateStore,
    pub(super) observer: O,
    pub(super) udp_socket: UdpSocket,
    pub(super) dave: DaveCoordinator,
    pub(super) receive: ReceivePipeline<Raw>,
    pub(super) send: SendPipeline,
    pub(super) transport_crypto: TransportCrypto,
    pub(super) pending_media_ready_waits: DeadlineQueue<PendingMediaReadyWait>,
    pub(super) pending_media_ready_sends: DeadlineQueue<PendingMediaFrameSend>,
}

impl<O, Raw> ConnectionDriver<O, Raw>
where
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    async fn run(mut self) -> Result<()> {
        let result = self.run_loop().await;
        self.close.close();
        self.complete_pending_closed();
        if let Err(error) = &result {
            let connection = self.state.internal().config.public_info();
            self.observer.control_task_failed(ConnectionErrorEvent {
                endpoint: &connection.endpoint,
                guild_id: connection.guild_id,
                user_id: connection.user_id,
                error,
            });
        }
        result
    }

    async fn run_loop(&mut self) -> Result<()> {
        let mut heartbeat = interval(Duration::from_millis(
            self.state.internal().heartbeat_interval_ms,
        ));
        heartbeat.tick().await;
        let mut heartbeat_nonce = HeartbeatNonce::initial()?;
        let mut heartbeat_ack = GatewayHeartbeatAckState::default();
        let heartbeat_ack_timeout =
            heartbeat_ack_timeout(self.state.internal().heartbeat_interval_ms);
        let mut close_rx = self.close.subscribe();

        self.pump_dave().await?;
        self.resolve_pending_media_ready(&mut close_rx).await;

        loop {
            self.receive.discard_closed_packet_receives();
            self.flush_frame_stream();
            self.resolve_pending_media_ready(&mut close_rx).await;
            self.resolve_active_playout(&mut close_rx).await?;

            self.receive.udp_buffer.resize(
                self.state
                    .internal()
                    .config
                    .options
                    .tuning
                    .udp_receive_buffer_bytes
                    .get(),
                0,
            );
            let wake_deadline = self.next_driver_wake_deadline();

            tokio::select! {
                _ = heartbeat.tick() => {
                    if heartbeat_ack.is_pending() {
                        if heartbeat_ack.timed_out(heartbeat_ack_timeout) {
                            return Err(Error::Protocol(ProtocolError::HeartbeatAckTimeout));
                        }
                        continue;
                    }
                    let heartbeat_command = GatewayCommand::Heartbeat(HeartbeatCommand {
                        t: heartbeat_nonce.next(),
                        seq_ack: self.state.internal().last_seq,
                    });
                    self.send_voice_gateway_command(heartbeat_command).await?;
                    heartbeat_ack.mark_sent(Instant::now());
                }
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => self.handle_command(command, &mut close_rx).await?,
                        None => {
                            self.close.close();
                            let _ = self.write.send(WsMessage::Close(None)).await;
                            break;
                        }
                    }
                }
                command = self.media_rx.recv() => {
                    if let Some(command) = command {
                        self.handle_playout_command(command, &mut close_rx).await?;
                    }
                }
                () = wait_for_close(&mut close_rx) => {
                    let _ = self.write.send(WsMessage::Close(None)).await;
                    break;
                }
                received = self.udp_socket.recv(self.receive.udp_buffer.as_mut_slice()) => {
                    let started = O::ENABLE_TIMING.then(Instant::now);
                    let received = received?;
                    if let Some(started) = started {
                        let connection = self.state.internal().config.public_info();
                        self.observer.udp_packet_received(UdpPacketReceivedEvent {
                            endpoint: &connection.endpoint,
                            guild_id: connection.guild_id,
                            user_id: connection.user_id,
                            bytes: received,
                            elapsed: started.elapsed(),
                        });
                    }
                    self.handle_received_udp_packet(received);
                }
                () = async {
                    if let Some(deadline) = wake_deadline {
                        tokio::time::sleep_until(deadline).await;
                    }
                }, if wake_deadline.is_some() => {
                    self.expire_pending_dave_media();
                    self.collect_ready_voice_frames();
                    self.flush_frame_stream();
                    self.resolve_active_playout(&mut close_rx).await?;
                }
                message = self.read.next() => {
                    let Some(effects) = self
                        .handle_websocket_message(
                            message,
                            &mut heartbeat_ack,
                        )
                        .await?
                    else {
                        break;
                    };
                    self.pump_dave().await?;
                    self.resolve_pending_media_ready(&mut close_rx).await;
                    self.retry_pending_dave_media(effects.retry_dave_pending_media);
                    self.collect_ready_voice_frames();
                    self.flush_frame_stream();
                    self.resolve_active_playout(&mut close_rx).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_command(
        &mut self,
        command: ConnectionCommand<Raw>,
        close_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        match command {
            ConnectionCommand::SetSpeaking { flags, delay } => {
                let ssrc = self.state.internal().ready.ssrc;
                self.send_voice_gateway_command(GatewayCommand::Speaking(SpeakingCommand {
                    speaking: flags.bits(),
                    delay: Some(delay),
                    ssrc,
                    user_id: None,
                }))
                .await?;
            }
            ConnectionCommand::RecvUdpPacket {
                kind,
                max_len,
                response,
            } => {
                self.receive.push_packet_receive(
                    kind,
                    PendingReceive {
                        max_len,
                        response: DriverReply::new(response),
                    },
                );
            }
            ConnectionCommand::OpenFrameStream { frames, response } => {
                match self.receive.attach_frame_stream(frames) {
                    Ok(()) => {
                        response.complete(Ok(()));
                        self.collect_ready_voice_frames();
                        self.flush_frame_stream();
                    }
                    Err(error) => response.complete(Err(error)),
                }
            }
            ConnectionCommand::DaveMediaStatus { response } => {
                let _ = response.send(self.current_dave_media_status());
            }
            ConnectionCommand::WaitUntilMediaReady { max_wait, response } => {
                self.pending_media_ready_waits.push(
                    PendingMediaReadyWait { response, max_wait },
                    Instant::now() + max_wait,
                );
                self.resolve_pending_media_ready_waits();
            }
            ConnectionCommand::SendMediaFrame {
                codec,
                frame,
                duration,
                response,
            } => {
                let max_wait = self
                    .state
                    .internal()
                    .config
                    .options
                    .dave_send_media_ready_timeout;
                self.send_media_frame_when_ready(
                    PendingMediaFrameSend {
                        codec,
                        frame,
                        duration,
                        response,
                        max_wait,
                    },
                    close_rx,
                )
                .await;
            }
            ConnectionCommand::Close => {
                self.close.close();
                let _ = self.write.send(WsMessage::Close(None)).await;
            }
        }
        Ok(())
    }

    async fn handle_websocket_message(
        &mut self,
        message: Option<std::result::Result<WsMessage, tokio_tungstenite::tungstenite::Error>>,
        heartbeat_ack: &mut GatewayHeartbeatAckState,
    ) -> Result<Option<GatewayEventEffects>> {
        let connection = self.state.internal().config.public_info();
        match message {
            Some(Ok(WsMessage::Text(text))) => {
                let event = parse_event_text(&text)?;
                self.observer.websocket_text_event(WebSocketTextEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.guild_id,
                    user_id: connection.user_id,
                    opcode: event.opcode,
                    seq: event.seq,
                });
                if let Some(seq) = event.seq {
                    self.state.update(|state| {
                        state.last_seq = Some(seq);
                    });
                }
                let effects =
                    GatewayEventHandler::new(&mut self.state, heartbeat_ack, &self.observer)
                        .handle_text_event(event)?;
                self.apply_gateway_effects(&effects)?;
                if effects.media_session_updated {
                    self.send.update_negotiated_media(self.state.internal())?;
                }
                Ok(Some(effects))
            }
            Some(Ok(WsMessage::Binary(bytes))) => {
                self.observer.websocket_binary_event(WebSocketBinaryEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.guild_id,
                    user_id: connection.user_id,
                    bytes: bytes.len(),
                    first_byte: bytes.first().copied(),
                });
                let effects = handle_voice_binary_event(&mut self.state, &bytes)?;
                self.apply_gateway_effects(&effects)?;
                Ok(Some(effects))
            }
            Some(Ok(WsMessage::Close(frame))) => {
                self.observer.websocket_closed(WebSocketClosedEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.guild_id,
                    user_id: connection.user_id,
                    frame: frame.as_ref().map(WebSocketCloseFrame::from_frame),
                });
                self.close.close();
                Ok(None)
            }
            Some(Ok(_)) => Ok(Some(GatewayEventEffects::default())),
            Some(Err(error)) => {
                self.observer.websocket_read_failed(ConnectionErrorEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.guild_id,
                    user_id: connection.user_id,
                    error: &error,
                });
                Err(error.into())
            }
            None => {
                self.observer
                    .websocket_stream_ended(connection.connection_event());
                self.close.close();
                Ok(None)
            }
        }
    }

    async fn pump_dave(&mut self) -> Result<()> {
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

    pub(super) async fn send_voice_gateway_command(
        &mut self,
        command: GatewayCommand,
    ) -> Result<()> {
        let connection = self.state.internal().config.public_info();
        if let Some(bytes) = command.binary_payload() {
            if let Err(error) = self.write.send(WsMessage::Binary(bytes.into())).await {
                self.observer
                    .websocket_command_failed(WebSocketCommandFailedEvent {
                        endpoint: &connection.endpoint,
                        guild_id: connection.guild_id,
                        user_id: connection.user_id,
                        frame_kind: WebSocketFrameKind::Binary,
                        opcode: command.opcode().code(),
                        error: &error,
                    });
                return Err(error.into());
            }
        } else {
            let payload = command.text_payload()?;
            if let Err(error) = self.write.send(WsMessage::Text(payload.into())).await {
                self.observer
                    .websocket_command_failed(WebSocketCommandFailedEvent {
                        endpoint: &connection.endpoint,
                        guild_id: connection.guild_id,
                        user_id: connection.user_id,
                        opcode: command.opcode().code(),
                        frame_kind: WebSocketFrameKind::Text,
                        error: &error,
                    });
                return Err(error.into());
            }
        }
        Ok(())
    }

    fn apply_gateway_effects(&mut self, effects: &GatewayEventEffects) -> Result<()> {
        if let Some(config) = &effects.transport_crypto {
            self.transport_crypto = TransportCrypto::from_config(config)?;
        }
        if effects.allow_plaintext_receive_grace {
            self.dave.allow_plaintext_receive_grace();
        }
        if effects.removed_ssrcs.is_empty() {
            return Ok(());
        }
        let removed_ssrcs = effects
            .removed_ssrcs
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        self.receive.state.prune_ssrcs(&removed_ssrcs);
        self.receive.ready_frames.prune_ssrcs(&removed_ssrcs);
        Ok(())
    }

    fn resolve_pending_media_ready_waits(&mut self) {
        let status = self.current_dave_media_status();
        if status.media_ready {
            self.pending_media_ready_waits.drain_all(|wait| {
                wait.response.complete(Ok(status));
            });
            return;
        }
        self.pending_media_ready_waits
            .drain_expired(Instant::now(), |wait| {
                wait.response.complete(Err(Error::Timeout {
                    stage: None,
                    duration: wait.max_wait,
                }));
            });
    }

    async fn resolve_pending_media_ready(
        &mut self,
        close_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        self.resolve_pending_media_ready_waits();
        self.resolve_pending_media_ready_sends(close_rx).await;
    }

    async fn resolve_pending_media_ready_sends(
        &mut self,
        close_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        if self.current_dave_media_status().media_ready {
            let mut sends = Vec::new();
            self.pending_media_ready_sends
                .drain_all(|send| sends.push(send));
            for send in sends {
                self.complete_media_frame_send(send, close_rx).await;
            }
            return;
        }

        self.pending_media_ready_sends
            .drain_expired(Instant::now(), |send| {
                send.response.complete(Err(Error::Timeout {
                    stage: None,
                    duration: send.max_wait,
                }));
            });
    }

    async fn send_media_frame_when_ready(
        &mut self,
        send: PendingMediaFrameSend,
        close_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        if self.current_dave_media_status().media_ready {
            self.complete_media_frame_send(send, close_rx).await;
            return;
        }

        let deadline = Instant::now() + send.max_wait;
        self.pending_media_ready_sends.push(send, deadline);
    }

    async fn complete_media_frame_send(
        &mut self,
        send: PendingMediaFrameSend,
        close_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        let result = self
            .send_ready_media_frame(send.codec, &send.frame, send.duration, close_rx)
            .await;
        send.response.complete(result);
    }

    pub(super) fn current_dave_media_status(&self) -> DaveMediaStatus {
        let state = self.state.internal();
        let requires_dave = state.dave.send_requires_dave();
        let session_ready = self.dave.ready();
        let send_ready = self.dave.send_ready();
        let transition_ready = self.dave.transition_ready();
        let gateway_ready = state.dave.gateway_media_ready()
            || state.dave.transition_zero_media_ready(transition_ready);
        DaveMediaStatus {
            requires_dave,
            active_send_protocol_version: state.dave.active_send_protocol_version(),
            active_receive_protocol_version: state.dave.active_receive_protocol_version(),
            media_ready: DaveMediaStatus::ready_from(
                requires_dave,
                session_ready,
                send_ready,
                gateway_ready,
            ),
            session_ready,
            send_ready,
            transition_ready,
            protocol_version: state.dave.protocol_version(),
            transition_id: state.dave.transition_id(),
            mls: state.dave.mls_state(),
        }
    }

    pub(super) fn dave_send_requires_dave(&self) -> bool {
        self.state.internal().dave.send_requires_dave()
    }

    pub(super) fn dave_decrypt_state_can_still_change(&self) -> bool {
        let state = self.state.internal();
        let transition_zero_ready = state
            .dave
            .transition_zero_media_ready(self.dave.transition_ready());
        !self.dave.ready() || (!transition_zero_ready && !state.dave.gateway_media_ready())
    }

    fn next_driver_wake_deadline(&self) -> Option<Instant> {
        self.receive
            .state
            .pending_dave_media_deadline()
            .into_iter()
            .chain(self.receive.state.pending_rtp_reorder_deadline())
            .chain(
                self.send
                    .active_playout
                    .as_ref()
                    .and_then(ActiveOpusPlayout::wake_deadline),
            )
            .chain(
                self.send
                    .active_playout
                    .as_ref()
                    .and_then(ActiveOpusPlayout::dave_deadline),
            )
            .chain(self.pending_media_ready_waits.next_deadline())
            .chain(self.pending_media_ready_sends.next_deadline())
            .min()
    }

    fn complete_pending_closed(&mut self) {
        while let Ok(command) = self.command_rx.try_recv() {
            command.complete_closed();
        }
        while let Ok(send) = self.media_rx.try_recv() {
            send.complete_closed();
        }
        self.receive.complete_closed_packet_receives();
        if let Some(playout) = self.send.active_playout.take() {
            playout.cancel();
        }
        self.pending_media_ready_waits.drain_all(|wait| {
            wait.response.complete_closed();
        });
        self.pending_media_ready_sends.drain_all(|send| {
            send.response.complete_closed();
        });
    }
}

pub trait ConnectionConnect: Sized {
    fn connect(
        self,
    ) -> impl Future<Output = Result<Connection<NoopConnectionObserver, NoRawPackets>>>
    where
        Self: IntoValidatedConnectionConfig,
    {
        connect_config_with_observer_and_raw(self, NoopConnectionObserver)
    }

    fn connect_with_observer<O>(
        self,
        observer: O,
    ) -> impl Future<Output = Result<Connection<O, NoRawPackets>>>
    where
        Self: IntoValidatedConnectionConfig,
        O: ConnectionObserver,
    {
        connect_config_with_observer_and_raw(self, observer)
    }

    fn connect_with_observer_and_raw<O, Raw>(
        self,
        observer: O,
    ) -> impl Future<Output = Result<Connection<O, Raw>>>
    where
        Self: IntoValidatedConnectionConfig,
        O: ConnectionObserver,
        Raw: FrameRaw,
    {
        connect_config_with_observer_and_raw(self, observer)
    }
}

impl<T> ConnectionConnect for T where T: IntoValidatedConnectionConfig {}

#[doc(hidden)]
pub trait IntoValidatedConnectionConfig {
    fn into_validated_connection_config(self) -> Result<ValidatedConnectionConfig>;
}

impl IntoValidatedConnectionConfig for ConnectionConfig {
    fn into_validated_connection_config(self) -> Result<ValidatedConnectionConfig> {
        self.validate()
    }
}

impl IntoValidatedConnectionConfig for ConnectionRequest {
    fn into_validated_connection_config(self) -> Result<ValidatedConnectionConfig> {
        self.validate()
    }
}

impl IntoValidatedConnectionConfig for ValidatedConnectionConfig {
    fn into_validated_connection_config(self) -> Result<ValidatedConnectionConfig> {
        Ok(self)
    }
}

async fn connect_config_with_observer_and_raw<C, O, Raw>(
    config: C,
    observer: O,
) -> Result<Connection<O, Raw>>
where
    C: IntoValidatedConnectionConfig,
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    connect_validated_with_observer_and_raw(config.into_validated_connection_config()?, observer)
        .await
}

async fn connect_validated_with_observer_and_raw<O, Raw>(
    config: ValidatedConnectionConfig,
    observer: O,
) -> Result<Connection<O, Raw>>
where
    O: ConnectionObserver,
    Raw: FrameRaw,
{
    let websocket_url = config.websocket_url.clone();
    let tuning = config.options.tuning;
    let endpoint = config.endpoint.clone();
    let guild_id = config.identity.guild_id;
    let channel_id = config.identity.channel_id;
    let user_id = config.identity.user_id;
    let (ws_stream, _) = observed_stage_timeout(
        &observer,
        ConnectionEvent {
            endpoint: &endpoint,
            guild_id,
            user_id,
        },
        ConnectStage::WebSocketConnect,
        CONNECT_TIMEOUT,
        VoiceEndpoint::new(&websocket_url).connect_websocket(),
    )
    .await?;
    let (mut write, mut read) = ws_stream.split();

    let hello = observed_stage_timeout(
        &observer,
        ConnectionEvent {
            endpoint: &endpoint,
            guild_id,
            user_id,
        },
        ConnectStage::Hello,
        HELLO_TIMEOUT,
        read_event(&mut read),
    )
    .await?;
    let hello_data: HelloData = parse_data(hello.data)?;

    write
        .send(WsMessage::Text(identify_payload(&config)?.into()))
        .await?;

    let mut last_seq = hello.seq;
    let ready_event = observed_stage_timeout(
        &observer,
        ConnectionEvent {
            endpoint: &endpoint,
            guild_id,
            user_id,
        },
        ConnectStage::Ready,
        READY_TIMEOUT,
        wait_for_opcode(&mut read, Opcode::Ready, &mut last_seq),
    )
    .await?;
    let ready: GatewayReady = parse_data(ready_event.data)?;

    let udp_socket = VoiceUdpRemote::parse(&ready.ip)?.bind_socket().await?;
    udp_socket.connect((&*ready.ip, ready.port)).await?;
    udp_socket
        .send(&UdpDiscoveryPacket::request(ready.ssrc))
        .await?;

    let mut discovery_buffer = [0_u8; UdpDiscoveryPacket::LEN];
    let received = observed_stage_timeout(
        &observer,
        ConnectionEvent {
            endpoint: &endpoint,
            guild_id,
            user_id,
        },
        ConnectStage::UdpDiscovery,
        UDP_DISCOVERY_TIMEOUT,
        async { Ok(udp_socket.recv(&mut discovery_buffer).await?) },
    )
    .await?;
    let discovery = UdpDiscoveryPacket::decode(&discovery_buffer[..received])?;
    let selected_mode = ready.select_encryption_mode(&config.options)?;

    write
        .send(WsMessage::Text(
            GatewayCommand::SelectProtocol(SelectProtocolCommand::udp(
                discovery.address.clone(),
                discovery.port,
                selected_mode,
                &config.options.codec_preferences,
            ))
            .text_payload()?
            .into(),
        ))
        .await?;

    let (session_description_event, pending_events) = observed_stage_timeout(
        &observer,
        ConnectionEvent {
            endpoint: &endpoint,
            guild_id,
            user_id,
        },
        ConnectStage::SessionDescription,
        SESSION_DESCRIPTION_TIMEOUT,
        wait_for_session_description(&mut read, &mut last_seq),
    )
    .await?;
    let session_description: SessionDescription = parse_data(session_description_event.data)?;
    let rtp_codecs =
        DiscordRtpCodecMap::new(&session_description, &config.options.codec_preferences)?;
    let dave_protocol_version = session_description.dave_protocol_version;
    let dave_identity = config.options.dave_identity.clone();
    let runtime_config = config.runtime_config();
    let mut dave = DaveInternalState::default();
    dave.set_session_protocol(dave_protocol_version);

    let initial_state = ConnectionInternalState {
        config: runtime_config,
        heartbeat_interval_ms: hello_data.heartbeat_interval_ms(),
        last_seq,
        ready,
        discovery,
        selected_mode,
        session_description: Some(session_description),
        rtp_codecs: Some(rtp_codecs),
        connected_user_ids: Arc::new(HashSet::from([user_id])),
        ssrc_users: Arc::new(HashMap::new()),
        speaking: Arc::new(HashMap::new()),
        dave,
        roster_authoritative: false,
        resumed: false,
    };
    let mut state = ConnectionStateStore::new(initial_state);
    replay_pending_voice_events(&mut state, pending_events, &observer)?;
    let transport_crypto = {
        let session_description = state
            .internal()
            .session_description
            .as_ref()
            .ok_or(Error::Protocol(ProtocolError::MissingSessionDescription))?;
        TransportCrypto::from_config(&session_description.transport_crypto)?
    };
    let (command_tx, command_rx) = mpsc::channel::<ConnectionCommand<Raw>>(128);
    let (media_tx, media_rx) = mpsc::channel::<PlayoutCommand>(tuning.media_queue_capacity.get());
    let close = ConnectionClose::new();
    let state_rx = state.subscribe_public();
    let task = tokio::spawn(
        ConnectionDriver {
            write,
            read,
            command_rx,
            media_rx,
            close: close.clone(),
            dave: if let Some(dave_identity) = dave_identity {
                DaveCoordinator::new_with_identity(user_id, channel_id, dave_identity)?
            } else {
                DaveCoordinator::new(user_id, channel_id)?
            },
            receive: ReceivePipeline::new(tuning),
            send: SendPipeline::new(state.internal())?,
            transport_crypto,
            pending_media_ready_waits: DeadlineQueue::default(),
            pending_media_ready_sends: DeadlineQueue::default(),
            state,
            observer: observer.clone(),
            udp_socket,
        }
        .run(),
    );
    let abort = task.abort_handle();
    let join_tx = spawn_voice_connection_join_task(task);

    Ok(Connection {
        inner: Arc::new(ConnectionInner {
            state_rx,
            command_tx,
            media_tx,
            close,
            join_tx,
            abort,
            observer,
        }),
    })
}

pub(crate) async fn stage_timeout<T>(
    stage: ConnectStage,
    duration: Duration,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    match timeout(duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::Timeout {
            stage: Some(stage),
            duration,
        }),
    }
}

pub(crate) async fn observed_stage_timeout<O, T>(
    observer: &O,
    connection: ConnectionEvent<'_>,
    stage: ConnectStage,
    duration: Duration,
    future: impl Future<Output = Result<T>>,
) -> Result<T>
where
    O: ConnectionObserver,
{
    let started = Instant::now();
    let result = stage_timeout(stage, duration, future).await;
    match &result {
        Ok(_) => observer.connect_stage_completed(ConnectStageCompletedEvent {
            endpoint: connection.endpoint,
            guild_id: connection.guild_id,
            user_id: connection.user_id,
            stage,
            elapsed: started.elapsed(),
        }),
        Err(error) => observer.connect_stage_failed(ConnectStageFailedEvent {
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

pub(crate) fn heartbeat_ack_timeout(heartbeat_interval_ms: u64) -> Duration {
    Duration::from_millis(heartbeat_interval_ms.saturating_mul(2)).max(Duration::from_secs(1))
}
