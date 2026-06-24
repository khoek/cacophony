use std::{collections::HashSet, time::Duration};

use dave::MediaType;
use tokio::{sync::oneshot, time::Instant};

use crate::{
    dave::{
        dave_decrypt_failure_should_retry, dave_gateway_media_ready, dave_receive_transform_active,
        dave_transition_zero_media_ready,
    },
    errors::{DaveError, Error, PayloadKind, ProtocolError, Result},
    media::{
        FrameRaw, RawUdpPacket, RawUdpPacketInfo, ReceivedFrame, detect_rtp_codec, parse_rtp_header,
    },
    observer::{
        ConnectionObserver, DavePendingMediaReason, ReceiveDecodeContext, ReceiveDecodeErrorKind,
        ReceiveDecodeStage, ReceiveFrameDropReason, ReceiveFrameDroppedEvent, RtcpPacketEvent,
        observe_receive_decode_error,
    },
    queue::{BoundedDeque, BucketQueue, PendingRequest, PendingRequestQueue, QueueBucket},
    state::{
        ConnectionTuning, DavePendingMediaRetry, PendingMediaFrame, PendingMediaPacket,
        ReceiveState,
    },
};

use super::driver::ConnectionDriver;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LowLevelReceiveKind {
    RawUdp,
    RtpUdp,
}

impl LowLevelReceiveKind {
    pub(crate) const ALL: [Self; 2] = [Self::RawUdp, Self::RtpUdp];
    pub(crate) const COUNT: usize = Self::ALL.len();

    pub(crate) const fn payload_kind(self) -> PayloadKind {
        match self {
            Self::RawUdp => PayloadKind::RawUdpPacket,
            Self::RtpUdp => PayloadKind::RtpPacket,
        }
    }

    pub(crate) fn accepts(self, info: RawUdpPacketInfo) -> bool {
        match self {
            Self::RawUdp => true,
            Self::RtpUdp => !info.is_rtcp(),
        }
    }
}

impl QueueBucket for LowLevelReceiveKind {
    fn index(self) -> usize {
        match self {
            Self::RawUdp => 0,
            Self::RtpUdp => 1,
        }
    }
}

pub(crate) struct PendingReceive<T> {
    pub(crate) id: u64,
    pub(crate) max_len: usize,
    pub(crate) deadline: Option<Instant>,
    pub(crate) max_wait: Option<Duration>,
    pub(crate) response: oneshot::Sender<Result<T>>,
}

impl<T> PendingReceive<T> {
    pub(crate) fn is_closed(&self) -> bool {
        self.response.is_closed()
    }

    #[cfg(test)]
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    pub(crate) fn complete(self, result: Result<T>) {
        let _ = self.response.send(result);
    }

    #[cfg(test)]
    pub(crate) fn complete_timeout(self) {
        <Self as PendingRequest>::complete_timeout(self);
    }
}

impl<T> PendingRequest for PendingReceive<T> {
    type Key = u64;

    fn key(&self) -> Self::Key {
        self.id
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn is_closed(&self) -> bool {
        self.is_closed()
    }

    fn complete_timeout(self) {
        if let Some(duration) = self.max_wait {
            let _ = self.response.send(Err(Error::Timeout {
                stage: None,
                duration,
            }));
        } else {
            let _ = self.response.send(Err(Error::Closed));
        }
    }

    fn complete_closed(self) {
        let _ = self.response.send(Err(Error::Closed));
    }
}

pub(crate) type PendingPacketReceive = PendingReceive<RawUdpPacket>;
pub(crate) type FrameReceiveResult<Raw> = Result<ReceivedFrame<Raw>>;

pub(crate) struct ReadyFrameQueue<Raw>
where
    Raw: FrameRaw,
{
    frames: BoundedDeque<FrameReceiveResult<Raw>>,
}

impl<Raw> Default for ReadyFrameQueue<Raw>
where
    Raw: FrameRaw,
{
    fn default() -> Self {
        Self::new(ConnectionTuning::default().ready_frame_buffer_max)
    }
}

impl<Raw> ReadyFrameQueue<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn new(max_frames: usize) -> Self {
        Self {
            frames: BoundedDeque::new(max_frames),
        }
    }

    pub(crate) fn pop_front(&mut self) -> Option<FrameReceiveResult<Raw>> {
        self.frames.pop_front()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.frames.has_capacity()
    }

    pub(crate) fn push<O>(&mut self, observer: &O, result: FrameReceiveResult<Raw>)
    where
        O: ConnectionObserver,
    {
        let queued_before = self.frames.len();
        if let Some(dropped) = self.frames.push_back(result) {
            Self::observe_dropped(observer, &dropped, queued_before.saturating_sub(1));
        }
    }

    pub(crate) fn prune_ssrcs(&mut self, removed_ssrcs: &HashSet<u32>) {
        if removed_ssrcs.is_empty() {
            return;
        }
        self.frames.retain(|result| {
            result
                .as_ref()
                .map_or(true, |frame| !removed_ssrcs.contains(&frame.rtp.ssrc))
        });
    }

    fn observe_dropped<O>(observer: &O, result: &FrameReceiveResult<Raw>, queued_frames: usize)
    where
        O: ConnectionObserver,
    {
        if !O::ENABLE_RECEIVE_TELEMETRY {
            return;
        }
        let (ssrc, user_id, seq, dropped_error) = match result {
            Ok(frame) => (
                Some(frame.rtp.ssrc),
                frame.user_id,
                Some(frame.rtp.seq),
                false,
            ),
            Err(_) => (None, None, None, true),
        };
        observer.receive_frame_dropped(ReceiveFrameDroppedEvent {
            reason: ReceiveFrameDropReason::ReadyQueueOverflow,
            ssrc,
            user_id,
            seq,
            queued_frames,
            dropped_error,
        });
    }
}

pub(super) struct ReceivePipeline<Raw>
where
    Raw: FrameRaw,
{
    pub(super) state: ReceiveState<Raw>,
    pub(super) udp_buffer: Vec<u8>,
    pub(super) payload_buffer: Vec<u8>,
    pub(super) ready_frames: ReadyFrameQueue<Raw>,
    pub(super) pending_frame_receives: PendingRequestQueue<PendingReceive<ReceivedFrame<Raw>>>,
    pending_packet_receives:
        BucketQueue<LowLevelReceiveKind, PendingPacketReceive, { LowLevelReceiveKind::COUNT }>,
    next_receive_id: u64,
}

impl<Raw> ReceivePipeline<Raw>
where
    Raw: FrameRaw,
{
    pub(super) fn new(tuning: ConnectionTuning) -> Self {
        Self {
            state: ReceiveState::new(tuning),
            udp_buffer: Vec::new(),
            payload_buffer: Vec::new(),
            ready_frames: ReadyFrameQueue::new(tuning.ready_frame_buffer_max),
            pending_frame_receives: PendingRequestQueue::default(),
            pending_packet_receives: BucketQueue::default(),
            next_receive_id: 1,
        }
    }

    pub(super) fn next_receive_id(&mut self) -> u64 {
        let id = self.next_receive_id;
        self.next_receive_id = self.next_receive_id.wrapping_add(1).max(1);
        id
    }

    pub(super) fn push_packet_receive(
        &mut self,
        kind: LowLevelReceiveKind,
        receive: PendingPacketReceive,
    ) {
        self.pending_packet_receives.push_back(kind, receive);
    }

    pub(super) fn pop_packet_receive(
        &mut self,
        kind: LowLevelReceiveKind,
    ) -> Option<PendingPacketReceive> {
        self.pending_packet_receives.pop_front(kind)
    }

    pub(super) fn discard_closed_packet_receives(&mut self) {
        for kind in LowLevelReceiveKind::ALL {
            self.pending_packet_receives
                .retain(kind, |receive| !receive.is_closed());
        }
    }

    pub(super) fn complete_closed_packet_receives(&mut self) {
        for kind in LowLevelReceiveKind::ALL {
            while let Some(receive) = self.pending_packet_receives.pop_front(kind) {
                <PendingPacketReceive as PendingRequest>::complete_closed(receive);
            }
        }
    }
}

pub(super) fn take_receive_payload_buffer(buffer: &mut Vec<u8>) -> Vec<u8> {
    std::mem::take(buffer)
}

pub(super) fn recycle_receive_payload_buffer(buffer: &mut Vec<u8>, mut payload: Vec<u8>) {
    payload.clear();
    if payload.capacity() > buffer.capacity() {
        *buffer = payload;
    }
}

pub(crate) fn limit_raw_packet_result(
    raw: RawUdpPacket,
    max_len: usize,
    kind: PayloadKind,
) -> Result<RawUdpPacket> {
    if raw.bytes.len() > max_len {
        Err(Error::PayloadTooLarge {
            kind,
            len: raw.bytes.len(),
            max_len,
        })
    } else {
        Ok(raw)
    }
}

pub(crate) fn limit_voice_frame_result<Raw>(
    result: FrameReceiveResult<Raw>,
    max_len: usize,
) -> FrameReceiveResult<Raw>
where
    Raw: FrameRaw,
{
    result.and_then(|frame| {
        if frame.frame.len() > max_len {
            Err(Error::PayloadTooLarge {
                kind: PayloadKind::Frame,
                len: frame.frame.len(),
                max_len,
            })
        } else {
            Ok(frame)
        }
    })
}

impl<O, Raw> ConnectionDriver<O, Raw>
where
    O: crate::observer::ConnectionObserver,
    Raw: crate::media::FrameRaw,
{
    pub(super) fn resolve_pending_receives(&mut self) {
        loop {
            self.receive.pending_frame_receives.discard_closed();
            if self.receive.pending_frame_receives.is_empty() {
                return;
            }
            let Some(receive) = self.receive.pending_frame_receives.pop_front() else {
                return;
            };
            let result = match self.receive.ready_frames.pop_front() {
                Some(result) => result,
                None => {
                    let Some(result) = self.drain_ready_voice_frame() else {
                        self.receive.pending_frame_receives.push_front(receive);
                        return;
                    };
                    result
                }
            };
            let max_len = receive.max_len;
            receive.complete(limit_voice_frame_result(result, max_len));
        }
    }

    fn queue_ready_voice_frame(&mut self, result: FrameReceiveResult<Raw>) {
        self.receive.ready_frames.push(&self.observer, result);
    }

    pub(super) fn collect_ready_voice_frames(&mut self) {
        while self.receive.ready_frames.has_capacity() {
            let Some(result) = self.drain_ready_voice_frame() else {
                return;
            };
            self.queue_ready_voice_frame(result);
        }
    }

    pub(super) fn discard_inactive_pending_receives(&mut self) {
        let now = Instant::now();
        self.receive.discard_closed_packet_receives();
        self.receive.pending_frame_receives.complete_expired(now);
        self.receive.pending_frame_receives.discard_closed();
    }

    pub(super) fn handle_received_udp_packet(&mut self, len: usize) {
        let info = RawUdpPacketInfo::from_bytes(&self.receive.udp_buffer[..len]);
        self.resolve_pending_low_level_receives(info, len);
        if info.is_rtcp() {
            self.observe_rtcp_packet(info, len);
            return;
        }
        if let Some(result) = self.decode_received_voice_packet(info, len) {
            self.queue_ready_voice_frame(result);
        }
        self.collect_ready_voice_frames();
        self.resolve_pending_receives();
    }

    fn resolve_pending_low_level_receives(&mut self, info: RawUdpPacketInfo, len: usize) {
        for kind in LowLevelReceiveKind::ALL {
            if kind.accepts(info) {
                self.resolve_pending_packet_receive(kind, info, len);
            }
        }
    }

    fn resolve_pending_packet_receive(
        &mut self,
        kind: LowLevelReceiveKind,
        info: RawUdpPacketInfo,
        len: usize,
    ) {
        let Some(receive) = self.receive.pop_packet_receive(kind) else {
            return;
        };
        let max_len = receive.max_len;
        receive.complete(limit_raw_packet_result(
            info.into_raw_packet(&self.receive.udp_buffer[..len]),
            max_len,
            kind.payload_kind(),
        ));
    }

    fn decode_received_voice_packet(
        &mut self,
        info: RawUdpPacketInfo,
        len: usize,
    ) -> Option<FrameReceiveResult<Raw>> {
        let rtp = match parse_rtp_header(&self.receive.udp_buffer[..len]) {
            Ok(rtp) => rtp,
            Err(error) => {
                self.observe_decode_error(
                    ReceiveDecodeStage::Rtp,
                    ReceiveDecodeErrorKind::MalformedRtp,
                    info.ssrc,
                    None,
                    info.seq,
                    &error,
                );
                return Some(Err(error.into()));
            }
        };
        let (user_id, codec, dave_active) = {
            let state = self.state.internal();
            let session_description = match state.session_description.as_ref() {
                Some(session_description) => session_description,
                None => {
                    return Some(Err(Error::Protocol(
                        ProtocolError::MissingSessionDescription,
                    )));
                }
            };
            let user_id = state.ssrc_users.get(&rtp.ssrc).copied();
            let codec = match detect_rtp_codec(&rtp, session_description) {
                Ok(codec) => codec,
                Err(error) => {
                    self.observe_decode_error(
                        ReceiveDecodeStage::Codec,
                        ReceiveDecodeErrorKind::UnsupportedCodec,
                        Some(rtp.ssrc),
                        user_id,
                        Some(rtp.seq),
                        &error,
                    );
                    return Some(Err(error.into()));
                }
            };
            (user_id, codec, dave_receive_transform_active(&state.dave))
        };
        self.receive.payload_buffer.clear();
        let packet_bytes = &self.receive.udp_buffer[..len];
        if let Err(error) = self.transport_crypto.decrypt_payload_into(
            packet_bytes,
            &rtp,
            &mut self.receive.payload_buffer,
        ) {
            self.observe_decode_error(
                ReceiveDecodeStage::Transport,
                ReceiveDecodeErrorKind::TransportDecryptFailed,
                Some(rtp.ssrc),
                user_id,
                Some(rtp.seq),
                &error,
            );
            return Some(Err(error));
        }
        let packet = PendingMediaPacket {
            raw: Raw::capture_packet(packet_bytes, info),
            rtp,
            user_id,
            codec,
            encrypted_payload: take_receive_payload_buffer(&mut self.receive.payload_buffer),
            dave: dave_active,
        };
        let media = self
            .receive
            .state
            .push_media_packet(&self.observer, packet)?;
        self.decode_ordered_media_frame(media)
    }

    fn drain_ready_voice_frame(&mut self) -> Option<FrameReceiveResult<Raw>> {
        while let Some(media) = self.receive.state.drain_ordered_media(&self.observer) {
            if let Some(result) = self.decode_ordered_media_frame(media) {
                return Some(result);
            }
        }
        None
    }

    fn decode_ordered_media_frame(
        &mut self,
        media: PendingMediaFrame<Raw>,
    ) -> Option<FrameReceiveResult<Raw>> {
        if media.dave {
            return self.decode_or_enqueue_dave_media(media);
        }
        Some(Ok(ReceivedFrame {
            raw: media.raw,
            rtp: media.rtp,
            user_id: media.user_id,
            media_type: MediaType::Audio,
            codec: media.codec,
            frame: media.encrypted_frame,
        }))
    }

    pub(super) fn retry_pending_dave_media(&mut self, retry: DavePendingMediaRetry) {
        if retry.is_empty() {
            return;
        }
        let ttl = self.state.internal().config.tuning.dave_pending_media_ttl;
        while let Some(mut media) = self.receive.state.pending_dave_media.pop_retry(retry) {
            media.was_pending = true;
            if media.enqueued_at.elapsed() >= ttl {
                self.observe_pending_dave_media(&media, DavePendingMediaReason::Expired, false);
                continue;
            }
            if let Some(result) = self.decode_or_enqueue_dave_media(media) {
                self.queue_ready_voice_frame(result);
            }
        }
    }

    pub(super) fn expire_pending_dave_media(&mut self) {
        let ttl = self.state.internal().config.tuning.dave_pending_media_ttl;
        while let Some(media) = self
            .receive
            .state
            .pending_dave_media
            .pop_expired(Instant::now(), ttl)
        {
            self.observe_pending_dave_media(&media, DavePendingMediaReason::Expired, false);
        }
    }

    fn decode_or_enqueue_dave_media(
        &mut self,
        mut media: PendingMediaFrame<Raw>,
    ) -> Option<FrameReceiveResult<Raw>> {
        media.user_id = self
            .state
            .internal()
            .ssrc_users
            .get(&media.rtp.ssrc)
            .copied();
        if media.user_id.is_none() {
            self.enqueue_dave_media(media, DavePendingMediaReason::MissingUser);
            return None;
        }
        let (gateway_pending, transition_zero_ready) = {
            let state = self.state.internal();
            (
                !dave_gateway_media_ready(&state.dave),
                dave_transition_zero_media_ready(&state.dave, self.dave.transition_ready()),
            )
        };
        if !self.dave.ready() {
            self.enqueue_dave_media(media, DavePendingMediaReason::SessionNotReady);
            return None;
        }
        if gateway_pending && !transition_zero_ready {
            self.enqueue_dave_media(media, DavePendingMediaReason::GatewayPending);
            return None;
        }
        self.receive.payload_buffer.clear();
        match self.dave.decrypt_discord_voice_frame_into(
            media.user_id,
            &media.encrypted_frame,
            &mut self.receive.payload_buffer,
        ) {
            Ok(len) => {
                if media.was_pending {
                    self.observe_pending_dave_media(&media, media.reason, true);
                }
                self.receive.payload_buffer.truncate(len);
                let frame = take_receive_payload_buffer(&mut self.receive.payload_buffer);
                recycle_receive_payload_buffer(
                    &mut self.receive.payload_buffer,
                    std::mem::take(&mut media.encrypted_frame),
                );
                Some(Ok(ReceivedFrame {
                    raw: media.raw,
                    rtp: media.rtp,
                    user_id: media.user_id,
                    media_type: MediaType::Audio,
                    codec: media.codec,
                    frame,
                }))
            }
            Err(error) => {
                let kind = error.receive_decode_kind();
                self.observe_decode_error(
                    ReceiveDecodeStage::DaveDecrypt,
                    kind,
                    Some(media.rtp.ssrc),
                    media.user_id,
                    Some(media.rtp.seq),
                    &error,
                );
                if media.enqueued_at.elapsed()
                    < self.state.internal().config.tuning.dave_pending_media_ttl
                    && dave_decrypt_failure_should_retry(
                        kind,
                        self.dave_decrypt_state_can_still_change(),
                    )
                {
                    let reason = if error.is_no_valid_cryptor() {
                        DavePendingMediaReason::NoValidCryptorPending
                    } else {
                        DavePendingMediaReason::DecryptStatePending
                    };
                    self.enqueue_dave_media(media, reason);
                    return None;
                }
                self.observe_pending_dave_media(
                    &media,
                    DavePendingMediaReason::StableDecryptFailure,
                    false,
                );
                let error = DaveError::Decrypt(error).into();
                recycle_receive_payload_buffer(
                    &mut self.receive.payload_buffer,
                    std::mem::take(&mut media.encrypted_frame),
                );
                Some(Err(error))
            }
        }
    }

    fn enqueue_dave_media(
        &mut self,
        mut media: PendingMediaFrame<Raw>,
        reason: DavePendingMediaReason,
    ) {
        let was_pending = media.was_pending;
        media.reason = reason;
        let event = (O::ENABLE_RECEIVE_TELEMETRY && !was_pending)
            .then(|| media.event(self.receive.state.pending_dave_media.len() + 1, reason));
        let pending_packets = self.receive.state.pending_dave_media.push(media);
        if let Some(mut event) = event {
            event.pending_packets = pending_packets;
            self.observer.dave_pending_media_enqueued(event);
        }
    }

    fn observe_pending_dave_media(
        &self,
        media: &PendingMediaFrame<Raw>,
        reason: DavePendingMediaReason,
        drained: bool,
    ) {
        if !O::ENABLE_RECEIVE_TELEMETRY {
            return;
        }
        let event = media.event(self.receive.state.pending_dave_media.len(), reason);
        if drained {
            self.observer.dave_pending_media_drained(event);
        } else if matches!(
            reason,
            DavePendingMediaReason::StableDecryptFailure | DavePendingMediaReason::Expired
        ) {
            self.observer.dave_pending_media_dropped(event);
        } else {
            self.observer.dave_pending_media_enqueued(event);
        }
    }

    fn observe_rtcp_packet(&self, info: RawUdpPacketInfo, len: usize) {
        if !O::ENABLE_RTCP {
            return;
        }
        let bytes = &self.receive.udp_buffer[..len];
        let connection = self.state.internal().config.public_info();
        self.observer.rtcp_packet_received(RtcpPacketEvent {
            endpoint: &connection.endpoint,
            guild_id: connection.server_id,
            user_id: connection.user_id,
            bytes,
            header: info.rtcp_header(bytes),
        });
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
            &self.observer,
            stage,
            kind,
            ReceiveDecodeContext { ssrc, user_id, seq },
            error,
        );
    }
}
