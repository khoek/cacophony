use std::{
    collections::VecDeque,
    time::{Duration, Instant as StdInstant},
};

use tokio::{
    sync::{mpsc, oneshot, watch},
    time::Instant,
};

use crate::{
    errors::{BackpressureError, Error, Result},
    gateway::{GatewayCommand, SpeakingCommand, SpeakingFlags},
    media::{OutboundPacket, RtpPayload},
    opus::{Codec, discord::Packet},
};

use super::{ConnectionClose, driver::ConnectionDriver};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DurationDistribution {
    pub count: usize,
    pub min: Option<Duration>,
    pub avg: Option<Duration>,
    pub p95: Option<Duration>,
    pub max: Option<Duration>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpusPlayoutStats {
    pub packets: usize,
    pub first_packet: Option<OutboundPacket>,
    pub last_packet: Option<OutboundPacket>,
    pub first_packet_sent_at: Option<StdInstant>,
    pub first_packet_sent_after_start: Option<Duration>,
    pub wall_elapsed: Duration,
    pub expected_media: Duration,
    pub send_call: DurationDistribution,
    pub inter_frame_gap: DurationDistribution,
    pub scheduler_lateness: DurationDistribution,
    pub late_wakes_over_5ms: usize,
    pub late_wakes_over_20ms: usize,
    pub underflows: usize,
    pub underflow_wait: DurationDistribution,
    pub dropped_stale_frames: usize,
    pub clock_rebases: usize,
    pub clock_rebase_wait: DurationDistribution,
    pub dave_enabled: bool,
}

pub struct OpusPlayout {
    pub(super) id: u64,
    pub(super) media_tx: mpsc::Sender<PlayoutCommand>,
    pub(super) close: ConnectionClose,
    pub(super) finished: bool,
}

impl OpusPlayout {
    fn ensure_open(&self) -> Result<()> {
        if self.close.is_closed() {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    pub async fn push_packet(&self, packet: &[u8], duration: Duration) -> Result<()> {
        self.push_bytes_owned(packet.to_vec(), duration).await
    }

    pub async fn push_packet_owned(&self, packet: Packet) -> Result<()> {
        self.push_payload_owned(packet).await
    }

    pub async fn push_payload_owned<P>(&self, payload: P) -> Result<()>
    where
        P: RtpPayload<Codec = Codec>,
    {
        let duration = payload.duration();
        self.push_bytes_owned(payload.into_bytes(), duration).await
    }

    pub async fn push_bytes_owned(&self, packet: Vec<u8>, duration: Duration) -> Result<()> {
        self.ensure_open()?;
        self.media_tx
            .send(PlayoutCommand::Frame {
                id: self.id,
                frame: PlayoutFrame {
                    frame: packet,
                    duration,
                },
            })
            .await
            .map_err(|_| Error::Closed)
    }

    pub fn try_push_packet_owned(&self, packet: Packet) -> Result<()> {
        self.try_push_payload_owned(packet)
    }

    pub fn try_push_payload_owned<P>(&self, payload: P) -> Result<()>
    where
        P: RtpPayload<Codec = Codec>,
    {
        let duration = payload.duration();
        self.try_push_bytes_owned(payload.into_bytes(), duration)
    }

    pub fn try_push_bytes_owned(&self, packet: Vec<u8>, duration: Duration) -> Result<()> {
        self.ensure_open()?;
        match self.media_tx.try_send(PlayoutCommand::Frame {
            id: self.id,
            frame: PlayoutFrame {
                frame: packet,
                duration,
            },
        }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(Error::Backpressure(BackpressureError::MediaQueueFull))
            }
        }
    }

    pub async fn finish(mut self) -> Result<OpusPlayoutStats> {
        let stats = self.finish_inner().await?;
        self.finished = true;
        Ok(stats)
    }

    async fn finish_inner(&self) -> Result<OpusPlayoutStats> {
        self.ensure_open()?;
        let (response, receive) = oneshot::channel();
        self.media_tx
            .send(PlayoutCommand::Finish {
                id: self.id,
                response,
            })
            .await
            .map_err(|_| Error::Closed)?;
        receive.await.map_err(|_| Error::Closed)?
    }
}

impl Drop for OpusPlayout {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self
                .media_tx
                .try_send(PlayoutCommand::Cancel { id: self.id });
        }
    }
}

pub(crate) enum PlayoutCommand {
    Start {
        response: oneshot::Sender<Result<u64>>,
    },
    Frame {
        id: u64,
        frame: PlayoutFrame,
    },
    Finish {
        id: u64,
        response: oneshot::Sender<Result<OpusPlayoutStats>>,
    },
    Cancel {
        id: u64,
    },
}

impl PlayoutCommand {
    pub(crate) fn complete_closed(self) {
        match self {
            Self::Start { response } => {
                let _ = response.send(Err(Error::Closed));
            }
            Self::Finish { response, .. } => {
                let _ = response.send(Err(Error::Closed));
            }
            Self::Frame { .. } | Self::Cancel { .. } => {}
        }
    }
}

pub(crate) struct PlayoutFrame {
    pub(super) frame: Vec<u8>,
    pub(super) duration: Duration,
}

pub(super) struct ActiveOpusPlayout {
    pub(super) id: u64,
    pub(super) started_at: StdInstant,
    pub(super) frames: VecDeque<PlayoutFrame>,
    pub(super) next_send_at: Option<Instant>,
    pub(super) media_ready_deadline: Option<Instant>,
    pub(super) finish_response: Option<oneshot::Sender<Result<OpusPlayoutStats>>>,
    pub(super) speaking: bool,
    pub(super) stats: ActiveOpusPlayoutStats,
}

impl ActiveOpusPlayout {
    pub(super) fn new(id: u64, dave_enabled: bool) -> Self {
        Self {
            id,
            started_at: StdInstant::now(),
            frames: VecDeque::new(),
            next_send_at: None,
            media_ready_deadline: None,
            finish_response: None,
            speaking: false,
            stats: ActiveOpusPlayoutStats {
                dave_enabled,
                ..ActiveOpusPlayoutStats::default()
            },
        }
    }

    pub(super) fn push(&mut self, frame: PlayoutFrame) {
        if self.frames.is_empty() && self.finish_response.is_none() {
            let now = Instant::now();
            if self
                .next_send_at
                .is_some_and(|next_send_at| now > next_send_at)
            {
                let next_send_at = self.next_send_at.take().expect("deadline checked");
                self.stats.underflows += 1;
                self.stats.underflow_wait.observe(now - next_send_at);
            }
        }
        self.frames.push_back(frame);
    }

    pub(super) fn finish(&mut self, response: oneshot::Sender<Result<OpusPlayoutStats>>) {
        self.finish_response = Some(response);
    }

    pub(super) fn cancel(mut self) {
        if let Some(response) = self.finish_response.take() {
            let _ = response.send(Err(Error::Closed));
        }
    }

    pub(super) fn dave_deadline(&self) -> Option<Instant> {
        (!self.frames.is_empty())
            .then_some(self.media_ready_deadline)
            .flatten()
    }

    pub(super) fn wake_deadline(&self) -> Option<Instant> {
        if !self.frames.is_empty() {
            return self.next_send_at.or_else(|| Some(Instant::now()));
        }
        if self.finish_response.is_some() {
            return self.next_send_at;
        }
        None
    }

    pub(super) fn ready_to_complete(&self) -> bool {
        if self.finish_response.is_none() || !self.frames.is_empty() {
            return false;
        }
        self.next_send_at
            .is_none_or(|deadline| Instant::now() >= deadline)
    }

    pub(super) fn stats(self) -> OpusPlayoutStats {
        self.stats.finish(self.started_at.elapsed())
    }
}

#[derive(Default)]
pub(super) struct ActiveOpusPlayoutStats {
    packets: usize,
    first_packet: Option<OutboundPacket>,
    last_packet: Option<OutboundPacket>,
    first_packet_sent_at: Option<StdInstant>,
    first_packet_sent_after_start: Option<Duration>,
    expected_media: Duration,
    send_call: TimingSamples,
    inter_frame_gap: TimingSamples,
    scheduler_lateness: TimingSamples,
    late_wakes_over_5ms: usize,
    late_wakes_over_20ms: usize,
    pub(super) underflows: usize,
    pub(super) underflow_wait: TimingSamples,
    pub(super) dropped_stale_frames: usize,
    clock_rebases: usize,
    clock_rebase_wait: TimingSamples,
    last_send_started_at: Option<Instant>,
    dave_enabled: bool,
}

impl ActiveOpusPlayoutStats {
    pub(super) fn record_send_started(&mut self, now: Instant) {
        if let Some(previous) = self.last_send_started_at {
            self.inter_frame_gap.observe(now - previous);
        }
        self.last_send_started_at = Some(now);
    }

    pub(super) fn record_packet_sent(
        &mut self,
        started_at: StdInstant,
        send_started: Instant,
        packet: OutboundPacket,
        duration: Duration,
    ) {
        self.send_call.observe(send_started.elapsed());
        self.expected_media += duration;
        self.packets += 1;
        if self.first_packet.is_none() {
            let now = StdInstant::now();
            self.first_packet = Some(packet.clone());
            self.first_packet_sent_at = Some(now);
            self.first_packet_sent_after_start = Some(now.duration_since(started_at));
        }
        self.last_packet = Some(packet);
    }

    pub(super) fn record_lateness(&mut self, lateness: Duration) {
        self.scheduler_lateness.observe(lateness);
        if lateness >= Duration::from_millis(5) {
            self.late_wakes_over_5ms += 1;
        }
        if lateness >= Duration::from_millis(20) {
            self.late_wakes_over_20ms += 1;
        }
    }

    pub(super) fn record_clock_rebase(&mut self, lateness: Duration) {
        self.clock_rebases += 1;
        self.clock_rebase_wait.observe(lateness);
    }

    fn finish(self, wall_elapsed: Duration) -> OpusPlayoutStats {
        OpusPlayoutStats {
            packets: self.packets,
            first_packet: self.first_packet,
            last_packet: self.last_packet,
            first_packet_sent_at: self.first_packet_sent_at,
            first_packet_sent_after_start: self.first_packet_sent_after_start,
            wall_elapsed,
            expected_media: self.expected_media,
            send_call: self.send_call.finish(),
            inter_frame_gap: self.inter_frame_gap.finish(),
            scheduler_lateness: self.scheduler_lateness.finish(),
            late_wakes_over_5ms: self.late_wakes_over_5ms,
            late_wakes_over_20ms: self.late_wakes_over_20ms,
            underflows: self.underflows,
            underflow_wait: self.underflow_wait.finish(),
            dropped_stale_frames: self.dropped_stale_frames,
            clock_rebases: self.clock_rebases,
            clock_rebase_wait: self.clock_rebase_wait.finish(),
            dave_enabled: self.dave_enabled,
        }
    }
}

#[derive(Default)]
pub(super) struct TimingSamples {
    values: Vec<Duration>,
}

impl TimingSamples {
    pub(super) fn observe(&mut self, value: Duration) {
        self.values.push(value);
    }

    fn finish(mut self) -> DurationDistribution {
        if self.values.is_empty() {
            return DurationDistribution::default();
        }
        let total = self
            .values
            .iter()
            .fold(Duration::ZERO, |total, value| total + *value);
        self.values.sort_unstable();
        let p95_index = (self.values.len() * 95).div_ceil(100).saturating_sub(1);
        DurationDistribution {
            count: self.values.len(),
            min: self.values.first().copied(),
            avg: Some(duration_div(total, self.values.len())),
            p95: Some(self.values[p95_index]),
            max: self.values.last().copied(),
        }
    }
}

fn duration_div(duration: Duration, divisor: usize) -> Duration {
    if divisor == 0 {
        return Duration::ZERO;
    }
    let nanos = duration.as_nanos() / divisor as u128;
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

impl<O, Raw> ConnectionDriver<O, Raw>
where
    O: crate::observer::ConnectionObserver,
    Raw: crate::media::FrameRaw,
{
    pub(super) async fn handle_playout_command(
        &mut self,
        command: PlayoutCommand,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Result<()> {
        match command {
            PlayoutCommand::Start { response } => {
                if self.send.active_playout.is_some() {
                    let _ = response.send(Err(Error::Backpressure(
                        BackpressureError::ActiveOpusPlayout,
                    )));
                    return Ok(());
                }
                let id = self.send.next_playout_id;
                self.send.next_playout_id = self.send.next_playout_id.wrapping_add(1).max(1);
                self.send.active_playout =
                    Some(ActiveOpusPlayout::new(id, self.dave_send_active()));
                let _ = response.send(Ok(id));
            }
            PlayoutCommand::Frame { id, frame } => {
                if let Some(playout) = self
                    .send
                    .active_playout
                    .as_mut()
                    .filter(|playout| playout.id == id)
                {
                    playout.push(frame);
                }
            }
            PlayoutCommand::Finish { id, response } => {
                if let Some(playout) = self
                    .send
                    .active_playout
                    .as_mut()
                    .filter(|playout| playout.id == id)
                {
                    playout.finish(response);
                } else {
                    let _ = response.send(Err(Error::Closed));
                }
            }
            PlayoutCommand::Cancel { id } => {
                if self
                    .send
                    .active_playout
                    .as_ref()
                    .is_some_and(|playout| playout.id == id)
                {
                    let Some(playout) = self.send.active_playout.take() else {
                        return Ok(());
                    };
                    self.cancel_playout(playout).await?;
                }
            }
        }
        self.resolve_active_playout(close_rx).await
    }

    pub(super) async fn resolve_active_playout(
        &mut self,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Result<()> {
        let Some(mut playout) = self.send.active_playout.take() else {
            return Ok(());
        };

        if playout.ready_to_complete() {
            self.complete_playout(playout).await?;
            return Ok(());
        }

        let Some(frame_duration) = playout.frames.front().map(|frame| frame.duration) else {
            self.send.active_playout = Some(playout);
            return Ok(());
        };

        let mut due_at = playout.next_send_at.unwrap_or_else(Instant::now);
        let now = Instant::now();
        if now < due_at {
            self.send.active_playout = Some(playout);
            return Ok(());
        }
        let mut scheduler_lateness = now.duration_since(due_at);
        if let Some(max_stale) = frame_duration.checked_mul(3) {
            while scheduler_lateness >= max_stale && playout.frames.len() > 1 {
                playout.frames.pop_front();
                playout.stats.dropped_stale_frames += 1;
                due_at += frame_duration;
                scheduler_lateness = now.saturating_duration_since(due_at);
            }
            if scheduler_lateness >= max_stale {
                playout.stats.record_clock_rebase(scheduler_lateness);
                due_at = now;
            }
        }
        if playout.next_send_at.is_some() {
            playout.stats.record_lateness(scheduler_lateness);
        }

        if self.dave_send_active() && !self.current_dave_media_status().media_ready {
            let timeout = self.state.internal().config.dave_send_media_ready_timeout;
            let deadline = *playout
                .media_ready_deadline
                .get_or_insert_with(|| Instant::now() + timeout);
            if Instant::now() >= deadline {
                self.fail_playout(
                    playout,
                    Error::Timeout {
                        stage: None,
                        duration: timeout,
                    },
                )
                .await?;
            } else {
                self.send.active_playout = Some(playout);
            }
            return Ok(());
        }
        playout.media_ready_deadline = None;

        if !playout.speaking {
            self.send_playout_speaking(SpeakingFlags::MICROPHONE)
                .await?;
            playout.speaking = true;
        }

        let Some(frame) = playout.frames.pop_front() else {
            self.send.active_playout = Some(playout);
            return Ok(());
        };
        let send_started = Instant::now();
        playout.stats.record_send_started(send_started);
        let packet = match self
            .send_ready_opus_frame(frame.frame, frame_duration, close_rx)
            .await
        {
            Ok(packet) => packet,
            Err(error) => {
                self.fail_playout(playout, error).await?;
                return Ok(());
            }
        };
        playout
            .stats
            .record_packet_sent(playout.started_at, send_started, packet, frame_duration);
        playout.next_send_at = Some(due_at + frame_duration);
        self.send.active_playout = Some(playout);
        Ok(())
    }

    async fn complete_playout(&mut self, mut playout: ActiveOpusPlayout) -> Result<()> {
        if playout.speaking {
            self.send_playout_speaking(SpeakingFlags::NONE).await?;
            playout.speaking = false;
        }
        if let Some(response) = playout.finish_response.take() {
            let _ = response.send(Ok(playout.stats()));
        }
        Ok(())
    }

    async fn fail_playout(&mut self, mut playout: ActiveOpusPlayout, error: Error) -> Result<()> {
        if playout.speaking {
            self.send_playout_speaking(SpeakingFlags::NONE).await?;
            playout.speaking = false;
        }
        if let Some(response) = playout.finish_response.take() {
            let _ = response.send(Err(error));
        }
        Ok(())
    }

    async fn cancel_playout(&mut self, mut playout: ActiveOpusPlayout) -> Result<()> {
        if playout.speaking {
            self.send_playout_speaking(SpeakingFlags::NONE).await?;
            playout.speaking = false;
        }
        playout.cancel();
        Ok(())
    }

    async fn send_playout_speaking(&mut self, flags: SpeakingFlags) -> Result<()> {
        let ssrc = self.state.internal().ready.ssrc;
        self.send_voice_gateway_command(GatewayCommand::Speaking(SpeakingCommand {
            speaking: flags.bits(),
            delay: Some(0),
            ssrc,
            user_id: None,
        }))
        .await
    }
}
