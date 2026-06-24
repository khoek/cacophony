use std::time::Duration;

use tokio::{sync::watch, time::Instant};

use crate::{
    buffer::ReusableBuffer,
    errors::{Error, Result},
    media::{OutboundPacket, OutboundRtpState},
    observer::UdpPacketSentEvent,
    opus::PayloadCodec,
};

use super::{driver::ConnectionDriver, playout::ActiveOpusPlayout, wait_for_close};

pub(super) struct SendPipeline {
    pub(super) outbound_rtp: OutboundRtpState<PayloadCodec>,
    pub(super) dave_payload_buffer: ReusableBuffer,
    pub(super) packet_buffer: ReusableBuffer,
    pub(super) active_playout: Option<ActiveOpusPlayout>,
    pub(super) next_playout_id: u64,
}

impl SendPipeline {
    pub(super) fn new(ssrc: u32) -> Self {
        Self {
            outbound_rtp: OutboundRtpState::new(ssrc),
            dave_payload_buffer: ReusableBuffer::new(),
            packet_buffer: ReusableBuffer::new(),
            active_playout: None,
            next_playout_id: 1,
        }
    }
}

impl<O, Raw> ConnectionDriver<O, Raw>
where
    O: crate::observer::ConnectionObserver,
    Raw: crate::media::FrameRaw,
{
    pub(super) async fn send_ready_opus_frame(
        &mut self,
        frame: Vec<u8>,
        duration: Duration,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Result<OutboundPacket> {
        let requires_dave = self.dave_send_active();
        let connection = self.state.internal().config.public_info();
        self.send.dave_payload_buffer.clear();
        let opus_payload = if requires_dave {
            match self.dave.encrypt_media_frame_into::<PayloadCodec>(
                &frame,
                self.send.dave_payload_buffer.as_vec_mut(),
            )? {
                ::dave::FrameEncryptResult::Unchanged => frame.as_slice(),
                ::dave::FrameEncryptResult::Encrypted => self.send.dave_payload_buffer.as_slice(),
            }
        } else {
            frame.as_slice()
        };
        let payload_bytes = opus_payload.len();
        let build_started = O::ENABLE_TIMING.then(Instant::now);
        let packet = self.send.outbound_rtp.build_packet(
            opus_payload,
            duration,
            &self.transport_crypto,
            self.send.packet_buffer.as_vec_mut(),
        )?;
        let build_elapsed = build_started.map(|started| started.elapsed());
        let send_started = O::ENABLE_TIMING.then(Instant::now);
        tokio::select! {
            sent = self.udp_socket.send(self.send.packet_buffer.as_slice()) => {
                sent?;
            }
            () = wait_for_close(close_rx) => return Err(Error::Closed),
        }
        if let (Some(build_elapsed), Some(send_started)) = (build_elapsed, send_started) {
            self.observer.udp_packet_sent(UdpPacketSentEvent {
                endpoint: &connection.endpoint,
                guild_id: connection.server_id,
                user_id: connection.user_id,
                dave: requires_dave,
                payload_bytes,
                packet_bytes: self.send.packet_buffer.len(),
                build_elapsed,
                send_elapsed: send_started.elapsed(),
            });
        }
        Ok(packet)
    }
}
