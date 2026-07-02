use std::time::Duration;

use tokio::{sync::watch, time::Instant};

use crate::{
    buffer::ReusableBuffer,
    codecs,
    errors::{Error, ProtocolError, Result},
    media::{OutboundCodecBinding, OutboundPacket, OutboundRtpState},
    observer::UdpPacketSentEvent,
    rtp_payload::RtpPayloadPacketizer,
    state::ConnectionInternalState,
};

use super::{driver::ConnectionDriver, playout::ActiveOpusPlayout, wait_for_close};

pub(super) struct SendPipeline {
    pub(super) outbound_audio_rtp: OutboundRtpState,
    pub(super) outbound_video_rtp: Option<OutboundRtpState>,
    pub(super) dave_payload_buffer: ReusableBuffer,
    pub(super) rtp_payload_buffer: ReusableBuffer,
    pub(super) packet_buffer: ReusableBuffer,
    pub(super) active_playout: Option<ActiveOpusPlayout>,
    pub(super) next_playout_id: u64,
}

impl SendPipeline {
    pub(super) fn new(state: &ConnectionInternalState) -> Result<Self> {
        Ok(Self {
            outbound_audio_rtp: OutboundRtpState::new(OutboundCodecBinding::new(
                dave::Codec::Opus,
                state.ready.ssrc,
            ))?,
            outbound_video_rtp: negotiated_video_rtp(state)?,
            dave_payload_buffer: ReusableBuffer::new(),
            rtp_payload_buffer: ReusableBuffer::new(),
            packet_buffer: ReusableBuffer::new(),
            active_playout: None,
            next_playout_id: 1,
        })
    }

    pub(super) fn update_negotiated_media(
        &mut self,
        state: &ConnectionInternalState,
    ) -> Result<()> {
        match negotiated_video_media(state) {
            Some(video) => match &mut self.outbound_video_rtp {
                Some(rtp) if rtp.ssrc() == video.ssrc => {
                    rtp.update_binding(video.binding());
                }
                slot => {
                    *slot = Some(OutboundRtpState::new(video.binding())?);
                }
            },
            None => self.outbound_video_rtp = None,
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NegotiatedVideoMedia {
    codec: dave::Codec,
    ssrc: u32,
}

fn negotiated_video_rtp(state: &ConnectionInternalState) -> Result<Option<OutboundRtpState>> {
    negotiated_video_media(state)
        .map(|video| OutboundRtpState::new(video.binding()))
        .transpose()
}

fn negotiated_video_media(state: &ConnectionInternalState) -> Option<NegotiatedVideoMedia> {
    state
        .session_description
        .as_ref()
        .and_then(|description| description.video_codec.as_deref())
        .and_then(codecs::video_codec)
        .zip(state.ready.primary_video_stream())
        .map(|(codec, stream)| NegotiatedVideoMedia {
            codec,
            ssrc: stream.ssrc,
        })
}

impl NegotiatedVideoMedia {
    fn binding(self) -> OutboundCodecBinding {
        OutboundCodecBinding::new(self.codec, self.ssrc)
    }
}

impl<O, Raw> ConnectionDriver<O, Raw>
where
    O: crate::observer::ConnectionObserver,
    Raw: crate::media::FrameRaw,
{
    pub(super) async fn send_ready_opus_packet(
        &mut self,
        frame: &[u8],
        duration: Duration,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Result<OutboundPacket> {
        self.send_ready_media_frame(::dave::Codec::Opus, frame, duration, close_rx)
            .await
    }

    pub(super) async fn send_ready_media_frame(
        &mut self,
        codec: ::dave::Codec,
        frame: &[u8],
        duration: Duration,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Result<OutboundPacket> {
        let requires_dave = self.dave_send_requires_dave();
        let connection = self.state.internal().config.public_info();
        self.send.dave_payload_buffer.clear();
        let media_payload = if requires_dave {
            self.dave.encrypt_dynamic_media_frame_into(
                codec,
                frame,
                self.send.dave_payload_buffer.as_vec_mut(),
            )?;
            self.send.dave_payload_buffer.as_slice()
        } else {
            frame
        };
        let mut packetizer = RtpPayloadPacketizer::new(codec, media_payload)?;
        let rtp = match codec.media_type() {
            ::dave::MediaType::Audio => &mut self.send.outbound_audio_rtp,
            ::dave::MediaType::Video => self
                .send
                .outbound_video_rtp
                .as_mut()
                .ok_or(Error::Protocol(ProtocolError::MissingVideoSsrc { codec }))?,
        };
        if rtp.codec() != codec {
            return Err(Error::Protocol(ProtocolError::MediaCodecNotNegotiated {
                codec,
                negotiated_codec: Some(rtp.codec()),
            }));
        }
        let mut last_packet = None;
        while let Some(marker) = packetizer.next(self.send.rtp_payload_buffer.as_vec_mut())? {
            let build_started = O::ENABLE_TIMING.then(Instant::now);
            let payload = self.send.rtp_payload_buffer.as_slice();
            let packet = match rtp.build_packet(
                payload,
                marker,
                duration,
                &self.transport_crypto,
                self.send.packet_buffer.as_vec_mut(),
            ) {
                Ok(packet) => packet,
                Err(error) => return Err(error),
            };
            let build_elapsed = build_started.map(|started| started.elapsed());
            let send_started = O::ENABLE_TIMING.then(Instant::now);
            tokio::select! {
                sent = self.udp_socket.send(self.send.packet_buffer.as_slice()) => {
                    if let Err(error) = sent {
                        return Err(error.into());
                    }
                }
                () = wait_for_close(close_rx) => {
                    return Err(Error::Closed);
                },
            }
            if let (Some(build_elapsed), Some(send_started)) = (build_elapsed, send_started) {
                self.observer.udp_packet_sent(UdpPacketSentEvent {
                    endpoint: &connection.endpoint,
                    guild_id: connection.guild_id,
                    user_id: connection.user_id,
                    dave: requires_dave,
                    payload_bytes: payload.len(),
                    packet_bytes: self.send.packet_buffer.len(),
                    build_elapsed,
                    send_elapsed: send_started.elapsed(),
                });
            }
            last_packet = Some(packet);
        }
        last_packet.ok_or_else(|| {
            Error::InvalidInput(crate::errors::InvalidInputError::EmptyPayload { codec })
        })
    }
}
