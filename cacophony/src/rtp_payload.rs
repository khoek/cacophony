use std::marker::PhantomData;

use dave::{
    Av1, Codec, FrameCodec, H26xFrameCodec, H264, H265, Opus, Vp8, Vp9, codec as dave_codec,
    leb128::DecodedUleb128,
};

use crate::{
    codecs::{
        DiscordCodec, DiscordCodecDescriptor, DiscordCodecExt, DiscordCodecVisitor,
        VIDEO_CLOCK_RATE_HZ,
    },
    errors::RtpError,
    opus,
    rtp::RtpPayloadType,
};

pub(crate) const RTP_MEDIA_PAYLOAD_MAX_BYTES: usize = 1_200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RtpPayloadPacketizer<'a> {
    codec: Codec,
    state: RtpPayloadPacketizerState<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RtpPayloadPacketizerState<'a> {
    Single {
        frame: &'a [u8],
        marker: bool,
        emitted: bool,
    },
    Fragmented {
        frame: &'a [u8],
        offset: usize,
        header: FragmentedPayloadHeader,
    },
    H264(H26xPacketizer<'a, H264>),
    H265(H26xPacketizer<'a, H265>),
    Av1 {
        frame: &'a [u8],
        obu_start: usize,
        obu_end: usize,
        fragment_offset: usize,
    },
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FragmentedPayloadHeader {
    Vp8,
    Vp9,
}

impl FragmentedPayloadHeader {
    const fn len(self) -> usize {
        match self {
            Self::Vp8 | Self::Vp9 => 1,
        }
    }

    fn write(self, first: bool, last: bool, payload: &mut Vec<u8>) {
        match self {
            Self::Vp8 => payload.push(if first { 0x10 } else { 0 }),
            Self::Vp9 => {
                payload.push((if first { 0x08 } else { 0 }) | (if last { 0x04 } else { 0 }));
            }
        }
    }
}

pub(crate) trait H26xRtpPayload:
    H26xFrameCodec + Clone + Copy + std::fmt::Debug + PartialEq + Eq
{
    const AGGREGATION_PAYLOAD_OFFSET: usize;
    const FRAGMENT_HEADER_LEN: usize;
    const UNSUPPORTED_RTP_NAL_UNIT_TYPE: &'static str;

    fn fragment_payload(nalu: &[u8]) -> Result<&[u8], RtpError>;
    fn is_aggregation_nalu_type(nalu_type: u8) -> bool;
    fn is_fragment_nalu_type(nalu_type: u8) -> bool;
    fn is_single_nalu_type(nalu_type: u8) -> bool;
    fn parse_fragment_payload(payload: &[u8]) -> Result<H26xFragmentPayload<'_>, RtpError>;
    fn rtp_nalu_type(payload: &[u8]) -> Result<u8, RtpError>;
    fn write_fragment_header(
        nalu: &[u8],
        first: bool,
        last: bool,
        payload: &mut Vec<u8>,
    ) -> Result<(), RtpError>;
}

impl H26xRtpPayload for H264 {
    const AGGREGATION_PAYLOAD_OFFSET: usize = 1;
    const FRAGMENT_HEADER_LEN: usize = 2;
    const UNSUPPORTED_RTP_NAL_UNIT_TYPE: &'static str = "unsupported H264 RTP NAL unit type";

    fn fragment_payload(nalu: &[u8]) -> Result<&[u8], RtpError> {
        nalu.get(Self::NAL_HEADER_BYTES..)
            .ok_or_else(|| malformed(Self::CODEC, "empty H264 NAL unit"))
    }

    fn is_aggregation_nalu_type(nalu_type: u8) -> bool {
        nalu_type == 24
    }

    fn is_fragment_nalu_type(nalu_type: u8) -> bool {
        nalu_type == 28
    }

    fn is_single_nalu_type(nalu_type: u8) -> bool {
        (1..=23).contains(&nalu_type)
    }

    fn parse_fragment_payload(payload: &[u8]) -> Result<H26xFragmentPayload<'_>, RtpError> {
        if payload.len() < 3 {
            return Err(malformed(Self::CODEC, "truncated H264 FU-A payload"));
        }
        let fu_indicator = payload[0];
        let fu_header = payload[1];
        Ok(H26xFragmentPayload {
            starts_fragment: fu_header & 0x80 != 0,
            completes_fragment: fu_header & 0x40 != 0,
            nalu_header: [(fu_indicator & 0xe0) | (fu_header & 0x1f), 0],
            nalu_header_len: 1,
            fragment_payload: &payload[2..],
        })
    }

    fn rtp_nalu_type(payload: &[u8]) -> Result<u8, RtpError> {
        payload
            .first()
            .map(|header| Self::nal_type(*header))
            .ok_or_else(|| malformed(Self::CODEC, "empty H264 payload"))
    }

    fn write_fragment_header(
        nalu: &[u8],
        first: bool,
        last: bool,
        payload: &mut Vec<u8>,
    ) -> Result<(), RtpError> {
        let Some(&nalu_header) = nalu.first() else {
            return Err(malformed(Self::CODEC, "empty H264 NAL unit"));
        };
        payload.push((nalu_header & 0xe0) | 28);
        payload.push(
            (if first { 0x80 } else { 0 }) | (if last { 0x40 } else { 0 }) | (nalu_header & 0x1f),
        );
        Ok(())
    }
}

impl H26xRtpPayload for H265 {
    const AGGREGATION_PAYLOAD_OFFSET: usize = 2;
    const FRAGMENT_HEADER_LEN: usize = 3;
    const UNSUPPORTED_RTP_NAL_UNIT_TYPE: &'static str = "unsupported H265 RTP NAL unit type";

    fn fragment_payload(nalu: &[u8]) -> Result<&[u8], RtpError> {
        if nalu.len() < Self::NAL_HEADER_BYTES {
            return Err(malformed(Self::CODEC, "truncated H265 NAL header"));
        }
        Ok(&nalu[Self::NAL_HEADER_BYTES..])
    }

    fn is_aggregation_nalu_type(nalu_type: u8) -> bool {
        nalu_type == 48
    }

    fn is_fragment_nalu_type(nalu_type: u8) -> bool {
        nalu_type == 49
    }

    fn is_single_nalu_type(nalu_type: u8) -> bool {
        nalu_type <= 47
    }

    fn parse_fragment_payload(payload: &[u8]) -> Result<H26xFragmentPayload<'_>, RtpError> {
        if payload.len() < 4 {
            return Err(malformed(Self::CODEC, "truncated H265 FU payload"));
        }
        let fu_indicator = [payload[0], payload[1]];
        let fu_header = payload[2];
        Ok(H26xFragmentPayload {
            starts_fragment: fu_header & 0x80 != 0,
            completes_fragment: fu_header & 0x40 != 0,
            nalu_header: [
                (fu_indicator[0] & 0x81) | ((fu_header & 0x3f) << 1),
                fu_indicator[1],
            ],
            nalu_header_len: 2,
            fragment_payload: &payload[3..],
        })
    }

    fn rtp_nalu_type(payload: &[u8]) -> Result<u8, RtpError> {
        if payload.len() < Self::NAL_HEADER_BYTES {
            return Err(malformed(Self::CODEC, "truncated H265 payload header"));
        }
        Ok(Self::nal_type(payload[0]))
    }

    fn write_fragment_header(
        nalu: &[u8],
        first: bool,
        last: bool,
        payload: &mut Vec<u8>,
    ) -> Result<(), RtpError> {
        if nalu.len() < Self::NAL_HEADER_BYTES {
            return Err(malformed(Self::CODEC, "truncated H265 NAL header"));
        }
        payload.extend_from_slice(&[(nalu[0] & 0x81) | (49 << 1), nalu[1]]);
        payload.push(
            (if first { 0x80 } else { 0 })
                | (if last { 0x40 } else { 0 })
                | ((nalu[0] & 0x7e) >> 1),
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct H26xPacketizer<'a, C>
where
    C: H26xRtpPayload,
{
    nalus: dave_codec::AnnexBNalus<'a>,
    nalu: Option<&'a [u8]>,
    fragment_offset: usize,
    codec: PhantomData<C>,
}

impl<'a, C> H26xPacketizer<'a, C>
where
    C: H26xRtpPayload,
{
    fn new(frame: &'a [u8]) -> Result<Self, RtpError> {
        let mut nalus = dave_codec::AnnexBFrame::new(frame).nalus();
        let Some(nalu) = nalus.next() else {
            return Err(malformed(C::CODEC, "missing Annex B start code"));
        };
        Ok(Self {
            nalus,
            nalu: Some(nalu),
            fragment_offset: 0,
            codec: PhantomData,
        })
    }

    fn next_payload(&mut self, payload: &mut Vec<u8>) -> Result<Option<bool>, RtpError> {
        let Some(nalu) = self.nalu else {
            return Ok(None);
        };
        let last_nalu = self.nalus.is_empty();
        if nalu.len() <= RTP_MEDIA_PAYLOAD_MAX_BYTES {
            payload.extend_from_slice(nalu);
            self.nalu = self.nalus.next();
            return Ok(Some(last_nalu));
        }
        if RTP_MEDIA_PAYLOAD_MAX_BYTES <= C::FRAGMENT_HEADER_LEN {
            return Err(RtpError::PayloadTooLarge {
                codec: C::CODEC,
                payload_len: nalu.len(),
                max_payload_len: RTP_MEDIA_PAYLOAD_MAX_BYTES,
            });
        }
        let nalu_payload = C::fragment_payload(nalu)?;
        let end = self
            .fragment_offset
            .saturating_add(RTP_MEDIA_PAYLOAD_MAX_BYTES - C::FRAGMENT_HEADER_LEN)
            .min(nalu_payload.len());
        let first = self.fragment_offset == 0;
        let last = end == nalu_payload.len();
        payload.reserve(C::FRAGMENT_HEADER_LEN + end - self.fragment_offset);
        C::write_fragment_header(nalu, first, last, payload)?;
        payload.extend_from_slice(&nalu_payload[self.fragment_offset..end]);
        if last {
            self.nalu = self.nalus.next();
            self.fragment_offset = 0;
        } else {
            self.fragment_offset = end;
        }
        Ok(Some(last_nalu && last))
    }
}

impl DiscordCodec for Opus {
    const DESCRIPTOR: DiscordCodecDescriptor = DiscordCodecDescriptor {
        codec: Codec::Opus,
        wire_name: "opus",
        payload_type: RtpPayloadType::new_const(opus::discord::RTP_PAYLOAD_TYPE),
        rtx_payload_type: None,
        clock_rate_hz: opus::discord::SAMPLE_RATE_HZ,
    };

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError> {
        Ok(RtpPayloadPacketizerState::Single {
            frame,
            marker: false,
            emitted: false,
        })
    }

    fn parse_payload<'a>(
        payload: &'a [u8],
        _marker: bool,
        _has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError> {
        Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame: true,
                completes_frame: true,
            },
            depacketized: DepacketizedPayload::Raw(payload),
        })
    }
}

impl DiscordCodec for Vp8 {
    const DESCRIPTOR: DiscordCodecDescriptor = DiscordCodecDescriptor {
        codec: Codec::Vp8,
        wire_name: "VP8",
        payload_type: RtpPayloadType::new_const(107),
        rtx_payload_type: Some(RtpPayloadType::new_const(108)),
        clock_rate_hz: VIDEO_CLOCK_RATE_HZ,
    };

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError> {
        Ok(RtpPayloadPacketizerState::Fragmented {
            frame,
            offset: 0,
            header: FragmentedPayloadHeader::Vp8,
        })
    }

    fn parse_payload<'a>(
        payload: &'a [u8],
        marker: bool,
        _has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError> {
        let (descriptor_len, starts_frame) = vp8_descriptor(payload)?;
        Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame,
                completes_frame: marker && payload.len() > descriptor_len,
            },
            depacketized: DepacketizedPayload::Raw(&payload[descriptor_len..]),
        })
    }
}

impl DiscordCodec for Vp9 {
    const DESCRIPTOR: DiscordCodecDescriptor = DiscordCodecDescriptor {
        codec: Codec::Vp9,
        wire_name: "VP9",
        payload_type: RtpPayloadType::new_const(109),
        rtx_payload_type: Some(RtpPayloadType::new_const(110)),
        clock_rate_hz: VIDEO_CLOCK_RATE_HZ,
    };

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError> {
        Ok(RtpPayloadPacketizerState::Fragmented {
            frame,
            offset: 0,
            header: FragmentedPayloadHeader::Vp9,
        })
    }

    fn parse_payload<'a>(
        payload: &'a [u8],
        marker: bool,
        _has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError> {
        let descriptor = vp9_descriptor(payload)?;
        Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame: descriptor.starts_frame,
                completes_frame: marker || descriptor.completes_frame,
            },
            depacketized: DepacketizedPayload::Raw(&payload[descriptor.len..]),
        })
    }
}

impl DiscordCodec for H264 {
    const DESCRIPTOR: DiscordCodecDescriptor = DiscordCodecDescriptor {
        codec: Codec::H264,
        wire_name: "H264",
        payload_type: RtpPayloadType::new_const(103),
        rtx_payload_type: Some(RtpPayloadType::new_const(104)),
        clock_rate_hz: VIDEO_CLOCK_RATE_HZ,
    };

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError> {
        Ok(RtpPayloadPacketizerState::H264(H26xPacketizer::new(frame)?))
    }

    fn parse_payload<'a>(
        payload: &'a [u8],
        marker: bool,
        has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError> {
        parse_h26x_payload::<H264>(payload, marker, has_partial_frame)
    }
}

impl DiscordCodec for H265 {
    const DESCRIPTOR: DiscordCodecDescriptor = DiscordCodecDescriptor {
        codec: Codec::H265,
        wire_name: "H265",
        payload_type: RtpPayloadType::new_const(105),
        rtx_payload_type: Some(RtpPayloadType::new_const(106)),
        clock_rate_hz: VIDEO_CLOCK_RATE_HZ,
    };

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError> {
        Ok(RtpPayloadPacketizerState::H265(H26xPacketizer::new(frame)?))
    }

    fn parse_payload<'a>(
        payload: &'a [u8],
        marker: bool,
        has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError> {
        parse_h26x_payload::<H265>(payload, marker, has_partial_frame)
    }
}

impl DiscordCodec for Av1 {
    const DESCRIPTOR: DiscordCodecDescriptor = DiscordCodecDescriptor {
        codec: Codec::Av1,
        wire_name: "AV1",
        payload_type: RtpPayloadType::new_const(101),
        rtx_payload_type: Some(RtpPayloadType::new_const(102)),
        clock_rate_hz: VIDEO_CLOCK_RATE_HZ,
    };

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError> {
        Ok(RtpPayloadPacketizerState::Av1 {
            frame,
            obu_start: 0,
            obu_end: 0,
            fragment_offset: 0,
        })
    }

    fn parse_payload<'a>(
        payload: &'a [u8],
        marker: bool,
        has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError> {
        let Some((&aggregation_header, payload)) = payload.split_first() else {
            return Err(malformed(Self::CODEC, "empty AV1 payload"));
        };
        Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame: !has_partial_frame && aggregation_header & 0x80 == 0,
                completes_frame: marker,
            },
            depacketized: DepacketizedPayload::Av1 {
                w: (aggregation_header >> 4) & 0x03,
                payload,
            },
        })
    }
}

impl<'a> RtpPayloadPacketizer<'a> {
    pub(crate) fn new(codec: Codec, frame: &'a [u8]) -> Result<Self, RtpError> {
        if frame.is_empty() {
            return Err(malformed(codec, "empty encoded frame"));
        }
        let state = codec.visit_discord(&mut PacketizerStateVisitor { frame })?;
        Ok(Self { codec, state })
    }

    pub(crate) fn next(&mut self, payload: &mut Vec<u8>) -> Result<Option<bool>, RtpError> {
        payload.clear();
        match &mut self.state {
            RtpPayloadPacketizerState::Single {
                frame,
                marker,
                emitted,
            } => {
                if *emitted {
                    self.state = RtpPayloadPacketizerState::Done;
                    return Ok(None);
                }
                if frame.len() > RTP_MEDIA_PAYLOAD_MAX_BYTES {
                    return Err(RtpError::PayloadTooLarge {
                        codec: self.codec,
                        payload_len: frame.len(),
                        max_payload_len: RTP_MEDIA_PAYLOAD_MAX_BYTES,
                    });
                }
                payload.extend_from_slice(frame);
                *emitted = true;
                Ok(Some(*marker))
            }
            RtpPayloadPacketizerState::Fragmented {
                frame,
                offset,
                header,
            } => next_fragmented_payload(self.codec, frame, offset, *header, payload),
            RtpPayloadPacketizerState::H264(packetizer) => packetizer.next_payload(payload),
            RtpPayloadPacketizerState::H265(packetizer) => packetizer.next_payload(payload),
            RtpPayloadPacketizerState::Av1 {
                frame,
                obu_start,
                obu_end,
                fragment_offset,
            } => next_av1_payload(
                self.codec,
                frame,
                obu_start,
                obu_end,
                fragment_offset,
                payload,
            ),
            RtpPayloadPacketizerState::Done => Ok(None),
        }
        .inspect(|marker| {
            if marker.is_none() {
                self.state = RtpPayloadPacketizerState::Done;
            }
        })
    }
}

struct PacketizerStateVisitor<'a> {
    frame: &'a [u8],
}

impl<'a> DiscordCodecVisitor for PacketizerStateVisitor<'a> {
    type Output = Result<RtpPayloadPacketizerState<'a>, RtpError>;

    fn visit<C>(&mut self) -> Self::Output
    where
        C: DiscordCodec,
    {
        C::packetizer_state(self.frame)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RtpPayloadBoundary {
    pub(crate) starts_frame: bool,
    pub(crate) completes_frame: bool,
}

fn next_fragmented_payload(
    codec: Codec,
    frame: &[u8],
    offset: &mut usize,
    header: FragmentedPayloadHeader,
    payload: &mut Vec<u8>,
) -> Result<Option<bool>, RtpError> {
    if *offset >= frame.len() {
        return Ok(None);
    }
    let header_len = header.len();
    if RTP_MEDIA_PAYLOAD_MAX_BYTES <= header_len {
        return Err(RtpError::PayloadTooLarge {
            codec,
            payload_len: frame.len(),
            max_payload_len: RTP_MEDIA_PAYLOAD_MAX_BYTES,
        });
    }
    let chunk_len = RTP_MEDIA_PAYLOAD_MAX_BYTES - header_len;
    let end = (*offset + chunk_len).min(frame.len());
    let first = *offset == 0;
    let last = end == frame.len();
    payload.reserve(header_len + end - *offset);
    header.write(first, last, payload);
    payload.extend_from_slice(&frame[*offset..end]);
    *offset = end;
    Ok(Some(last))
}

fn next_av1_payload(
    codec: Codec,
    frame: &[u8],
    obu_start: &mut usize,
    obu_end: &mut usize,
    fragment_offset: &mut usize,
    payload: &mut Vec<u8>,
) -> Result<Option<bool>, RtpError> {
    if *obu_start >= frame.len() {
        return Ok(None);
    }
    if RTP_MEDIA_PAYLOAD_MAX_BYTES <= 1 {
        return Err(RtpError::PayloadTooLarge {
            codec,
            payload_len: frame.len(),
            max_payload_len: RTP_MEDIA_PAYLOAD_MAX_BYTES,
        });
    }
    if *fragment_offset == 0 {
        *obu_end = av1_obu_end(codec, frame, *obu_start)?;
    }
    let chunk_len = RTP_MEDIA_PAYLOAD_MAX_BYTES - 1;
    let offset = *obu_start + *fragment_offset;
    let end = (offset + chunk_len).min(*obu_end);
    let first = *fragment_offset == 0;
    let last_fragment = end == *obu_end;
    let last_obu = *obu_end == frame.len();
    payload.reserve(1 + end - offset);
    payload.push((if !first { 0x80 } else { 0 }) | (if !last_fragment { 0x40 } else { 0 }) | 0x10);
    payload.extend_from_slice(&frame[offset..end]);
    if last_fragment {
        *obu_start = *obu_end;
        *fragment_offset = 0;
    } else {
        *fragment_offset += end - offset;
    }
    Ok(Some(last_obu && last_fragment))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedRtpPayload<'a> {
    boundary: RtpPayloadBoundary,
    depacketized: DepacketizedPayload<'a>,
}

impl<'a> ParsedRtpPayload<'a> {
    pub(crate) fn parse(
        codec: Codec,
        payload: &'a [u8],
        marker: bool,
        has_partial_frame: bool,
    ) -> Result<Self, RtpError> {
        codec.visit_discord(&mut ParsePayloadVisitor {
            payload,
            marker,
            has_partial_frame,
        })
    }

    pub(crate) const fn boundary(&self) -> RtpPayloadBoundary {
        self.boundary
    }

    pub(crate) fn append_depacketized(&self, frame: &mut Vec<u8>) -> Result<(), RtpError> {
        match self.depacketized {
            DepacketizedPayload::Raw(payload) => {
                frame.extend_from_slice(payload);
                Ok(())
            }
            DepacketizedPayload::H26xNalu(nalu) => {
                append_annex_b_nalu(nalu, frame);
                Ok(())
            }
            DepacketizedPayload::H26xAggregation { codec, payload } => {
                append_h26x_aggregation(codec, payload, frame)
            }
            DepacketizedPayload::H26xFragment(fragment) => {
                if fragment.starts_fragment {
                    frame.extend_from_slice(&dave_codec::H26X_LONG_START_CODE);
                    frame.extend_from_slice(&fragment.nalu_header[..fragment.nalu_header_len]);
                }
                frame.extend_from_slice(fragment.fragment_payload);
                Ok(())
            }
            DepacketizedPayload::Av1 { w, payload } => append_av1_payload(w, payload, frame),
        }
    }
}

struct ParsePayloadVisitor<'a> {
    payload: &'a [u8],
    marker: bool,
    has_partial_frame: bool,
}

impl<'a> DiscordCodecVisitor for ParsePayloadVisitor<'a> {
    type Output = Result<ParsedRtpPayload<'a>, RtpError>;

    fn visit<C>(&mut self) -> Self::Output
    where
        C: DiscordCodec,
    {
        C::parse_payload(self.payload, self.marker, self.has_partial_frame)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DepacketizedPayload<'a> {
    Raw(&'a [u8]),
    H26xNalu(&'a [u8]),
    H26xAggregation { codec: Codec, payload: &'a [u8] },
    H26xFragment(H26xFragmentPayload<'a>),
    Av1 { w: u8, payload: &'a [u8] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H26xFragmentPayload<'a> {
    starts_fragment: bool,
    completes_fragment: bool,
    nalu_header: [u8; 2],
    nalu_header_len: usize,
    fragment_payload: &'a [u8],
}

fn parse_h26x_payload<'a, C>(
    payload: &'a [u8],
    marker: bool,
    has_partial_frame: bool,
) -> Result<ParsedRtpPayload<'a>, RtpError>
where
    C: H26xRtpPayload,
{
    let nalu_type = C::rtp_nalu_type(payload)?;
    if C::is_single_nalu_type(nalu_type) {
        return Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame: !has_partial_frame,
                completes_frame: marker,
            },
            depacketized: DepacketizedPayload::H26xNalu(payload),
        });
    }
    if C::is_aggregation_nalu_type(nalu_type) {
        return Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame: !has_partial_frame,
                completes_frame: marker,
            },
            depacketized: DepacketizedPayload::H26xAggregation {
                codec: C::CODEC,
                payload: &payload[C::AGGREGATION_PAYLOAD_OFFSET..],
            },
        });
    }
    if C::is_fragment_nalu_type(nalu_type) {
        let fragment = C::parse_fragment_payload(payload)?;
        return Ok(ParsedRtpPayload {
            boundary: RtpPayloadBoundary {
                starts_frame: fragment.starts_fragment,
                completes_frame: marker && fragment.completes_fragment,
            },
            depacketized: DepacketizedPayload::H26xFragment(fragment),
        });
    }
    Err(malformed(C::CODEC, C::UNSUPPORTED_RTP_NAL_UNIT_TYPE))
}

fn append_h26x_aggregation(
    codec: Codec,
    mut payload: &[u8],
    frame: &mut Vec<u8>,
) -> Result<(), RtpError> {
    while !payload.is_empty() {
        if payload.len() < 2 {
            return Err(malformed(codec, "truncated H26x aggregation length"));
        }
        let nalu_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
        payload = &payload[2..];
        if payload.len() < nalu_len {
            return Err(malformed(codec, "truncated H26x aggregation NAL unit"));
        }
        append_annex_b_nalu(&payload[..nalu_len], frame);
        payload = &payload[nalu_len..];
    }
    Ok(())
}

fn append_annex_b_nalu(nalu: &[u8], frame: &mut Vec<u8>) {
    frame.extend_from_slice(&dave_codec::H26X_LONG_START_CODE);
    frame.extend_from_slice(nalu);
}

fn append_av1_payload(w: u8, mut payload: &[u8], frame: &mut Vec<u8>) -> Result<(), RtpError> {
    if w == 1 {
        frame.extend_from_slice(payload);
        return Ok(());
    }

    let mut elements = 0_u8;
    while !payload.is_empty() {
        elements = elements.saturating_add(1);
        if w != 0 && elements == w {
            frame.extend_from_slice(payload);
            return Ok(());
        }
        let decoded_len = DecodedUleb128::read(payload)
            .ok_or_else(|| malformed(Codec::Av1, "invalid AV1 OBU length"))?;
        let len = usize::try_from(decoded_len.value())
            .map_err(|_| malformed(Codec::Av1, "oversized AV1 OBU length"))?;
        payload = &payload[decoded_len.encoded_len()..];
        if payload.len() < len {
            return Err(malformed(Codec::Av1, "truncated AV1 OBU element"));
        }
        frame.extend_from_slice(&payload[..len]);
        payload = &payload[len..];
    }
    Ok(())
}

fn av1_obu_end(codec: Codec, frame: &[u8], offset: usize) -> Result<usize, RtpError> {
    let Some(&header) = frame.get(offset) else {
        return Err(malformed(codec, "missing AV1 OBU header"));
    };
    let mut index = offset + 1;
    if header & 0x04 != 0 {
        index = index
            .checked_add(1)
            .ok_or_else(|| malformed(codec, "overflowing AV1 extension offset"))?;
    }
    if index > frame.len() {
        return Err(malformed(codec, "truncated AV1 OBU extension"));
    }
    if header & 0x02 == 0 {
        return Ok(frame.len());
    }
    let decoded_payload_len = DecodedUleb128::read(&frame[index..])
        .ok_or_else(|| malformed(codec, "invalid AV1 OBU size"))?;
    let payload_len = usize::try_from(decoded_payload_len.value())
        .map_err(|_| malformed(codec, "oversized AV1 OBU size"))?;
    index += decoded_payload_len.encoded_len();
    index
        .checked_add(payload_len)
        .filter(|end| *end <= frame.len())
        .ok_or_else(|| malformed(codec, "truncated AV1 OBU payload"))
}

fn vp8_descriptor(payload: &[u8]) -> Result<(usize, bool), RtpError> {
    let Some(&first) = payload.first() else {
        return Err(malformed(Codec::Vp8, "empty VP8 payload"));
    };
    let mut len = 1;
    if first & 0x80 != 0 {
        let Some(&extension) = payload.get(len) else {
            return Err(malformed(Codec::Vp8, "truncated VP8 extension flags"));
        };
        len += 1;
        if extension & 0x80 != 0 {
            let Some(&picture_id) = payload.get(len) else {
                return Err(malformed(Codec::Vp8, "truncated VP8 picture id"));
            };
            len += if picture_id & 0x80 != 0 { 2 } else { 1 };
        }
        if extension & 0x40 != 0 {
            len += 1;
        }
        if extension & 0x30 != 0 {
            len += 1;
        }
    }
    if len > payload.len() {
        return Err(malformed(Codec::Vp8, "truncated VP8 payload descriptor"));
    }
    Ok((len, first & 0x10 != 0 && first & 0x0f == 0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Vp9Descriptor {
    len: usize,
    starts_frame: bool,
    completes_frame: bool,
}

fn vp9_descriptor(payload: &[u8]) -> Result<Vp9Descriptor, RtpError> {
    let Some(&flags) = payload.first() else {
        return Err(malformed(Codec::Vp9, "empty VP9 payload"));
    };
    let mut len = 1;
    if flags & 0x80 != 0 {
        let Some(&picture_id) = payload.get(len) else {
            return Err(malformed(Codec::Vp9, "truncated VP9 picture id"));
        };
        len += if picture_id & 0x80 != 0 { 2 } else { 1 };
    }
    if flags & 0x20 != 0 {
        len += 1;
        if flags & 0x10 == 0 {
            len += 1;
        }
    }
    if flags & 0x10 != 0 && flags & 0x40 != 0 {
        loop {
            let Some(&reference) = payload.get(len) else {
                return Err(malformed(Codec::Vp9, "truncated VP9 reference indices"));
            };
            len += 1;
            if reference & 0x01 == 0 {
                break;
            }
        }
    }
    if flags & 0x02 != 0 {
        len = skip_vp9_scalability_structure(payload, len)?;
    }
    if len > payload.len() {
        return Err(malformed(Codec::Vp9, "truncated VP9 payload descriptor"));
    }
    Ok(Vp9Descriptor {
        len,
        starts_frame: flags & 0x08 != 0,
        completes_frame: flags & 0x04 != 0,
    })
}

fn skip_vp9_scalability_structure(payload: &[u8], mut len: usize) -> Result<usize, RtpError> {
    let Some(&header) = payload.get(len) else {
        return Err(malformed(Codec::Vp9, "truncated VP9 scalability structure"));
    };
    len += 1;
    let spatial_layers = usize::from(header & 0x07) + 1;
    if header & 0x10 != 0 {
        len += spatial_layers * 4;
    }
    if header & 0x08 != 0 {
        let Some(&pictures) = payload.get(len) else {
            return Err(malformed(Codec::Vp9, "truncated VP9 picture group"));
        };
        len += 1;
        for _ in 0..pictures {
            let Some(&picture) = payload.get(len) else {
                return Err(malformed(Codec::Vp9, "truncated VP9 picture group entry"));
            };
            len += 1 + usize::from(picture & 0x03);
        }
    }
    Ok(len)
}

fn malformed(codec: Codec, reason: &'static str) -> RtpError {
    RtpError::MalformedPayload { codec, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp8_packetization_round_trips_large_frame() {
        assert_packetization_round_trip(Codec::Vp8, &vec![0x80; RTP_MEDIA_PAYLOAD_MAX_BYTES * 2]);
    }

    #[test]
    fn vp9_packetization_round_trips_large_frame() {
        assert_packetization_round_trip(Codec::Vp9, &vec![0x80; RTP_MEDIA_PAYLOAD_MAX_BYTES * 2]);
    }

    #[test]
    fn h264_packetization_round_trips_annex_b_frame() {
        let mut frame = dave_codec::H26X_LONG_START_CODE.to_vec();
        frame.push(0x65);
        frame.extend(vec![0xaa; RTP_MEDIA_PAYLOAD_MAX_BYTES * 2]);
        assert_packetization_round_trip(Codec::H264, &frame);
    }

    #[test]
    fn h265_packetization_round_trips_annex_b_frame() {
        let mut frame = dave_codec::H26X_LONG_START_CODE.to_vec();
        frame.extend_from_slice(&[0x26, 0x01]);
        frame.extend(vec![0xaa; RTP_MEDIA_PAYLOAD_MAX_BYTES * 2]);
        assert_packetization_round_trip(Codec::H265, &frame);
    }

    #[test]
    fn av1_packetization_round_trips_obu_frame() {
        let mut frame = vec![0x10];
        frame.extend(vec![0xaa; RTP_MEDIA_PAYLOAD_MAX_BYTES * 2]);
        assert_packetization_round_trip(Codec::Av1, &frame);
    }

    #[test]
    fn av1_packetization_round_trips_multiple_obus_in_one_temporal_unit() {
        let mut frame = vec![0x12, 16];
        frame.extend([0xaa; 16]);
        frame.extend([0x12, 16]);
        frame.extend([0xbb; 16]);
        assert_packetization_round_trip(Codec::Av1, &frame);
    }

    #[test]
    fn av1_payload_lengths_reject_overflowing_leb128() {
        let payload = [
            &[0x00][..],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2][..],
        ]
        .concat();
        assert!(matches!(
            ParsedRtpPayload::parse(Codec::Av1, &payload, true, false)
                .and_then(|payload| payload.append_depacketized(&mut Vec::new())),
            Err(RtpError::MalformedPayload {
                reason: "invalid AV1 OBU length",
                ..
            })
        ));
    }

    fn assert_packetization_round_trip(codec: Codec, frame: &[u8]) {
        let mut packetizer = RtpPayloadPacketizer::new(codec, frame).unwrap();
        let mut payload = Vec::new();
        let mut assembled = Vec::new();
        let mut packets = 0;
        let mut has_partial = false;
        while let Some(marker) = packetizer.next(&mut payload).unwrap() {
            packets += 1;
            let payload = ParsedRtpPayload::parse(codec, &payload, marker, has_partial).unwrap();
            let boundary = payload.boundary();
            if boundary.starts_frame {
                assembled.clear();
            }
            payload.append_depacketized(&mut assembled).unwrap();
            has_partial = !boundary.completes_frame;
        }

        assert!(packets > 1);
        assert_eq!(assembled, frame);
    }
}
