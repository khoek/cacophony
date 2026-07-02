use dave::{Av1, Codec, FrameCodec, H264, H265, MediaType, Opus, Vp8, Vp9};

use crate::{
    errors::{RtpError, UnsupportedCodecError},
    rtp::RtpPayloadType,
    rtp_payload::{ParsedRtpPayload, RtpPayloadPacketizerState},
    state::{ConnectionCodecPreferences, SessionDescription},
};

pub const VIDEO_CLOCK_RATE_HZ: u32 = 90_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscordCodecDescriptor {
    pub(crate) codec: Codec,
    pub(crate) wire_name: &'static str,
    pub(crate) payload_type: RtpPayloadType,
    pub(crate) rtx_payload_type: Option<RtpPayloadType>,
    pub(crate) clock_rate_hz: u32,
}

impl DiscordCodecDescriptor {
    pub(crate) fn media_type(self) -> MediaType {
        self.codec.media_type()
    }
}

pub(crate) trait DiscordCodec: FrameCodec {
    const DESCRIPTOR: DiscordCodecDescriptor;

    fn packetizer_state(frame: &[u8]) -> Result<RtpPayloadPacketizerState<'_>, RtpError>;

    fn parse_payload<'a>(
        payload: &'a [u8],
        marker: bool,
        has_partial_frame: bool,
    ) -> Result<ParsedRtpPayload<'a>, RtpError>;
}

pub(crate) trait DiscordCodecVisitor {
    type Output;

    fn visit<C>(&mut self) -> Self::Output
    where
        C: DiscordCodec;
}

pub(crate) trait DiscordCodecExt {
    fn visit_discord<V>(self, visitor: &mut V) -> V::Output
    where
        V: DiscordCodecVisitor;
}

impl DiscordCodecExt for Codec {
    fn visit_discord<V>(self, visitor: &mut V) -> V::Output
    where
        V: DiscordCodecVisitor,
    {
        match self {
            Self::Opus => visitor.visit::<Opus>(),
            Self::Vp8 => visitor.visit::<Vp8>(),
            Self::Vp9 => visitor.visit::<Vp9>(),
            Self::H264 => visitor.visit::<H264>(),
            Self::H265 => visitor.visit::<H265>(),
            Self::Av1 => visitor.visit::<Av1>(),
        }
    }
}

const DISCORD_CODECS: [DiscordCodecDescriptor; Codec::ALL.len()] = [
    <Opus as DiscordCodec>::DESCRIPTOR,
    <Av1 as DiscordCodec>::DESCRIPTOR,
    <H265 as DiscordCodec>::DESCRIPTOR,
    <H264 as DiscordCodec>::DESCRIPTOR,
    <Vp8 as DiscordCodec>::DESCRIPTOR,
    <Vp9 as DiscordCodec>::DESCRIPTOR,
];

pub(crate) fn video_codecs() -> impl Iterator<Item = Codec> {
    DISCORD_CODECS
        .iter()
        .filter(|descriptor| descriptor.media_type() == MediaType::Video)
        .map(|descriptor| descriptor.codec)
}

pub(crate) fn descriptor(codec: Codec) -> DiscordCodecDescriptor {
    codec.visit_discord(&mut DescriptorVisitor)
}

pub(crate) fn payload_type(codec: Codec) -> RtpPayloadType {
    descriptor(codec).payload_type
}

struct DescriptorVisitor;

impl DiscordCodecVisitor for DescriptorVisitor {
    type Output = DiscordCodecDescriptor;

    fn visit<C>(&mut self) -> Self::Output
    where
        C: DiscordCodec,
    {
        C::DESCRIPTOR
    }
}

pub(crate) fn codec_for_payload_type(payload_type: RtpPayloadType) -> Option<Codec> {
    DISCORD_CODECS
        .iter()
        .find(|descriptor| descriptor.payload_type == payload_type)
        .map(|descriptor| descriptor.codec)
}

pub(crate) fn audio_codec(name: &str) -> Option<Codec> {
    DISCORD_CODECS
        .iter()
        .find(|descriptor| {
            descriptor.media_type() == MediaType::Audio
                && name.eq_ignore_ascii_case(descriptor.wire_name)
        })
        .map(|descriptor| descriptor.codec)
}

pub(crate) fn video_codec(name: &str) -> Option<Codec> {
    DISCORD_CODECS
        .iter()
        .find(|descriptor| {
            descriptor.media_type() == MediaType::Video
                && name.eq_ignore_ascii_case(descriptor.wire_name)
        })
        .map(|descriptor| descriptor.codec)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DiscordRtpCodecMap {
    payload_codecs: [Option<Codec>; 128],
    expected_payload_types: Vec<RtpPayloadType>,
}

impl DiscordRtpCodecMap {
    pub(crate) fn new(
        session_description: &SessionDescription,
        codec_preferences: &ConnectionCodecPreferences,
    ) -> Result<Self, UnsupportedCodecError> {
        let audio_codec =
            session_description
                .audio_codec
                .as_deref()
                .map_or(Ok(Codec::Opus), |codec| {
                    audio_codec(codec).ok_or_else(|| UnsupportedCodecError::UnsupportedAudioCodec {
                        codec: codec.to_string(),
                    })
                })?;

        if let Some(codec) = session_description.video_codec.as_deref() {
            video_codec(codec).ok_or_else(|| UnsupportedCodecError::UnsupportedVideoCodec {
                codec: codec.to_string(),
            })?;
        }

        let mut payload_codecs = [None; 128];
        let mut expected_payload_types =
            Vec::with_capacity(1 + codec_preferences.video_codecs().len());
        Self::insert_codec(
            &mut payload_codecs,
            &mut expected_payload_types,
            audio_codec,
        );
        for codec in codec_preferences.video_codecs().iter().copied() {
            Self::insert_codec(&mut payload_codecs, &mut expected_payload_types, codec);
        }
        Ok(Self {
            payload_codecs,
            expected_payload_types,
        })
    }

    pub(crate) fn detect(
        &self,
        payload_type: RtpPayloadType,
    ) -> Result<Codec, UnsupportedCodecError> {
        if let Some(codec) = self
            .payload_codecs
            .get(payload_type.index())
            .and_then(|codec| *codec)
        {
            return Ok(codec);
        }

        if let Some(codec) = codec_for_payload_type(payload_type) {
            return Err(UnsupportedCodecError::UnexpectedRtpPayloadCodec {
                payload_type,
                codec,
                expected_payload_types: self.expected_payload_types.clone(),
            });
        }

        Err(UnsupportedCodecError::UnsupportedRtpPayloadType {
            payload_type,
            expected_payload_types: self.expected_payload_types.clone(),
        })
    }

    fn insert_codec(
        payload_codecs: &mut [Option<Codec>; 128],
        expected_payload_types: &mut Vec<RtpPayloadType>,
        codec: Codec,
    ) {
        let rtp_payload_type = payload_type(codec);
        payload_codecs[rtp_payload_type.index()] = Some(codec);
        expected_payload_types.push(rtp_payload_type);
    }
}
