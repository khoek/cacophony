use std::io::Cursor;

use ogg::{PacketWriteEndInfo, PacketWriter, reading::PacketReader};
use opus_rs::{
    Application as RawOpusApplication, OpusDecoder as RawOpusDecoder, OpusEncoder as RawOpusEncoder,
};

use crate::{
    errors::{Error, InvalidInputError, OpusError, OpusOperation, Result},
    media::{DecodedFrame, DecodedFrameMetadata, DecodedPcmLayout, FrameRaw, ReceivedFrame},
    pcm::PcmChunk,
};

const MILLISECONDS_PER_SECOND: usize = 1_000;
const OPUS_ARCHIVE_CHANNELS: usize = 1;
const OPUS_ARCHIVE_FRAME_MS: u32 = 20;
const OPUS_ARCHIVE_GRANULE_SAMPLE_RATE: u64 = 48_000;
const OGG_OPUS_ARCHIVE_SERIAL: u32 = 0xDEADBEEF;
const OGG_OPUS_ARCHIVE_BITRATE_BPS: i32 = 24_000;

pub struct CapturedPcmAudio {
    pcm: PcmChunk,
}

impl CapturedPcmAudio {
    pub fn new(pcm: PcmChunk) -> Result<Self> {
        if pcm.channels().get() != OPUS_ARCHIVE_CHANNELS {
            return Err(Error::Opus(OpusError::UnsupportedChannelCount {
                channels: pcm.channels().get(),
            }));
        }
        Ok(Self { pcm })
    }

    pub fn pcm(&self) -> &PcmChunk {
        &self.pcm
    }

    pub fn encode_ogg_opus_archive(&self, vendor: &str) -> Result<OggOpusAudioArchive> {
        OggOpusArchiveEncoder::new(self)?.encode(vendor)
    }
}

pub struct OggOpusAudioArchive {
    pub content: Vec<u8>,
    pub original_bytes: usize,
    pub sample_rate_hz: u32,
}

pub struct OggOpusMonoAudio {
    pub samples: Vec<f32>,
    pub input_channels: u8,
    pub source_pcm_bytes: usize,
    pub sample_rate_hz: u32,
}

impl OggOpusMonoAudio {
    pub fn decode(bytes: &[u8], sample_rate_hz: u32) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Opus(OpusError::OggOpusEmpty));
        }
        let max_samples_per_channel = usize::try_from(u64::from(sample_rate_hz) * 120 / 1_000)
            .map_err(|_| {
                Error::Opus(OpusError::OggOpusOutputSampleRateTooLarge { sample_rate_hz })
            })?;
        let decoder_sample_rate = i32::try_from(sample_rate_hz).map_err(|_| {
            Error::Opus(OpusError::OggOpusOutputSampleRateTooLarge { sample_rate_hz })
        })?;
        let mut reader = PacketReader::new(Cursor::new(bytes));
        let head_packet = reader
            .read_packet()
            .map_err(ogg_opus_read_error)?
            .ok_or(Error::Opus(OpusError::OggOpusNoPackets))?;
        if !head_packet.first_in_stream() {
            return Err(Error::Opus(OpusError::OggOpusHeaderNotStart));
        }
        let head = OggOpusHead::parse(&head_packet.data)?;
        let tags_packet = reader
            .read_packet()
            .map_err(ogg_opus_read_error)?
            .ok_or(Error::Opus(OpusError::OggOpusMissingTags))?;
        if !tags_packet.data.starts_with(b"OpusTags") {
            return Err(Error::Opus(OpusError::OggOpusMissingTags));
        }

        let channels = usize::from(head.channels);
        let mut decoder = RawOpusDecoder::new(decoder_sample_rate, channels).map_err(|reason| {
            Error::Opus(OpusError::OperationFailed {
                operation: OpusOperation::CreateDecoder,
                reason,
            })
        })?;
        let mut samples = Vec::new();
        let mut packets = 0_usize;
        while let Some(packet) = reader.read_packet().map_err(ogg_opus_read_error)? {
            if packet.first_in_stream() {
                return Err(Error::Opus(OpusError::OggOpusMultipleLogicalStreams));
            }
            let mut decoded = vec![0.0_f32; max_samples_per_channel * channels];
            let frames = decoder
                .decode(&packet.data, max_samples_per_channel, &mut decoded)
                .map_err(|reason| {
                    Error::Opus(OpusError::OperationFailed {
                        operation: OpusOperation::DecodeFrame,
                        reason,
                    })
                })?;
            decoded.truncate(frames * channels);
            samples.extend(decoded.chunks_exact(channels).map(mix_opus_frame_to_mono));
            packets += 1;
        }
        if packets == 0 {
            return Err(Error::Opus(OpusError::OggOpusNoAudioPackets));
        }
        if head.pre_skip >= samples.len() {
            return Err(Error::Opus(OpusError::OggOpusNoAudioAfterPreSkip));
        }
        samples.drain(..head.pre_skip);
        if samples.is_empty() {
            return Err(Error::Opus(OpusError::OggOpusDecodedEmpty));
        }
        let source_pcm_bytes = samples.len() * channels * std::mem::size_of::<f32>();
        Ok(Self {
            samples,
            input_channels: head.channels,
            source_pcm_bytes,
            sample_rate_hz,
        })
    }
}

struct OggOpusHead {
    channels: u8,
    pre_skip: usize,
}

impl OggOpusHead {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 19 || !data.starts_with(b"OpusHead") {
            return Err(Error::Opus(OpusError::OggOpusMissingHead));
        }
        let version = data[8];
        if version > 15 {
            return Err(Error::Opus(OpusError::OggOpusUnsupportedVersion {
                version,
            }));
        }
        let channels = data[9];
        if !matches!(channels, 1 | 2) {
            return Err(Error::Opus(OpusError::OggOpusUnsupportedChannelCount {
                channels,
            }));
        }
        let mapping_family = data[18];
        if mapping_family != 0 {
            return Err(Error::Opus(OpusError::OggOpusUnsupportedMappingFamily {
                mapping_family,
            }));
        }
        Ok(Self {
            channels,
            pre_skip: usize::from(u16::from_le_bytes([data[10], data[11]])),
        })
    }
}

fn mix_opus_frame_to_mono(frame: &[f32]) -> f32 {
    match frame {
        [sample] => sample.clamp(-1.0, 1.0),
        [left, right] => ((*left + *right) * 0.5).clamp(-1.0, 1.0),
        _ => 0.0,
    }
}

fn ogg_opus_read_error(error: ogg::OggReadError) -> Error {
    Error::Opus(OpusError::OggOpusRead(error.to_string()))
}

struct OggOpusArchiveEncoder {
    audio: PcmChunk,
}

impl OggOpusArchiveEncoder {
    fn new(audio: &CapturedPcmAudio) -> Result<Self> {
        let chunk = audio.pcm().clone();
        if chunk.is_empty() {
            return Err(Error::InvalidInput(InvalidInputError::PcmArchiveEmpty));
        }
        if !matches!(
            chunk.sample_rate_hz().get(),
            8_000 | 12_000 | 16_000 | 24_000 | 48_000
        ) {
            return Err(Error::InvalidInput(
                InvalidInputError::OggOpusUnsupportedSampleRate {
                    sample_rate_hz: chunk.sample_rate_hz().get(),
                },
            ));
        }
        Ok(Self { audio: chunk })
    }

    fn encode(self, vendor: &str) -> Result<OggOpusAudioArchive> {
        if vendor.is_empty() {
            return Err(Error::InvalidInput(InvalidInputError::OggOpusVendorEmpty));
        }
        let sample_rate_hz = self.audio.sample_rate_hz().get();
        let frame_samples = (sample_rate_hz * OPUS_ARCHIVE_FRAME_MS / 1000) as usize;
        let granule_step =
            OPUS_ARCHIVE_GRANULE_SAMPLE_RATE * u64::from(OPUS_ARCHIVE_FRAME_MS) / 1000;
        let mut encoder = RawOpusEncoder::new(
            sample_rate_hz as i32,
            OPUS_ARCHIVE_CHANNELS,
            RawOpusApplication::Voip,
        )
        .map_err(|reason| {
            Error::Opus(OpusError::OperationFailed {
                operation: OpusOperation::CreateEncoder,
                reason,
            })
        })?;
        encoder.bitrate_bps = OGG_OPUS_ARCHIVE_BITRATE_BPS;
        encoder.use_cbr = false;

        let mut output = vec![0; 4096];
        let mut writer = PacketWriter::new(Cursor::new(Vec::new()));
        writer.write_packet(
            Self::opus_head(sample_rate_hz),
            OGG_OPUS_ARCHIVE_SERIAL,
            PacketWriteEndInfo::EndPage,
            0,
        )?;
        writer.write_packet(
            Self::opus_tags(vendor),
            OGG_OPUS_ARCHIVE_SERIAL,
            PacketWriteEndInfo::EndPage,
            0,
        )?;

        let mut granule_position = 0;
        let frame_count = self.audio.sample_count().div_ceil(frame_samples);
        let bytes_per_sample = self.audio.encoding().bytes_per_sample();
        let mut frame = Vec::with_capacity(frame_samples);
        for index in 0..frame_count {
            let start = index * frame_samples;
            let end = ((index + 1) * frame_samples).min(self.audio.sample_count());
            frame.clear();
            self.audio.encoding().append_f32(
                &self.audio.data()[start * bytes_per_sample..end * bytes_per_sample],
                &mut frame,
            )?;
            frame.resize(frame_samples, 0.0);
            let written = encoder
                .encode(&frame, frame_samples, &mut output)
                .map_err(|reason| {
                    Error::Opus(OpusError::OperationFailed {
                        operation: OpusOperation::EncodeFrame,
                        reason,
                    })
                })?;
            granule_position += granule_step;
            writer.write_packet(
                output[..written].to_vec(),
                OGG_OPUS_ARCHIVE_SERIAL,
                if index + 1 == frame_count {
                    PacketWriteEndInfo::EndStream
                } else {
                    PacketWriteEndInfo::NormalPacket
                },
                granule_position,
            )?;
        }

        Ok(OggOpusAudioArchive {
            content: writer.into_inner().into_inner(),
            original_bytes: self.audio.byte_len(),
            sample_rate_hz,
        })
    }

    fn opus_head(input_sample_rate: u32) -> Vec<u8> {
        let mut packet = Vec::with_capacity(19);
        packet.extend_from_slice(b"OpusHead");
        packet.push(1);
        packet.push(OPUS_ARCHIVE_CHANNELS as u8);
        packet.extend_from_slice(&0_u16.to_le_bytes());
        packet.extend_from_slice(&input_sample_rate.to_le_bytes());
        packet.extend_from_slice(&0_i16.to_le_bytes());
        packet.push(0);
        packet
    }

    fn opus_tags(vendor: &str) -> Vec<u8> {
        let vendor = vendor.as_bytes();
        let mut packet = Vec::with_capacity(16 + vendor.len());
        packet.extend_from_slice(b"OpusTags");
        packet.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
        packet.extend_from_slice(vendor);
        packet.extend_from_slice(&0_u32.to_le_bytes());
        packet
    }
}

pub mod discord {
    use std::{marker::PhantomData, num::NonZeroU32, ops::Range, time::Duration};

    use crate::{
        errors::{Error, InvalidInputError, OpusError, OpusOperation, PayloadKind, Result},
        pcm::{
            ALaw, ChannelLayout, F32, F32Le, Mono, MuLaw, PcmChunk, PcmEncoding, PcmFormat, S16Le,
            SampleEncoding, Samples, StereoInterleaved, StreamingSincResampler,
        },
    };
    use opus_rs::{Application as RawOpusApplication, OpusEncoder as RawOpusEncoder};

    use super::MILLISECONDS_PER_SECOND;

    pub const SAMPLE_RATE_HZ: u32 = 48_000;
    pub const CHANNELS: usize = 2;
    pub const BLOCK_DURATION_MS: u64 = 20;
    pub const BLOCK_DURATION: Duration = Duration::from_millis(BLOCK_DURATION_MS);
    pub const SAMPLES_PER_CHANNEL: usize =
        SAMPLE_RATE_HZ as usize * BLOCK_DURATION_MS as usize / MILLISECONDS_PER_SECOND;
    pub const STEREO_SAMPLES_PER_BLOCK: usize = CHANNELS * SAMPLES_PER_CHANNEL;
    const OPUS_MAX_PACKET_SAMPLES_PER_CHANNEL: usize = SAMPLE_RATE_HZ as usize * 120 / 1_000;
    const OPUS_MAX_FRAME_BYTES: usize = 1_275;
    pub const MAX_PACKET_BYTES: usize = 4096;
    pub const RTP_PAYLOAD_TYPE: u8 = 120;
    pub const DEFAULT_BITRATE_BPS: u32 = 128_000;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Packet {
        bytes: Vec<u8>,
    }

    impl Packet {
        pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
            validate_packet_bytes(&bytes)?;
            Ok(Self { bytes })
        }

        fn from_encoder_bytes(bytes: Vec<u8>) -> Self {
            debug_assert!(validate_packet_bytes(&bytes).is_ok());
            Self { bytes }
        }

        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }

        pub const fn duration(&self) -> Duration {
            BLOCK_DURATION
        }

        pub fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PacketSpan {
        offset: usize,
        len: usize,
    }

    impl PacketSpan {
        pub fn len(self) -> usize {
            self.len
        }

        pub fn is_empty(self) -> bool {
            self.len == 0
        }

        pub const fn duration(self) -> Duration {
            BLOCK_DURATION
        }

        pub fn range(self) -> Range<usize> {
            self.offset..self.offset + self.len
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PacketRef<'a> {
        bytes: &'a [u8],
    }

    impl<'a> PacketRef<'a> {
        pub fn bytes(self) -> &'a [u8] {
            self.bytes
        }

        pub const fn duration(self) -> Duration {
            BLOCK_DURATION
        }

        pub fn to_packet(self) -> Packet {
            Packet::from_encoder_bytes(self.bytes.to_vec())
        }
    }

    #[derive(Debug, Default)]
    pub struct PacketBatch {
        bytes: Vec<u8>,
        packets: Vec<PacketSpan>,
        scratch: Vec<u8>,
    }

    impl PacketBatch {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn len(&self) -> usize {
            self.packets.len()
        }

        pub fn is_empty(&self) -> bool {
            self.packets.is_empty()
        }

        pub fn clear(&mut self) {
            self.bytes.clear();
            self.packets.clear();
            self.scratch.clear();
        }

        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }

        pub fn spans(&self) -> &[PacketSpan] {
            &self.packets
        }

        pub fn packet(&self, span: PacketSpan) -> PacketRef<'_> {
            PacketRef {
                bytes: &self.bytes[span.range()],
            }
        }

        pub fn iter(&self) -> impl ExactSizeIterator<Item = PacketRef<'_>> + '_ {
            self.packets.iter().copied().map(|span| self.packet(span))
        }

        pub fn into_packets(self) -> Vec<Packet> {
            let Self { bytes, packets, .. } = self;
            packets
                .into_iter()
                .map(|span| Packet::from_encoder_bytes(bytes[span.range()].to_vec()))
                .collect()
        }

        pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<PacketSpan>) {
            let Self { bytes, packets, .. } = self;
            (bytes, packets)
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Application {
        Voip,
        #[default]
        Audio,
        RestrictedLowDelay,
    }

    impl Application {
        const fn raw(self) -> RawOpusApplication {
            match self {
                Self::Voip => RawOpusApplication::Voip,
                Self::Audio => RawOpusApplication::Audio,
                Self::RestrictedLowDelay => RawOpusApplication::RestrictedLowDelay,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EncodeConfig {
        pub application: Application,
        pub bitrate_bps: NonZeroU32,
        pub cbr: bool,
    }

    impl Default for EncodeConfig {
        fn default() -> Self {
            Self {
                application: Application::Audio,
                bitrate_bps: NonZeroU32::new(DEFAULT_BITRATE_BPS)
                    .expect("default Opus bitrate is nonzero"),
                cbr: true,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct PcmBlock {
        samples: Box<[f32; STEREO_SAMPLES_PER_BLOCK]>,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct PcmFrame<'a> {
        samples: &'a [f32],
    }

    impl<'a> PcmFrame<'a> {
        pub fn from_stereo_interleaved(samples: &'a [f32]) -> Result<Self> {
            if samples.len() != STEREO_SAMPLES_PER_BLOCK {
                return Err(Error::InvalidInput(
                    InvalidInputError::PcmBlockSampleCount {
                        expected: STEREO_SAMPLES_PER_BLOCK,
                        actual: samples.len(),
                    },
                ));
            }
            Ok(Self { samples })
        }

        pub fn samples(self) -> &'a [f32] {
            self.samples
        }
    }

    impl PcmBlock {
        pub fn from_48khz<E, L>(samples: impl Samples<E>) -> Result<Self>
        where
            E: SampleEncoding,
            L: ChannelLayout,
        {
            let mut stereo = Vec::with_capacity(STEREO_SAMPLES_PER_BLOCK);
            let frames = L::append_stereo_interleaved_from_source::<E, _>(&samples, &mut stereo)?;
            if frames != SAMPLES_PER_CHANNEL {
                return Err(Error::InvalidInput(InvalidInputError::PcmBlockFrameCount {
                    expected: SAMPLES_PER_CHANNEL,
                    actual: frames,
                }));
            }
            Self::from_stereo_interleaved(stereo)
        }

        pub fn samples(&self) -> &[f32; STEREO_SAMPLES_PER_BLOCK] {
            &self.samples
        }

        pub fn as_frame(&self) -> PcmFrame<'_> {
            PcmFrame {
                samples: self.samples.as_slice(),
            }
        }

        fn from_stereo_interleaved(samples: impl AsRef<[f32]>) -> Result<Self> {
            let samples = samples.as_ref();
            if samples.len() != STEREO_SAMPLES_PER_BLOCK {
                return Err(Error::InvalidInput(
                    InvalidInputError::PcmBlockSampleCount {
                        expected: STEREO_SAMPLES_PER_BLOCK,
                        actual: samples.len(),
                    },
                ));
            }
            let mut block = Box::new([0.0; STEREO_SAMPLES_PER_BLOCK]);
            block.copy_from_slice(samples);
            Ok(Self { samples: block })
        }
    }

    pub struct PacketEncoder {
        encoder: RawOpusEncoder,
    }

    impl PacketEncoder {
        pub fn new(config: EncodeConfig) -> Result<Self> {
            let mut encoder =
                RawOpusEncoder::new(SAMPLE_RATE_HZ as i32, CHANNELS, config.application.raw())
                    .map_err(|reason| {
                        Error::Opus(OpusError::OperationFailed {
                            operation: OpusOperation::CreateEncoder,
                            reason,
                        })
                    })?;
            encoder.bitrate_bps = i32::try_from(config.bitrate_bps.get()).map_err(|_| {
                Error::InvalidInput(InvalidInputError::OpusBitrateTooLarge {
                    bitrate_bps: config.bitrate_bps.get(),
                })
            })?;
            encoder.use_cbr = config.cbr;

            Ok(Self { encoder })
        }

        pub fn encode(&mut self, block: &PcmBlock) -> Result<Packet> {
            let mut bytes = Vec::with_capacity(MAX_PACKET_BYTES);
            self.encode_frame_into(block.as_frame(), &mut bytes)?;
            Ok(Packet::from_encoder_bytes(bytes))
        }

        pub fn encode_into(&mut self, block: &PcmBlock, output: &mut Vec<u8>) -> Result<usize> {
            self.encode_frame_into(block.as_frame(), output)
        }

        pub fn encode_frame(&mut self, frame: PcmFrame<'_>) -> Result<Packet> {
            let mut bytes = Vec::with_capacity(MAX_PACKET_BYTES);
            self.encode_frame_into(frame, &mut bytes)?;
            Ok(Packet::from_encoder_bytes(bytes))
        }

        pub fn encode_frame_into(
            &mut self,
            frame: PcmFrame<'_>,
            output: &mut Vec<u8>,
        ) -> Result<usize> {
            output.resize(MAX_PACKET_BYTES, 0);
            let written = self.encode_frame_to_slice(frame, output)?;
            output.truncate(written);
            Ok(written)
        }

        pub fn encode_to_slice(&mut self, block: &PcmBlock, output: &mut [u8]) -> Result<usize> {
            self.encode_frame_to_slice(block.as_frame(), output)
        }

        pub fn encode_frame_to_slice(
            &mut self,
            frame: PcmFrame<'_>,
            output: &mut [u8],
        ) -> Result<usize> {
            if output.len() < MAX_PACKET_BYTES {
                return Err(Error::InvalidInput(
                    InvalidInputError::OpusOutputBufferTooSmall {
                        min_len: MAX_PACKET_BYTES,
                        len: output.len(),
                    },
                ));
            }

            let written = self
                .encoder
                .encode(frame.samples(), SAMPLES_PER_CHANNEL, output)
                .map_err(|reason| {
                    Error::Opus(OpusError::OperationFailed {
                        operation: OpusOperation::EncodeFrame,
                        reason,
                    })
                })?;
            Ok(written)
        }
    }

    pub trait PacketSink {
        fn encode_packet(
            &mut self,
            encode: impl FnOnce(&mut Vec<u8>) -> Result<usize>,
        ) -> Result<()>;
    }

    impl PacketSink for Vec<Packet> {
        fn encode_packet(
            &mut self,
            encode: impl FnOnce(&mut Vec<u8>) -> Result<usize>,
        ) -> Result<()> {
            let mut bytes = Vec::with_capacity(MAX_PACKET_BYTES);
            let written = encode(&mut bytes)?;
            debug_assert_eq!(written, bytes.len());
            self.push(Packet::from_encoder_bytes(bytes));
            Ok(())
        }
    }

    impl PacketSink for PacketBatch {
        fn encode_packet(
            &mut self,
            encode: impl FnOnce(&mut Vec<u8>) -> Result<usize>,
        ) -> Result<()> {
            self.scratch.clear();
            let written = encode(&mut self.scratch)?;
            debug_assert_eq!(written, self.scratch.len());
            let offset = self.bytes.len();
            self.bytes.extend_from_slice(&self.scratch);
            self.packets.push(PacketSpan {
                offset,
                len: self.scratch.len(),
            });
            Ok(())
        }
    }

    pub struct PcmEncoder<E, L>
    where
        E: SampleEncoding,
        L: ChannelLayout,
    {
        input_sample_rate_hz: NonZeroU32,
        resampler: StreamingSincResampler<L>,
        packet_encoder: PacketEncoder,
        source_samples: Vec<f32>,
        resampled_samples: Vec<f32>,
        discord_samples: Vec<f32>,
        pending_stereo_samples: Vec<f32>,
        emitted_packets: usize,
        _encoding: PhantomData<E>,
        _layout: PhantomData<L>,
    }

    impl<E, L> PcmEncoder<E, L>
    where
        E: SampleEncoding,
        L: ChannelLayout,
    {
        pub fn new(input_sample_rate_hz: NonZeroU32, config: EncodeConfig) -> Result<Self> {
            Ok(Self {
                input_sample_rate_hz,
                resampler: StreamingSincResampler::<L>::new(
                    input_sample_rate_hz,
                    NonZeroU32::new(SAMPLE_RATE_HZ).expect("Discord Opus sample rate is nonzero"),
                    source_block_frames(input_sample_rate_hz),
                )?,
                packet_encoder: PacketEncoder::new(config)?,
                source_samples: Vec::new(),
                resampled_samples: Vec::new(),
                discord_samples: Vec::new(),
                pending_stereo_samples: Vec::with_capacity(STEREO_SAMPLES_PER_BLOCK),
                emitted_packets: 0,
                _encoding: PhantomData,
                _layout: PhantomData,
            })
        }

        pub fn push(
            &mut self,
            samples: impl Samples<E>,
            output: &mut Vec<Packet>,
        ) -> Result<usize> {
            self.push_to(samples, output)
        }

        pub fn push_to(
            &mut self,
            samples: impl Samples<E>,
            sink: &mut impl PacketSink,
        ) -> Result<usize> {
            let before = self.emitted_packets_hint();
            if self.resampling_required() {
                self.source_samples.clear();
                L::append_source_f32::<E, _>(&samples, &mut self.source_samples)?;
                if self.source_samples.is_empty() {
                    return Ok(0);
                }
                self.resampled_samples.clear();
                self.resampler
                    .push_into(&self.source_samples, &mut self.resampled_samples)?;
                self.encode_resampled(sink)?;
            } else {
                self.discord_samples.clear();
                L::append_stereo_interleaved_from_source::<E, _>(
                    &samples,
                    &mut self.discord_samples,
                )?;
                self.encode_discord_samples(sink)?;
            }
            Ok(self.emitted_packets_hint() - before)
        }

        fn emitted_packets_hint(&self) -> usize {
            self.emitted_packets
        }

        pub fn finish(&mut self, output: &mut Vec<Packet>) -> Result<usize> {
            self.finish_to(output)
        }

        pub fn finish_to(&mut self, sink: &mut impl PacketSink) -> Result<usize> {
            let before = self.emitted_packets_hint();
            if self.resampling_required() {
                self.resampled_samples.clear();
                self.resampler.finish_into(&mut self.resampled_samples)?;
                self.encode_resampled(sink)?;
            }
            if !self.pending_stereo_samples.is_empty() {
                self.pending_stereo_samples
                    .resize(STEREO_SAMPLES_PER_BLOCK, 0.0);
                self.encode_pending_block(sink)?;
            }
            Ok(self.emitted_packets_hint() - before)
        }

        pub fn push_packets(&mut self, samples: impl Samples<E>) -> Result<Vec<Packet>> {
            let mut packets = Vec::new();
            self.push(samples, &mut packets)?;
            Ok(packets)
        }

        pub fn push_packet_batch(&mut self, samples: impl Samples<E>) -> Result<PacketBatch> {
            let mut packets = PacketBatch::new();
            self.push_to(samples, &mut packets)?;
            Ok(packets)
        }

        pub fn finish_packets(&mut self) -> Result<Vec<Packet>> {
            let mut packets = Vec::new();
            self.finish(&mut packets)?;
            Ok(packets)
        }

        pub fn finish_packet_batch(&mut self) -> Result<PacketBatch> {
            let mut packets = PacketBatch::new();
            self.finish_to(&mut packets)?;
            Ok(packets)
        }

        pub fn encode_all(
            input_sample_rate_hz: NonZeroU32,
            samples: impl Samples<E>,
            config: EncodeConfig,
        ) -> Result<Vec<Packet>> {
            let mut encoder = Self::new(input_sample_rate_hz, config)?;
            let mut packets = Vec::new();
            encoder.push(samples, &mut packets)?;
            encoder.finish(&mut packets)?;
            Ok(packets)
        }

        pub fn encode_all_batch(
            input_sample_rate_hz: NonZeroU32,
            samples: impl Samples<E>,
            config: EncodeConfig,
        ) -> Result<PacketBatch> {
            let mut encoder = Self::new(input_sample_rate_hz, config)?;
            let mut packets = PacketBatch::new();
            encoder.push_to(samples, &mut packets)?;
            encoder.finish_to(&mut packets)?;
            Ok(packets)
        }

        pub fn input_sample_rate_hz(&self) -> NonZeroU32 {
            self.input_sample_rate_hz
        }

        pub fn resampling_required(&self) -> bool {
            self.resampler.resampling_required()
        }

        pub fn pending_samples_per_channel(&self) -> usize {
            self.pending_stereo_samples.len() / CHANNELS
        }

        fn encode_resampled(&mut self, sink: &mut impl PacketSink) -> Result<()> {
            if self.resampled_samples.is_empty() {
                return Ok(());
            }
            self.discord_samples.clear();
            L::append_stereo_interleaved(&self.resampled_samples, &mut self.discord_samples)?;
            self.encode_discord_samples(sink)
        }

        fn encode_discord_samples(&mut self, sink: &mut impl PacketSink) -> Result<()> {
            let mut offset = 0;
            if !self.pending_stereo_samples.is_empty() {
                let needed = STEREO_SAMPLES_PER_BLOCK - self.pending_stereo_samples.len();
                let available = needed.min(self.discord_samples.len());
                self.pending_stereo_samples
                    .extend_from_slice(&self.discord_samples[..available]);
                offset += available;
                if self.pending_stereo_samples.len() == STEREO_SAMPLES_PER_BLOCK {
                    self.encode_pending_block(sink)?;
                }
            }

            while self.discord_samples.len() - offset >= STEREO_SAMPLES_PER_BLOCK {
                let end = offset + STEREO_SAMPLES_PER_BLOCK;
                self.encode_stereo_frame(offset, end, sink)?;
                offset = end;
            }

            self.pending_stereo_samples
                .extend_from_slice(&self.discord_samples[offset..]);
            Ok(())
        }

        fn encode_stereo_frame(
            &mut self,
            start: usize,
            end: usize,
            sink: &mut impl PacketSink,
        ) -> Result<()> {
            let frame = PcmFrame::from_stereo_interleaved(&self.discord_samples[start..end])?;
            let packet_encoder = &mut self.packet_encoder;
            sink.encode_packet(|bytes| packet_encoder.encode_frame_into(frame, bytes))?;
            self.emitted_packets += 1;
            Ok(())
        }

        fn encode_pending_block(&mut self, sink: &mut impl PacketSink) -> Result<()> {
            let frame = PcmFrame::from_stereo_interleaved(&self.pending_stereo_samples)?;
            let packet_encoder = &mut self.packet_encoder;
            sink.encode_packet(|bytes| packet_encoder.encode_frame_into(frame, bytes))?;
            self.pending_stereo_samples.clear();
            self.emitted_packets += 1;
            Ok(())
        }
    }

    pub struct DynamicPcmEncoder {
        source_format: Option<PcmFormat>,
        source_pcm_bytes: usize,
        encoder: Option<DynamicPcmEncoderInner>,
    }

    impl Default for DynamicPcmEncoder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DynamicPcmEncoder {
        pub fn new() -> Self {
            Self {
                source_format: None,
                source_pcm_bytes: 0,
                encoder: None,
            }
        }

        pub fn push_chunk_to(
            &mut self,
            chunk: &PcmChunk,
            sink: &mut impl PacketSink,
        ) -> Result<usize> {
            self.accept_format(chunk.format())?;
            self.source_pcm_bytes += chunk.byte_len();
            self.encoder_mut()?.push(chunk.data(), sink)
        }

        pub fn push_chunk(&mut self, chunk: &PcmChunk) -> Result<Vec<Packet>> {
            let mut packets = Vec::new();
            self.push_chunk_to(chunk, &mut packets)?;
            Ok(packets)
        }

        pub fn push_chunk_batch(&mut self, chunk: &PcmChunk) -> Result<PacketBatch> {
            let mut packets = PacketBatch::new();
            self.push_chunk_to(chunk, &mut packets)?;
            Ok(packets)
        }

        pub fn finish_to(&mut self, sink: &mut impl PacketSink) -> Result<usize> {
            if let Some(encoder) = self.encoder.as_mut() {
                encoder.finish(sink)
            } else {
                Ok(0)
            }
        }

        pub fn finish(&mut self) -> Result<Vec<Packet>> {
            let mut packets = Vec::new();
            self.finish_to(&mut packets)?;
            Ok(packets)
        }

        pub fn finish_batch(&mut self) -> Result<PacketBatch> {
            let mut packets = PacketBatch::new();
            self.finish_to(&mut packets)?;
            Ok(packets)
        }

        pub fn source_sample_rate_hz(&self) -> u32 {
            self.source_format
                .map(PcmFormat::sample_rate_hz)
                .map(NonZeroU32::get)
                .unwrap_or(SAMPLE_RATE_HZ)
        }

        pub fn source_format(&self) -> Option<PcmFormat> {
            self.source_format
        }

        pub fn source_pcm_bytes(&self) -> usize {
            self.source_pcm_bytes
        }

        pub fn source_channel_count(&self) -> usize {
            self.source_format
                .map(|format| format.channels().get())
                .unwrap_or(1)
        }

        pub fn resampling_required(&self) -> bool {
            self.encoder
                .as_ref()
                .is_some_and(DynamicPcmEncoderInner::resampling_required)
        }

        fn accept_format(&mut self, format: PcmFormat) -> Result<()> {
            match self.source_format {
                None => {
                    self.source_format = Some(format);
                    self.encoder = Some(DynamicPcmEncoderInner::new(format)?);
                    Ok(())
                }
                Some(existing) if existing == format => Ok(()),
                Some(existing) if existing.sample_rate_hz() != format.sample_rate_hz() => Err(
                    Error::InvalidInput(InvalidInputError::DiscordPcmMixedSampleRates {
                        existing: existing.sample_rate_hz().get(),
                        actual: format.sample_rate_hz().get(),
                    }),
                ),
                Some(existing) if existing.channels() != format.channels() => Err(
                    Error::InvalidInput(InvalidInputError::DiscordPcmMixedChannelCounts {
                        existing: existing.channels().get(),
                        actual: format.channels().get(),
                    }),
                ),
                Some(_) => Err(Error::InvalidInput(
                    InvalidInputError::DiscordPcmMixedEncoding,
                )),
            }
        }

        fn encoder_mut(&mut self) -> Result<&mut DynamicPcmEncoderInner> {
            self.encoder.as_mut().ok_or(Error::InvalidInput(
                InvalidInputError::DiscordPcmEncoderUninitialized,
            ))
        }
    }

    enum DynamicPcmEncoderInner {
        Mono(DynamicPcmLayoutEncoder<Mono>),
        Stereo(DynamicPcmLayoutEncoder<StereoInterleaved>),
    }

    enum DynamicPcmLayoutEncoder<L>
    where
        L: ChannelLayout,
    {
        F32Le(PcmEncoder<F32Le, L>),
        S16Le(PcmEncoder<S16Le, L>),
        MuLaw(PcmEncoder<MuLaw, L>),
        ALaw(PcmEncoder<ALaw, L>),
    }

    trait DynamicPcmSampleEncoding: SampleEncoding {
        fn push_to<L, S>(
            encoder: &mut PcmEncoder<Self, L>,
            data: &[u8],
            sink: &mut S,
        ) -> Result<usize>
        where
            Self: Sized,
            L: ChannelLayout,
            S: PacketSink;
    }

    impl DynamicPcmSampleEncoding for F32Le {
        fn push_to<L, S>(
            encoder: &mut PcmEncoder<Self, L>,
            data: &[u8],
            sink: &mut S,
        ) -> Result<usize>
        where
            L: ChannelLayout,
            S: PacketSink,
        {
            encoder.push_to(data, sink)
        }
    }

    impl DynamicPcmSampleEncoding for S16Le {
        fn push_to<L, S>(
            encoder: &mut PcmEncoder<Self, L>,
            data: &[u8],
            sink: &mut S,
        ) -> Result<usize>
        where
            L: ChannelLayout,
            S: PacketSink,
        {
            encoder.push_to(data, sink)
        }
    }

    impl DynamicPcmSampleEncoding for MuLaw {
        fn push_to<L, S>(
            encoder: &mut PcmEncoder<Self, L>,
            data: &[u8],
            sink: &mut S,
        ) -> Result<usize>
        where
            L: ChannelLayout,
            S: PacketSink,
        {
            encoder.push_to(data, sink)
        }
    }

    impl DynamicPcmSampleEncoding for ALaw {
        fn push_to<L, S>(
            encoder: &mut PcmEncoder<Self, L>,
            data: &[u8],
            sink: &mut S,
        ) -> Result<usize>
        where
            L: ChannelLayout,
            S: PacketSink,
        {
            encoder.push_to(data, sink)
        }
    }

    trait DynamicPcmEncoderVisitor {
        type Output;

        fn visit<E, L>(&mut self, encoder: &mut PcmEncoder<E, L>) -> Self::Output
        where
            E: DynamicPcmSampleEncoding,
            L: ChannelLayout;
    }

    impl DynamicPcmEncoderInner {
        fn new(format: PcmFormat) -> Result<Self> {
            match format.channels().get() {
                1 => Ok(Self::Mono(DynamicPcmLayoutEncoder::new(format)?)),
                2 => Ok(Self::Stereo(DynamicPcmLayoutEncoder::new(format)?)),
                channels => Err(Error::Opus(OpusError::UnsupportedChannelCount { channels })),
            }
        }

        fn push(&mut self, data: &[u8], sink: &mut impl PacketSink) -> Result<usize> {
            self.visit(&mut PushDynamicPcmEncoder { data, sink })
        }

        fn finish(&mut self, sink: &mut impl PacketSink) -> Result<usize> {
            self.visit(&mut FinishDynamicPcmEncoder { sink })
        }

        fn resampling_required(&self) -> bool {
            match self {
                Self::Mono(encoder) => encoder.resampling_required(),
                Self::Stereo(encoder) => encoder.resampling_required(),
            }
        }

        fn visit<V>(&mut self, visitor: &mut V) -> V::Output
        where
            V: DynamicPcmEncoderVisitor,
        {
            match self {
                Self::Mono(encoder) => encoder.visit(visitor),
                Self::Stereo(encoder) => encoder.visit(visitor),
            }
        }
    }

    impl<L> DynamicPcmLayoutEncoder<L>
    where
        L: ChannelLayout,
    {
        fn new(format: PcmFormat) -> Result<Self> {
            Ok(match format.encoding() {
                PcmEncoding::F32Le => Self::F32Le(PcmEncoder::<F32Le, L>::new(
                    format.sample_rate_hz(),
                    EncodeConfig::default(),
                )?),
                PcmEncoding::S16Le => Self::S16Le(PcmEncoder::<S16Le, L>::new(
                    format.sample_rate_hz(),
                    EncodeConfig::default(),
                )?),
                PcmEncoding::MuLaw => Self::MuLaw(PcmEncoder::<MuLaw, L>::new(
                    format.sample_rate_hz(),
                    EncodeConfig::default(),
                )?),
                PcmEncoding::ALaw => Self::ALaw(PcmEncoder::<ALaw, L>::new(
                    format.sample_rate_hz(),
                    EncodeConfig::default(),
                )?),
            })
        }

        fn visit<V>(&mut self, visitor: &mut V) -> V::Output
        where
            V: DynamicPcmEncoderVisitor,
        {
            match self {
                Self::F32Le(encoder) => visitor.visit(encoder),
                Self::S16Le(encoder) => visitor.visit(encoder),
                Self::MuLaw(encoder) => visitor.visit(encoder),
                Self::ALaw(encoder) => visitor.visit(encoder),
            }
        }

        fn resampling_required(&self) -> bool {
            match self {
                Self::F32Le(encoder) => encoder.resampling_required(),
                Self::S16Le(encoder) => encoder.resampling_required(),
                Self::MuLaw(encoder) => encoder.resampling_required(),
                Self::ALaw(encoder) => encoder.resampling_required(),
            }
        }
    }

    struct PushDynamicPcmEncoder<'data, 'sink, S>
    where
        S: PacketSink,
    {
        data: &'data [u8],
        sink: &'sink mut S,
    }

    impl<S> DynamicPcmEncoderVisitor for PushDynamicPcmEncoder<'_, '_, S>
    where
        S: PacketSink,
    {
        type Output = Result<usize>;

        fn visit<E, L>(&mut self, encoder: &mut PcmEncoder<E, L>) -> Self::Output
        where
            E: DynamicPcmSampleEncoding,
            L: ChannelLayout,
        {
            E::push_to(encoder, self.data, self.sink)
        }
    }

    struct FinishDynamicPcmEncoder<'sink, S>
    where
        S: PacketSink,
    {
        sink: &'sink mut S,
    }

    impl<S> DynamicPcmEncoderVisitor for FinishDynamicPcmEncoder<'_, S>
    where
        S: PacketSink,
    {
        type Output = Result<usize>;

        fn visit<E, L>(&mut self, encoder: &mut PcmEncoder<E, L>) -> Self::Output
        where
            E: DynamicPcmSampleEncoding,
            L: ChannelLayout,
        {
            encoder.finish_to(self.sink)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PlaybackAudioSource {
        pub sample_rate_hz: NonZeroU32,
        pub channel_count: NonZeroU32,
        pub pcm_bytes: usize,
    }

    pub struct PlaybackAudio {
        packets: Vec<Packet>,
        source: PlaybackAudioSource,
    }

    impl PlaybackAudio {
        pub fn from_chunks(chunks: &[PcmChunk]) -> Result<Self> {
            let mut encoder = DynamicPcmEncoder::new();
            let mut packets = Vec::new();
            for chunk in chunks {
                encoder.push_chunk_to(chunk, &mut packets)?;
            }
            encoder.finish_to(&mut packets)?;
            Ok(Self {
                packets,
                source: PlaybackAudioSource {
                    sample_rate_hz: NonZeroU32::new(encoder.source_sample_rate_hz())
                        .expect("default Discord source sample rate is nonzero"),
                    channel_count: NonZeroU32::new(
                        u32::try_from(encoder.source_channel_count())
                            .expect("Discord source channel count fits u32"),
                    )
                    .expect("default Discord source channel count is nonzero"),
                    pcm_bytes: encoder.source_pcm_bytes(),
                },
            })
        }

        pub fn from_mono_samples(samples: &[f32], source: PlaybackAudioSource) -> Result<Self> {
            Ok(Self {
                packets: PcmEncoder::<F32, Mono>::encode_all(
                    source.sample_rate_hz,
                    samples,
                    EncodeConfig::default(),
                )?,
                source,
            })
        }

        pub fn packets(&self) -> &[Packet] {
            &self.packets
        }

        pub fn clone_packets(&self) -> Vec<Packet> {
            self.packets.clone()
        }

        pub fn source(&self) -> PlaybackAudioSource {
            self.source
        }

        pub fn source_sample_rate_hz(&self) -> u32 {
            self.source.sample_rate_hz.get()
        }

        pub fn source_channel_count(&self) -> u32 {
            self.source.channel_count.get()
        }

        pub fn source_pcm_bytes(&self) -> usize {
            self.source.pcm_bytes
        }

        pub fn packet_count(&self) -> usize {
            self.packets.len()
        }
    }

    fn source_block_frames(input_sample_rate_hz: NonZeroU32) -> usize {
        ((input_sample_rate_hz.get() as usize * BLOCK_DURATION_MS as usize)
            / MILLISECONDS_PER_SECOND)
            .max(1)
    }

    fn validate_packet_bytes(bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Err(Error::InvalidInput(InvalidInputError::EmptyPayload {
                codec: dave::Codec::Opus,
            }));
        }
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(Error::PayloadTooLarge {
                kind: PayloadKind::Frame,
                len: bytes.len(),
                max_len: MAX_PACKET_BYTES,
            });
        }
        let samples_per_channel = opus_packet_samples_per_channel(bytes)?;
        if samples_per_channel != SAMPLES_PER_CHANNEL {
            return Err(Error::Opus(OpusError::UnsupportedDiscordPacketDuration {
                expected_samples_per_channel: SAMPLES_PER_CHANNEL,
                actual_samples_per_channel: samples_per_channel,
            }));
        }
        Ok(())
    }

    fn opus_packet_samples_per_channel(packet: &[u8]) -> Result<usize> {
        let samples_per_frame = opus_samples_per_frame(packet[0]);
        let frame_count = opus_packet_frame_count(packet, samples_per_frame)?;
        let samples = samples_per_frame.checked_mul(frame_count).ok_or({
            Error::Opus(OpusError::InvalidPacket {
                reason: "sample count overflow",
            })
        })?;
        if samples > OPUS_MAX_PACKET_SAMPLES_PER_CHANNEL {
            return Err(Error::Opus(OpusError::InvalidPacket {
                reason: "packet duration exceeds 120 ms",
            }));
        }
        Ok(samples)
    }

    fn opus_packet_frame_count(packet: &[u8], samples_per_frame: usize) -> Result<usize> {
        let payload = &packet[1..];
        match packet[0] & 0x03 {
            0 => {
                validate_opus_frame_size(payload.len())?;
                Ok(1)
            }
            1 => {
                if !payload.len().is_multiple_of(2) {
                    return invalid_opus_packet("code 1 packet has odd payload length");
                }
                validate_opus_frame_size(payload.len() / 2)?;
                Ok(2)
            }
            2 => {
                let (first_len, used) = parse_opus_frame_size(payload)?;
                let remaining = payload.len().checked_sub(used).ok_or({
                    Error::Opus(OpusError::InvalidPacket {
                        reason: "code 2 packet size underflow",
                    })
                })?;
                if first_len > remaining {
                    return invalid_opus_packet("code 2 first frame exceeds packet length");
                }
                validate_opus_frame_size(first_len)?;
                validate_opus_frame_size(remaining - first_len)?;
                Ok(2)
            }
            _ => opus_code3_frame_count(payload, samples_per_frame),
        }
    }

    fn opus_code3_frame_count(payload: &[u8], samples_per_frame: usize) -> Result<usize> {
        let Some((&count_byte, mut frame_bytes)) = payload.split_first() else {
            return invalid_opus_packet("code 3 packet missing frame count");
        };
        let frame_count = usize::from(count_byte & 0x3f);
        if frame_count == 0 || frame_count > 48 {
            return invalid_opus_packet("code 3 packet has invalid frame count");
        }
        if samples_per_frame * frame_count > OPUS_MAX_PACKET_SAMPLES_PER_CHANNEL {
            return invalid_opus_packet("code 3 packet duration exceeds 120 ms");
        }
        if count_byte & 0x40 != 0 {
            let (padding, used) = parse_opus_padding_len(frame_bytes)?;
            frame_bytes = frame_bytes.get(used..).ok_or({
                Error::Opus(OpusError::InvalidPacket {
                    reason: "code 3 padding header exceeds packet length",
                })
            })?;
            let Some(data_len) = frame_bytes.len().checked_sub(padding) else {
                return invalid_opus_packet("code 3 padding exceeds packet length");
            };
            frame_bytes = &frame_bytes[..data_len];
        }
        if count_byte & 0x80 != 0 {
            validate_opus_vbr_frame_sizes(frame_bytes, frame_count)?;
        } else {
            if frame_bytes.len() % frame_count != 0 {
                return invalid_opus_packet("code 3 CBR payload is not frame-aligned");
            }
            validate_opus_frame_size(frame_bytes.len() / frame_count)?;
        }
        Ok(frame_count)
    }

    fn validate_opus_vbr_frame_sizes(mut frame_bytes: &[u8], frame_count: usize) -> Result<()> {
        let mut sized_payload_len = 0usize;
        for _ in 0..frame_count - 1 {
            let (frame_len, used) = parse_opus_frame_size(frame_bytes)?;
            validate_opus_frame_size(frame_len)?;
            frame_bytes = frame_bytes.get(used..).ok_or({
                Error::Opus(OpusError::InvalidPacket {
                    reason: "VBR frame size header exceeds packet length",
                })
            })?;
            sized_payload_len = sized_payload_len.checked_add(frame_len).ok_or({
                Error::Opus(OpusError::InvalidPacket {
                    reason: "VBR frame size overflow",
                })
            })?;
        }
        if sized_payload_len > frame_bytes.len() {
            return invalid_opus_packet("VBR frame sizes exceed packet length");
        }
        validate_opus_frame_size(frame_bytes.len() - sized_payload_len)?;
        Ok(())
    }

    fn parse_opus_frame_size(data: &[u8]) -> Result<(usize, usize)> {
        let Some((&first, rest)) = data.split_first() else {
            return invalid_opus_packet("missing frame size");
        };
        if first < 252 {
            Ok((usize::from(first), 1))
        } else {
            let Some((&second, _)) = rest.split_first() else {
                return invalid_opus_packet("truncated extended frame size");
            };
            Ok((usize::from(second) * 4 + usize::from(first), 2))
        }
    }

    fn parse_opus_padding_len(data: &[u8]) -> Result<(usize, usize)> {
        let mut padding = 0usize;
        for (index, byte) in data.iter().copied().enumerate() {
            padding = padding
                .checked_add(if byte == u8::MAX {
                    usize::from(u8::MAX - 1)
                } else {
                    usize::from(byte)
                })
                .ok_or(Error::Opus(OpusError::InvalidPacket {
                    reason: "padding length overflow",
                }))?;
            if byte != u8::MAX {
                return Ok((padding, index + 1));
            }
        }
        invalid_opus_packet("unterminated padding length")
    }

    fn validate_opus_frame_size(frame_len: usize) -> Result<()> {
        if frame_len > OPUS_MAX_FRAME_BYTES {
            invalid_opus_packet("frame exceeds Opus maximum encoded size")
        } else {
            Ok(())
        }
    }

    fn opus_samples_per_frame(toc: u8) -> usize {
        let sample_rate = SAMPLE_RATE_HZ as usize;
        if toc & 0x80 != 0 {
            (sample_rate << ((toc >> 3) & 0x03)) / 400
        } else if toc & 0x60 == 0x60 {
            if toc & 0x08 != 0 {
                sample_rate / 50
            } else {
                sample_rate / 100
            }
        } else {
            let config = (toc >> 3) & 0x03;
            if config == 3 {
                sample_rate * 60 / 1_000
            } else {
                (sample_rate << config) / 100
            }
        }
    }

    fn invalid_opus_packet<T>(reason: &'static str) -> Result<T> {
        Err(Error::Opus(OpusError::InvalidPacket { reason }))
    }
}

pub struct Decoder {
    mono_decoder: RawOpusDecoder,
    stereo_decoder: RawOpusDecoder,
    decoded_f32: Vec<f32>,
    sample_rate: u32,
    max_samples_per_channel: usize,
}

impl Decoder {
    pub fn discord_default() -> Result<Self> {
        let mono_decoder =
            RawOpusDecoder::new(discord::SAMPLE_RATE_HZ as i32, 1).map_err(|reason| {
                Error::Opus(OpusError::OperationFailed {
                    operation: OpusOperation::CreateMonoDecoder,
                    reason,
                })
            })?;
        let stereo_decoder = RawOpusDecoder::new(discord::SAMPLE_RATE_HZ as i32, discord::CHANNELS)
            .map_err(|reason| {
                Error::Opus(OpusError::OperationFailed {
                    operation: OpusOperation::CreateDecoder,
                    reason,
                })
            })?;
        Ok(Self {
            max_samples_per_channel: discord::SAMPLES_PER_CHANNEL,
            mono_decoder,
            stereo_decoder,
            decoded_f32: Vec::new(),
            sample_rate: discord::SAMPLE_RATE_HZ,
        })
    }

    pub fn decode_frame<Raw>(&mut self, frame: ReceivedFrame<Raw>) -> Result<DecodedFrame<Raw>>
    where
        Raw: FrameRaw,
    {
        let mut pcm = Vec::new();
        let metadata = self.decode_frame_into(frame, &mut pcm)?;
        Ok(DecodedFrame {
            frame: metadata.frame,
            pcm_layout: metadata.pcm_layout,
            pcm,
        })
    }

    pub fn decode_frame_into<Raw>(
        &mut self,
        frame: ReceivedFrame<Raw>,
        pcm: &mut Vec<i16>,
    ) -> Result<DecodedFrameMetadata<Raw>>
    where
        Raw: FrameRaw,
    {
        if frame.codec != dave::Codec::Opus {
            return Err(Error::Opus(OpusError::UnsupportedVoiceCodec {
                codec: frame.codec,
            }));
        }
        let channels = opus_frame_channels(&frame.frame)?;
        self.decoded_f32
            .resize(self.max_samples_per_channel * channels, 0.0);
        let decoder = match channels {
            1 => &mut self.mono_decoder,
            discord::CHANNELS => &mut self.stereo_decoder,
            _ => {
                return Err(Error::Opus(OpusError::UnsupportedChannelCount { channels }));
            }
        };
        let samples_per_channel = decoder
            .decode(
                &frame.frame,
                self.max_samples_per_channel,
                &mut self.decoded_f32,
            )
            .map_err(|reason| {
                Error::Opus(OpusError::OperationFailed {
                    operation: OpusOperation::DecodeFrame,
                    reason,
                })
            })?;
        let decoded_len = samples_per_channel * channels;
        self.decoded_f32.truncate(decoded_len);
        pcm.clear();
        pcm.reserve(samples_per_channel * discord::CHANNELS);
        if channels == 1 {
            for sample in &self.decoded_f32 {
                let sample = pcm_f32_to_i16(*sample);
                pcm.extend_from_slice(&[sample, sample]);
            }
        } else {
            pcm.extend(
                self.decoded_f32
                    .iter()
                    .map(|sample| pcm_f32_to_i16(*sample)),
            );
        }

        Ok(DecodedFrameMetadata {
            frame,
            pcm_layout: DecodedPcmLayout {
                sample_rate_hz: self.sample_rate,
                channels: discord::CHANNELS,
                samples_per_channel,
            },
        })
    }
}

pub(crate) fn opus_frame_channels(frame: &[u8]) -> Result<usize> {
    let Some(toc) = frame.first() else {
        return Err(Error::Opus(OpusError::EmptyFrame));
    };
    Ok(if toc & 0x04 != 0 { 2 } else { 1 })
}

fn pcm_f32_to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)).round() as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_pcm_is_archived_as_ogg_opus() {
        let sample_rate = 16_000;
        let samples = (0..sample_rate)
            .map(|index| {
                let phase = index as f32 / sample_rate as f32 * std::f32::consts::TAU * 220.0;
                (phase.sin() * i16::MAX as f32 * 0.2) as i16
            })
            .flat_map(i16::to_le_bytes)
            .collect::<Vec<_>>();
        let audio =
            PcmChunk::from_mono_bytes(sample_rate, crate::pcm::PcmEncoding::S16Le, samples.clone())
                .expect("test PCM should validate");
        let archive = CapturedPcmAudio::new(audio)
            .expect("captured PCM should validate")
            .encode_ogg_opus_archive("test")
            .expect("captured PCM should encode");

        assert!(archive.content.starts_with(b"OggS"));
        assert!(archive.content.len() < samples.len() / 2);
        assert_eq!(archive.original_bytes, samples.len());
        assert_eq!(archive.sample_rate_hz, sample_rate);
    }

    #[test]
    fn ogg_opus_archive_decodes_to_mono_f32() {
        let sample_rate = 16_000;
        let samples = (0..sample_rate / 2)
            .map(|index| {
                let phase = index as f32 / sample_rate as f32 * std::f32::consts::TAU * 440.0;
                (phase.sin() * i16::MAX as f32 * 0.1) as i16
            })
            .flat_map(i16::to_le_bytes)
            .collect::<Vec<_>>();
        let audio = PcmChunk::from_mono_bytes(sample_rate, crate::pcm::PcmEncoding::S16Le, samples)
            .expect("test PCM should validate");
        let archive = CapturedPcmAudio::new(audio)
            .expect("captured PCM should validate")
            .encode_ogg_opus_archive("test")
            .expect("captured PCM should encode");
        let decoded = OggOpusMonoAudio::decode(&archive.content, sample_rate)
            .expect("Ogg Opus should decode");

        assert_eq!(decoded.input_channels, 1);
        assert_eq!(decoded.sample_rate_hz, sample_rate);
        assert!(!decoded.samples.is_empty());
        assert!(decoded.source_pcm_bytes > 0);
    }

    #[test]
    fn discord_packet_batch_encodes_frames_in_one_slab() {
        let sample_rate =
            std::num::NonZeroU32::new(discord::SAMPLE_RATE_HZ).expect("sample rate is nonzero");
        let mut encoder = discord::PcmEncoder::<crate::pcm::F32, crate::pcm::Mono>::new(
            sample_rate,
            discord::EncodeConfig::default(),
        )
        .expect("encoder should initialize");
        let samples = vec![0.0; discord::SAMPLES_PER_CHANNEL];
        let batch = encoder
            .push_packet_batch(&samples)
            .expect("PCM should encode");

        assert_eq!(batch.len(), 1);
        assert_eq!(batch.spans().len(), 1);
        assert!(!batch.bytes().is_empty());
        let packet = batch.iter().next().expect("packet should be present");
        assert_eq!(packet.bytes(), batch.bytes());
        assert_eq!(packet.duration(), discord::BLOCK_DURATION);
        assert_eq!(batch.into_packets().len(), 1);
    }

    #[test]
    fn discord_packet_accepts_one_20ms_opus_packet() {
        let packet =
            discord::Packet::from_bytes(vec![0xf8, 0xff, 0xfe]).expect("silence frame is 20 ms");

        assert_eq!(packet.duration(), discord::BLOCK_DURATION);
    }

    #[test]
    fn discord_packet_rejects_non_20ms_opus_packet() {
        assert!(discord::Packet::from_bytes(vec![0xf0]).is_err());
    }
}
