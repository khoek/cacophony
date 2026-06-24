use std::{io::Cursor, marker::PhantomData};

use ogg::{PacketWriteEndInfo, PacketWriter};
use opus_rs::{
    Application as RawOpusApplication, OpusDecoder as RawOpusDecoder, OpusEncoder as RawOpusEncoder,
};
use tokio::time::Instant;

use crate::{
    errors::{Error, InvalidInputError, OpusError, OpusOperation, Result},
    media::{
        DecodedFrame, DecodedFrameMetadata, EncryptedMediaCodec, FrameRaw, MediaCodec,
        ReceivedFrame, RtpPayloadCodec,
    },
    observer::DavePendingMediaReason,
    pcm::PcmChunk,
    state::{PendingMediaFrame, PendingMediaPacket},
};

const MILLISECONDS_PER_SECOND: usize = 1_000;
const OPUS_ARCHIVE_CHANNELS: usize = 1;
const OPUS_ARCHIVE_FRAME_MS: u32 = 20;
const OPUS_ARCHIVE_GRANULE_SAMPLE_RATE: u64 = 48_000;
const OGG_OPUS_ARCHIVE_SERIAL: u32 = 0xDEADBEEF;
const OGG_OPUS_ARCHIVE_BITRATE_BPS: i32 = 24_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayloadCodec;

impl RtpPayloadCodec for PayloadCodec {
    const CODEC: MediaCodec = MediaCodec::Opus;
    const DISCORD_PAYLOAD_TYPE: u8 = discord::RTP_PAYLOAD_TYPE;
    const SAMPLE_RATE_HZ: u32 = discord::SAMPLE_RATE_HZ;
}

impl EncryptedMediaCodec for PayloadCodec {
    type DaveCodec = dave::Opus;
}

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
    use std::{
        marker::PhantomData,
        num::{NonZeroU32, NonZeroUsize},
        ops::Range,
        time::Duration,
    };

    use crate::{
        errors::{Error, InvalidInputError, OpusError, OpusOperation, Result},
        media::RtpPayload,
        pcm::{
            ALaw, ChannelLayout, F32, F32Le, Mono, MuLaw, PcmChunk, PcmEncoding, S16Le,
            SampleEncoding, Samples, StereoInterleaved, StreamingSincResampler,
        },
    };
    use opus_rs::{Application as RawOpusApplication, OpusEncoder as RawOpusEncoder};

    use super::{MILLISECONDS_PER_SECOND, PayloadCodec};

    pub const SAMPLE_RATE_HZ: u32 = 48_000;
    pub const CHANNELS: usize = 2;
    pub const BLOCK_DURATION_MS: u64 = 20;
    pub const BLOCK_DURATION: Duration = Duration::from_millis(BLOCK_DURATION_MS);
    pub const SAMPLES_PER_CHANNEL: usize =
        SAMPLE_RATE_HZ as usize * BLOCK_DURATION_MS as usize / MILLISECONDS_PER_SECOND;
    pub const STEREO_SAMPLES_PER_BLOCK: usize = CHANNELS * SAMPLES_PER_CHANNEL;
    pub const MAX_PACKET_BYTES: usize = 4096;
    pub const RTP_PAYLOAD_TYPE: u8 = 120;
    pub const DEFAULT_BITRATE_BPS: u32 = 128_000;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Packet {
        pub bytes: Vec<u8>,
        pub duration: Duration,
    }

    impl RtpPayload for Packet {
        type Codec = PayloadCodec;

        fn bytes(&self) -> &[u8] {
            &self.bytes
        }

        fn duration(&self) -> Duration {
            self.duration
        }

        fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PacketSpan {
        offset: usize,
        len: usize,
        duration: Duration,
    }

    impl PacketSpan {
        pub fn len(self) -> usize {
            self.len
        }

        pub fn is_empty(self) -> bool {
            self.len == 0
        }

        pub fn duration(self) -> Duration {
            self.duration
        }

        pub fn range(self) -> Range<usize> {
            self.offset..self.offset + self.len
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PacketRef<'a> {
        bytes: &'a [u8],
        duration: Duration,
    }

    impl<'a> PacketRef<'a> {
        pub fn bytes(self) -> &'a [u8] {
            self.bytes
        }

        pub fn duration(self) -> Duration {
            self.duration
        }

        pub fn to_packet(self) -> Packet {
            Packet {
                bytes: self.bytes.to_vec(),
                duration: self.duration,
            }
        }
    }

    impl RtpPayload for PacketRef<'_> {
        type Codec = PayloadCodec;

        fn bytes(&self) -> &[u8] {
            self.bytes
        }

        fn duration(&self) -> Duration {
            self.duration
        }

        fn into_bytes(self) -> Vec<u8> {
            self.bytes.to_vec()
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
                duration: span.duration,
            }
        }

        pub fn iter(&self) -> impl ExactSizeIterator<Item = PacketRef<'_>> + '_ {
            self.packets.iter().copied().map(|span| self.packet(span))
        }

        pub fn into_packets(self) -> Vec<Packet> {
            let Self { bytes, packets, .. } = self;
            packets
                .into_iter()
                .map(|span| Packet {
                    bytes: bytes[span.range()].to_vec(),
                    duration: span.duration,
                })
                .collect()
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
            let duration = self.encode_frame_into(block.as_frame(), &mut bytes)?;
            Ok(Packet { bytes, duration })
        }

        pub fn encode_into(&mut self, block: &PcmBlock, output: &mut Vec<u8>) -> Result<Duration> {
            self.encode_frame_into(block.as_frame(), output)
        }

        pub fn encode_frame(&mut self, frame: PcmFrame<'_>) -> Result<Packet> {
            let mut bytes = Vec::with_capacity(MAX_PACKET_BYTES);
            let duration = self.encode_frame_into(frame, &mut bytes)?;
            Ok(Packet { bytes, duration })
        }

        pub fn encode_frame_into(
            &mut self,
            frame: PcmFrame<'_>,
            output: &mut Vec<u8>,
        ) -> Result<Duration> {
            output.resize(MAX_PACKET_BYTES, 0);
            let (written, duration) = self.encode_frame_to_slice(frame, output)?;
            output.truncate(written);
            Ok(duration)
        }

        pub fn encode_to_slice(
            &mut self,
            block: &PcmBlock,
            output: &mut [u8],
        ) -> Result<(usize, Duration)> {
            self.encode_frame_to_slice(block.as_frame(), output)
        }

        pub fn encode_frame_to_slice(
            &mut self,
            frame: PcmFrame<'_>,
            output: &mut [u8],
        ) -> Result<(usize, Duration)> {
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
            Ok((written, BLOCK_DURATION))
        }
    }

    pub trait PacketSink {
        fn encode_packet(
            &mut self,
            encode: impl FnOnce(&mut Vec<u8>) -> Result<Duration>,
        ) -> Result<()>;
    }

    impl PacketSink for Vec<Packet> {
        fn encode_packet(
            &mut self,
            encode: impl FnOnce(&mut Vec<u8>) -> Result<Duration>,
        ) -> Result<()> {
            let mut bytes = Vec::with_capacity(MAX_PACKET_BYTES);
            let duration = encode(&mut bytes)?;
            self.push(Packet { bytes, duration });
            Ok(())
        }
    }

    impl PacketSink for PacketBatch {
        fn encode_packet(
            &mut self,
            encode: impl FnOnce(&mut Vec<u8>) -> Result<Duration>,
        ) -> Result<()> {
            self.scratch.clear();
            let duration = encode(&mut self.scratch)?;
            let offset = self.bytes.len();
            self.bytes.extend_from_slice(&self.scratch);
            self.packets.push(PacketSpan {
                offset,
                len: self.scratch.len(),
                duration,
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
        source_sample_rate_hz: Option<NonZeroU32>,
        source_channels: Option<NonZeroUsize>,
        source_encoding: Option<PcmEncoding>,
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
                source_sample_rate_hz: None,
                source_channels: None,
                source_encoding: None,
                source_pcm_bytes: 0,
                encoder: None,
            }
        }

        pub fn push_chunk_to(
            &mut self,
            chunk: &PcmChunk,
            sink: &mut impl PacketSink,
        ) -> Result<usize> {
            let encoding = chunk.encoding();
            self.accept_format(chunk.sample_rate_hz(), chunk.channels(), encoding)?;
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
            self.source_sample_rate_hz
                .map(NonZeroU32::get)
                .unwrap_or(SAMPLE_RATE_HZ)
        }

        pub fn source_pcm_bytes(&self) -> usize {
            self.source_pcm_bytes
        }

        pub fn source_channel_count(&self) -> usize {
            self.source_channels.map(NonZeroUsize::get).unwrap_or(1)
        }

        pub fn resampling_required(&self) -> bool {
            self.encoder
                .as_ref()
                .is_some_and(DynamicPcmEncoderInner::resampling_required)
        }

        fn accept_format(
            &mut self,
            sample_rate_hz: NonZeroU32,
            channels: NonZeroUsize,
            encoding: PcmEncoding,
        ) -> Result<()> {
            match (
                self.source_sample_rate_hz,
                self.source_channels,
                self.source_encoding,
            ) {
                (None, None, None) => {
                    self.source_sample_rate_hz = Some(sample_rate_hz);
                    self.source_channels = Some(channels);
                    self.source_encoding = Some(encoding);
                    self.encoder = Some(DynamicPcmEncoderInner::new(
                        sample_rate_hz,
                        channels,
                        encoding,
                    )?);
                    Ok(())
                }
                (Some(existing_sample_rate), Some(existing_channels), Some(existing_encoding))
                    if existing_sample_rate == sample_rate_hz
                        && existing_channels == channels
                        && existing_encoding == encoding =>
                {
                    Ok(())
                }
                (Some(existing), Some(_), Some(_)) if existing != sample_rate_hz => Err(
                    Error::InvalidInput(InvalidInputError::DiscordPcmMixedSampleRates {
                        existing: existing.get(),
                        actual: sample_rate_hz.get(),
                    }),
                ),
                (Some(_), Some(existing), Some(_)) if existing != channels => Err(
                    Error::InvalidInput(InvalidInputError::DiscordPcmMixedChannelCounts {
                        existing: existing.get(),
                        actual: channels.get(),
                    }),
                ),
                _ => Err(Error::InvalidInput(
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
        MonoF32Le(PcmEncoder<F32Le, Mono>),
        MonoS16Le(PcmEncoder<S16Le, Mono>),
        MonoMuLaw(PcmEncoder<MuLaw, Mono>),
        MonoALaw(PcmEncoder<ALaw, Mono>),
        StereoF32Le(PcmEncoder<F32Le, StereoInterleaved>),
        StereoS16Le(PcmEncoder<S16Le, StereoInterleaved>),
        StereoMuLaw(PcmEncoder<MuLaw, StereoInterleaved>),
        StereoALaw(PcmEncoder<ALaw, StereoInterleaved>),
    }

    macro_rules! with_dynamic_pcm_encoder {
        ($encoder:expr, $binding:ident => $body:expr) => {
            match $encoder {
                DynamicPcmEncoderInner::MonoF32Le($binding) => $body,
                DynamicPcmEncoderInner::MonoS16Le($binding) => $body,
                DynamicPcmEncoderInner::MonoMuLaw($binding) => $body,
                DynamicPcmEncoderInner::MonoALaw($binding) => $body,
                DynamicPcmEncoderInner::StereoF32Le($binding) => $body,
                DynamicPcmEncoderInner::StereoS16Le($binding) => $body,
                DynamicPcmEncoderInner::StereoMuLaw($binding) => $body,
                DynamicPcmEncoderInner::StereoALaw($binding) => $body,
            }
        };
    }

    impl DynamicPcmEncoderInner {
        fn new(
            sample_rate_hz: NonZeroU32,
            channels: NonZeroUsize,
            encoding: PcmEncoding,
        ) -> Result<Self> {
            match channels.get() {
                1 => Self::mono(sample_rate_hz, encoding),
                2 => Self::stereo(sample_rate_hz, encoding),
                channels => Err(Error::Opus(OpusError::UnsupportedChannelCount { channels })),
            }
        }

        fn mono(sample_rate_hz: NonZeroU32, encoding: PcmEncoding) -> Result<Self> {
            Ok(match encoding {
                PcmEncoding::F32Le => {
                    Self::MonoF32Le(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
                PcmEncoding::S16Le => {
                    Self::MonoS16Le(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
                PcmEncoding::MuLaw => {
                    Self::MonoMuLaw(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
                PcmEncoding::ALaw => {
                    Self::MonoALaw(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
            })
        }

        fn stereo(sample_rate_hz: NonZeroU32, encoding: PcmEncoding) -> Result<Self> {
            Ok(match encoding {
                PcmEncoding::F32Le => {
                    Self::StereoF32Le(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
                PcmEncoding::S16Le => {
                    Self::StereoS16Le(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
                PcmEncoding::MuLaw => {
                    Self::StereoMuLaw(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
                PcmEncoding::ALaw => {
                    Self::StereoALaw(PcmEncoder::new(sample_rate_hz, EncodeConfig::default())?)
                }
            })
        }

        fn push(&mut self, data: &[u8], sink: &mut impl PacketSink) -> Result<usize> {
            with_dynamic_pcm_encoder!(self, encoder => encoder.push_to(data, sink))
        }

        fn finish(&mut self, sink: &mut impl PacketSink) -> Result<usize> {
            with_dynamic_pcm_encoder!(self, encoder => encoder.finish_to(sink))
        }

        fn resampling_required(&self) -> bool {
            with_dynamic_pcm_encoder!(self, encoder => encoder.resampling_required())
        }
    }

    pub struct PlaybackAudio {
        packets: Vec<Packet>,
        source_sample_rate_hz: u32,
        source_channel_count: u32,
        source_pcm_bytes: usize,
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
                source_sample_rate_hz: encoder.source_sample_rate_hz(),
                source_channel_count: encoder.source_channel_count() as u32,
                source_pcm_bytes: encoder.source_pcm_bytes(),
            })
        }

        pub fn from_mono_samples(
            samples: &[f32],
            source_sample_rate_hz: u32,
            source_channel_count: u32,
            source_pcm_bytes: usize,
        ) -> Result<Self> {
            let sample_rate_hz = NonZeroU32::new(source_sample_rate_hz)
                .ok_or(crate::errors::PcmError::SampleRateZero)?;
            Ok(Self {
                packets: PcmEncoder::<F32, Mono>::encode_all(
                    sample_rate_hz,
                    samples,
                    EncodeConfig::default(),
                )?,
                source_sample_rate_hz,
                source_channel_count,
                source_pcm_bytes,
            })
        }

        pub fn packets(&self) -> &[Packet] {
            &self.packets
        }

        pub fn clone_packets(&self) -> Vec<Packet> {
            self.packets.clone()
        }

        pub fn source_sample_rate_hz(&self) -> u32 {
            self.source_sample_rate_hz
        }

        pub fn source_channel_count(&self) -> u32 {
            self.source_channel_count
        }

        pub fn source_pcm_bytes(&self) -> usize {
            self.source_pcm_bytes
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
            sample_rate: metadata.sample_rate,
            channels: metadata.channels,
            samples_per_channel: metadata.samples_per_channel,
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
        if frame.codec != MediaCodec::Opus {
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
            sample_rate: self.sample_rate,
            channels: discord::CHANNELS,
            samples_per_channel,
        })
    }
}

pub(crate) struct RtpFrameAssembler<Raw>
where
    Raw: FrameRaw,
{
    _raw: PhantomData<Raw>,
}

impl<Raw> Default for RtpFrameAssembler<Raw>
where
    Raw: FrameRaw,
{
    fn default() -> Self {
        Self { _raw: PhantomData }
    }
}

impl<Raw> RtpFrameAssembler<Raw>
where
    Raw: FrameRaw,
{
    pub(crate) fn push_packet(
        &mut self,
        packet: PendingMediaPacket<Raw>,
    ) -> Option<PendingMediaFrame<Raw>> {
        Some(PendingMediaFrame {
            raw: Raw::from_rtp_packet::<PayloadCodec>(packet.raw),
            rtp: packet.rtp,
            user_id: packet.user_id,
            codec: packet.codec,
            encrypted_frame: packet.encrypted_payload,
            dave: packet.dave,
            enqueued_at: Instant::now(),
            reason: DavePendingMediaReason::DecryptStatePending,
            was_pending: false,
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
}
