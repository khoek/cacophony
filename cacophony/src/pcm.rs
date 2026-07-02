use std::{
    marker::PhantomData,
    num::{NonZeroU32, NonZeroUsize},
    str::FromStr,
    sync::Arc,
};

use rubato::{
    Async, FixedAsync, Indexing, Resampler, SincInterpolationParameters, SincInterpolationType,
    WindowFunction, audioadapter_buffers::direct::SequentialSliceOfVecs,
};

use crate::{
    errors::{Error, PcmError, Result},
    media::{DecodedFrame, FrameRaw},
};

const SINC_FILTER_LEN: usize = 256;
const SINC_OVERSAMPLING_FACTOR: usize = 256;
const SINC_CUTOFF: f32 = 0.95;
const SINC_MAX_RELATIVE_RATIO: f64 = 1.0;
const SOURCE_BUFFER_COMPACT_FRAMES: usize = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcmEncoding {
    F32Le,
    S16Le,
    MuLaw,
    ALaw,
}

#[derive(Clone, Copy)]
struct PcmEncodingDescriptor {
    encoding: PcmEncoding,
    wire_name: &'static str,
    sample_encoding_name: &'static str,
    bytes_per_sample: usize,
}

const PCM_F32LE: PcmEncodingDescriptor = PcmEncodingDescriptor {
    encoding: PcmEncoding::F32Le,
    wire_name: "pcm_f32le",
    sample_encoding_name: F32Le::NAME,
    bytes_per_sample: std::mem::size_of::<f32>(),
};

const PCM_S16LE: PcmEncodingDescriptor = PcmEncodingDescriptor {
    encoding: PcmEncoding::S16Le,
    wire_name: "pcm_s16le",
    sample_encoding_name: S16Le::NAME,
    bytes_per_sample: std::mem::size_of::<i16>(),
};

const PCM_MULAW: PcmEncodingDescriptor = PcmEncodingDescriptor {
    encoding: PcmEncoding::MuLaw,
    wire_name: "pcm_mulaw",
    sample_encoding_name: MuLaw::NAME,
    bytes_per_sample: 1,
};

const PCM_ALAW: PcmEncodingDescriptor = PcmEncodingDescriptor {
    encoding: PcmEncoding::ALaw,
    wire_name: "pcm_alaw",
    sample_encoding_name: ALaw::NAME,
    bytes_per_sample: 1,
};

const PCM_ENCODINGS: [&PcmEncodingDescriptor; 4] = [&PCM_F32LE, &PCM_S16LE, &PCM_MULAW, &PCM_ALAW];

impl PcmEncoding {
    pub fn parse(value: &str) -> Result<Self> {
        value.parse().map_err(Error::from)
    }

    pub const fn as_str(self) -> &'static str {
        self.descriptor().wire_name
    }

    pub const fn sample_encoding_name(self) -> &'static str {
        self.descriptor().sample_encoding_name
    }

    pub const fn bytes_per_sample(self) -> usize {
        self.descriptor().bytes_per_sample
    }

    pub fn append_f32(self, data: &[u8], output: &mut Vec<f32>) -> Result<()> {
        self.visit(AppendPcmF32 { data, output })
    }

    const fn descriptor(self) -> &'static PcmEncodingDescriptor {
        match self {
            Self::F32Le => &PCM_F32LE,
            Self::S16Le => &PCM_S16LE,
            Self::MuLaw => &PCM_MULAW,
            Self::ALaw => &PCM_ALAW,
        }
    }

    fn visit<V>(self, visitor: V) -> V::Output
    where
        V: PcmEncodingVisitor,
    {
        match self {
            Self::F32Le => visitor.visit::<F32Le>(),
            Self::S16Le => visitor.visit::<S16Le>(),
            Self::MuLaw => visitor.visit::<MuLaw>(),
            Self::ALaw => visitor.visit::<ALaw>(),
        }
    }
}

impl FromStr for PcmEncoding {
    type Err = PcmError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        for descriptor in PCM_ENCODINGS {
            if value == descriptor.wire_name {
                return Ok(descriptor.encoding);
            }
        }
        Err(PcmError::UnsupportedEncoding(value.to_string()))
    }
}

impl std::fmt::Display for PcmEncoding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmFormat {
    sample_rate_hz: NonZeroU32,
    channels: NonZeroUsize,
    encoding: PcmEncoding,
}

impl PcmFormat {
    pub const fn new(
        sample_rate_hz: NonZeroU32,
        channels: NonZeroUsize,
        encoding: PcmEncoding,
    ) -> Self {
        Self {
            sample_rate_hz,
            channels,
            encoding,
        }
    }

    pub fn from_parts(sample_rate_hz: u32, channels: usize, encoding: PcmEncoding) -> Result<Self> {
        Ok(Self::new(
            NonZeroU32::new(sample_rate_hz).ok_or(PcmError::SampleRateZero)?,
            NonZeroUsize::new(channels).ok_or(PcmError::ChannelCountZero)?,
            encoding,
        ))
    }

    pub fn mono(sample_rate_hz: NonZeroU32, encoding: PcmEncoding) -> Self {
        Self::new(
            sample_rate_hz,
            NonZeroUsize::new(1).expect("mono channel count is nonzero"),
            encoding,
        )
    }

    pub const fn sample_rate_hz(self) -> NonZeroU32 {
        self.sample_rate_hz
    }

    pub const fn channels(self) -> NonZeroUsize {
        self.channels
    }

    pub const fn encoding(self) -> PcmEncoding {
        self.encoding
    }

    fn validate_bytes(self, byte_len: usize) -> Result<()> {
        validate_pcm_bytes(self.encoding, byte_len, self.channels.get())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcmChunk {
    format: PcmFormat,
    data: Arc<[u8]>,
}

impl PcmChunk {
    pub fn new(
        sample_rate_hz: NonZeroU32,
        channels: NonZeroUsize,
        encoding: PcmEncoding,
        data: impl Into<Arc<[u8]>>,
    ) -> Result<Self> {
        Self::with_format(PcmFormat::new(sample_rate_hz, channels, encoding), data)
    }

    pub fn with_format(format: PcmFormat, data: impl Into<Arc<[u8]>>) -> Result<Self> {
        let data = data.into();
        format.validate_bytes(data.len())?;
        Ok(Self { format, data })
    }

    pub fn from_bytes(
        sample_rate_hz: u32,
        channels: usize,
        encoding: PcmEncoding,
        data: impl Into<Arc<[u8]>>,
    ) -> Result<Self> {
        Self::with_format(
            PcmFormat::from_parts(sample_rate_hz, channels, encoding)?,
            data,
        )
    }

    pub fn new_mono(
        sample_rate_hz: NonZeroU32,
        encoding: PcmEncoding,
        data: impl Into<Arc<[u8]>>,
    ) -> Result<Self> {
        Self::with_format(PcmFormat::mono(sample_rate_hz, encoding), data)
    }

    pub fn from_mono_bytes(
        sample_rate_hz: u32,
        encoding: PcmEncoding,
        data: impl Into<Arc<[u8]>>,
    ) -> Result<Self> {
        Self::from_bytes(sample_rate_hz, 1, encoding, data)
    }

    pub const fn sample_rate_hz(&self) -> NonZeroU32 {
        self.format.sample_rate_hz()
    }

    pub const fn channels(&self) -> NonZeroUsize {
        self.format.channels()
    }

    pub const fn encoding(&self) -> PcmEncoding {
        self.format.encoding()
    }

    pub const fn format(&self) -> PcmFormat {
        self.format
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn data_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.data)
    }

    pub fn into_data(self) -> Arc<[u8]> {
        self.data
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.data.len()
    }

    pub fn sample_count(&self) -> usize {
        self.data.len() / self.format.encoding().bytes_per_sample()
    }

    pub fn frame_count(&self) -> usize {
        self.sample_count() / self.format.channels().get()
    }

    pub fn append_f32(&self, output: &mut Vec<f32>) -> Result<usize> {
        let start = output.len();
        output.reserve(self.sample_count());
        self.format.encoding().append_f32(&self.data, output)?;
        let samples = output.len() - start;
        validate_channel_alignment(self.format.channels().get(), samples)?;
        Ok(samples / self.format.channels().get())
    }
}

impl AsRef<[u8]> for PcmChunk {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

pub trait SampleEncoding: Copy + Send + Sync + 'static {
    const NAME: &'static str;
}

pub trait ByteSampleEncoding: SampleEncoding {
    const BYTES_PER_SAMPLE: usize;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct F32;

impl SampleEncoding for F32 {
    const NAME: &'static str = "f32";
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct F32Le;

impl SampleEncoding for F32Le {
    const NAME: &'static str = "f32le";
}

impl ByteSampleEncoding for F32Le {
    const BYTES_PER_SAMPLE: usize = std::mem::size_of::<f32>();
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct S16;

impl SampleEncoding for S16 {
    const NAME: &'static str = "s16";
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct S16Le;

impl SampleEncoding for S16Le {
    const NAME: &'static str = "s16le";
}

impl ByteSampleEncoding for S16Le {
    const BYTES_PER_SAMPLE: usize = std::mem::size_of::<i16>();
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MuLaw;

impl SampleEncoding for MuLaw {
    const NAME: &'static str = "mulaw";
}

impl ByteSampleEncoding for MuLaw {
    const BYTES_PER_SAMPLE: usize = 1;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ALaw;

impl SampleEncoding for ALaw {
    const NAME: &'static str = "alaw";
}

impl ByteSampleEncoding for ALaw {
    const BYTES_PER_SAMPLE: usize = 1;
}

trait RuntimePcmEncoding: ByteSampleEncoding {
    fn append_f32(data: &[u8], output: &mut Vec<f32>) -> Result<()>;
}

impl RuntimePcmEncoding for F32Le {
    fn append_f32(data: &[u8], output: &mut Vec<f32>) -> Result<()> {
        Samples::<Self>::append_f32(&data, output)
    }
}

impl RuntimePcmEncoding for S16Le {
    fn append_f32(data: &[u8], output: &mut Vec<f32>) -> Result<()> {
        Samples::<Self>::append_f32(&data, output)
    }
}

impl RuntimePcmEncoding for MuLaw {
    fn append_f32(data: &[u8], output: &mut Vec<f32>) -> Result<()> {
        Samples::<Self>::append_f32(&data, output)
    }
}

impl RuntimePcmEncoding for ALaw {
    fn append_f32(data: &[u8], output: &mut Vec<f32>) -> Result<()> {
        Samples::<Self>::append_f32(&data, output)
    }
}

trait PcmEncodingVisitor {
    type Output;

    fn visit<E>(self) -> Self::Output
    where
        E: RuntimePcmEncoding;
}

struct AppendPcmF32<'data, 'output> {
    data: &'data [u8],
    output: &'output mut Vec<f32>,
}

impl PcmEncodingVisitor for AppendPcmF32<'_, '_> {
    type Output = Result<()>;

    fn visit<E>(self) -> Self::Output
    where
        E: RuntimePcmEncoding,
    {
        E::append_f32(self.data, self.output)
    }
}

struct CheckedPcmByteSampleCount {
    byte_len: usize,
}

impl PcmEncodingVisitor for CheckedPcmByteSampleCount {
    type Output = Result<usize>;

    fn visit<E>(self) -> Self::Output
    where
        E: RuntimePcmEncoding,
    {
        checked_byte_sample_count::<E>(self.byte_len)
    }
}

pub trait Samples<E>
where
    E: SampleEncoding,
{
    fn sample_count(&self) -> Result<usize>;
    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()>;
}

impl<T> Samples<F32> for T
where
    T: AsRef<[f32]>,
{
    fn sample_count(&self) -> Result<usize> {
        Ok(self.as_ref().len())
    }

    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()> {
        let samples = self.as_ref();
        output.reserve(samples.len());
        output.extend(samples.iter().map(|sample| sample.clamp(-1.0, 1.0)));
        Ok(())
    }
}

impl<T> Samples<S16> for T
where
    T: AsRef<[i16]>,
{
    fn sample_count(&self) -> Result<usize> {
        Ok(self.as_ref().len())
    }

    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()> {
        let samples = self.as_ref();
        output.reserve(samples.len());
        output.extend(samples.iter().map(|sample| s16_to_f32(*sample)));
        Ok(())
    }
}

impl<T> Samples<F32Le> for T
where
    T: AsRef<[u8]>,
{
    fn sample_count(&self) -> Result<usize> {
        checked_byte_sample_count::<F32Le>(self.as_ref().len())
    }

    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()> {
        let bytes = self.as_ref();
        let samples = checked_byte_sample_count::<F32Le>(bytes.len())?;
        output.reserve(samples);
        output.extend(bytes.chunks_exact(4).map(|sample| {
            f32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]).clamp(-1.0, 1.0)
        }));
        Ok(())
    }
}

impl<T> Samples<S16Le> for T
where
    T: AsRef<[u8]>,
{
    fn sample_count(&self) -> Result<usize> {
        checked_byte_sample_count::<S16Le>(self.as_ref().len())
    }

    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()> {
        let bytes = self.as_ref();
        let samples = checked_byte_sample_count::<S16Le>(bytes.len())?;
        output.reserve(samples);
        output.extend(
            bytes
                .chunks_exact(2)
                .map(|sample| s16_to_f32(i16::from_le_bytes([sample[0], sample[1]]))),
        );
        Ok(())
    }
}

impl<T> Samples<MuLaw> for T
where
    T: AsRef<[u8]>,
{
    fn sample_count(&self) -> Result<usize> {
        Ok(self.as_ref().len())
    }

    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()> {
        let samples = self.as_ref();
        output.reserve(samples.len());
        output.extend(
            samples
                .iter()
                .copied()
                .map(|sample| s16_to_f32(decode_mulaw(sample))),
        );
        Ok(())
    }
}

impl<T> Samples<ALaw> for T
where
    T: AsRef<[u8]>,
{
    fn sample_count(&self) -> Result<usize> {
        Ok(self.as_ref().len())
    }

    fn append_f32(&self, output: &mut Vec<f32>) -> Result<()> {
        let samples = self.as_ref();
        output.reserve(samples.len());
        output.extend(
            samples
                .iter()
                .copied()
                .map(|sample| s16_to_f32(decode_alaw(sample))),
        );
        Ok(())
    }
}

pub trait ChannelLayout: Copy + Send + Sync + 'static {
    const CHANNELS: usize;

    fn append_source_f32<E, S>(samples: &S, output: &mut Vec<f32>) -> Result<usize>
    where
        E: SampleEncoding,
        S: Samples<E> + ?Sized;

    fn append_stereo_interleaved_from_source<E, S>(
        samples: &S,
        output: &mut Vec<f32>,
    ) -> Result<usize>
    where
        E: SampleEncoding,
        S: Samples<E> + ?Sized;

    fn append_stereo_interleaved(samples: &[f32], output: &mut Vec<f32>) -> Result<usize>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mono;

impl ChannelLayout for Mono {
    const CHANNELS: usize = 1;

    fn append_source_f32<E, S>(samples: &S, output: &mut Vec<f32>) -> Result<usize>
    where
        E: SampleEncoding,
        S: Samples<E> + ?Sized,
    {
        let start = output.len();
        samples.append_f32(output)?;
        Ok(output.len() - start)
    }

    fn append_stereo_interleaved_from_source<E, S>(
        samples: &S,
        output: &mut Vec<f32>,
    ) -> Result<usize>
    where
        E: SampleEncoding,
        S: Samples<E> + ?Sized,
    {
        let start = output.len();
        let frames = Self::append_source_f32::<E, _>(samples, output)?;
        output.resize(start + frames * 2, 0.0);
        for index in (0..frames).rev() {
            let sample = output[start + index];
            output[start + index * 2] = sample;
            output[start + index * 2 + 1] = sample;
        }
        Ok(frames)
    }

    fn append_stereo_interleaved(samples: &[f32], output: &mut Vec<f32>) -> Result<usize> {
        output.reserve(samples.len() * 2);
        for sample in samples {
            output.extend_from_slice(&[*sample, *sample]);
        }
        Ok(samples.len())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StereoInterleaved;

impl ChannelLayout for StereoInterleaved {
    const CHANNELS: usize = 2;

    fn append_source_f32<E, S>(samples: &S, output: &mut Vec<f32>) -> Result<usize>
    where
        E: SampleEncoding,
        S: Samples<E> + ?Sized,
    {
        let sample_count = samples.sample_count()?;
        validate_channel_alignment(Self::CHANNELS, sample_count)?;
        samples.append_f32(output)?;
        Ok(sample_count / Self::CHANNELS)
    }

    fn append_stereo_interleaved_from_source<E, S>(
        samples: &S,
        output: &mut Vec<f32>,
    ) -> Result<usize>
    where
        E: SampleEncoding,
        S: Samples<E> + ?Sized,
    {
        Self::append_source_f32::<E, _>(samples, output)
    }

    fn append_stereo_interleaved(samples: &[f32], output: &mut Vec<f32>) -> Result<usize> {
        validate_channel_alignment(Self::CHANNELS, samples.len())?;
        output.extend_from_slice(samples);
        Ok(samples.len() / Self::CHANNELS)
    }
}

pub struct StreamingSincResampler<L>
where
    L: ChannelLayout,
{
    input_sample_rate_hz: NonZeroU32,
    output_sample_rate_hz: NonZeroU32,
    ratio: f64,
    resampler: Option<Async<f32>>,
    buffered_source: Vec<Vec<f32>>,
    buffered_source_start: usize,
    received_source_frames: usize,
    emitted_output_frames: usize,
    trim_output_frames: usize,
    input_scratch: Vec<Vec<f32>>,
    output_scratch: Vec<Vec<f32>>,
    _layout: PhantomData<L>,
}

pub type MonoSincResampler = StreamingSincResampler<Mono>;

impl<L> StreamingSincResampler<L>
where
    L: ChannelLayout,
{
    pub fn from_hz(
        input_sample_rate_hz: u32,
        output_sample_rate_hz: u32,
        chunk_frames: usize,
    ) -> Result<Self> {
        Self::new(
            NonZeroU32::new(input_sample_rate_hz).ok_or(PcmError::SampleRateZero)?,
            NonZeroU32::new(output_sample_rate_hz).ok_or(PcmError::SampleRateZero)?,
            chunk_frames,
        )
    }

    pub fn new(
        input_sample_rate_hz: NonZeroU32,
        output_sample_rate_hz: NonZeroU32,
        chunk_frames: usize,
    ) -> Result<Self> {
        if L::CHANNELS == 0 {
            return Err(PcmError::ChannelCountZero.into());
        }
        if chunk_frames == 0 {
            return Err(PcmError::ResamplerChunkFramesZero.into());
        }
        let ratio = f64::from(output_sample_rate_hz.get()) / f64::from(input_sample_rate_hz.get());
        let resampler = if input_sample_rate_hz == output_sample_rate_hz {
            None
        } else {
            Some(high_quality_sinc_resampler(
                input_sample_rate_hz,
                output_sample_rate_hz,
                chunk_frames,
                L::CHANNELS,
            )?)
        };
        let trim_output_frames = resampler
            .as_ref()
            .map(Resampler::output_delay)
            .unwrap_or_default();
        Ok(Self {
            input_sample_rate_hz,
            output_sample_rate_hz,
            ratio,
            resampler,
            buffered_source: vec![Vec::new(); L::CHANNELS],
            buffered_source_start: 0,
            received_source_frames: 0,
            emitted_output_frames: 0,
            trim_output_frames,
            input_scratch: vec![Vec::new(); L::CHANNELS],
            output_scratch: vec![Vec::new(); L::CHANNELS],
            _layout: PhantomData,
        })
    }

    pub fn resampling_required(&self) -> bool {
        self.input_sample_rate_hz != self.output_sample_rate_hz
    }

    pub const fn input_sample_rate_hz(&self) -> NonZeroU32 {
        self.input_sample_rate_hz
    }

    pub const fn output_sample_rate_hz(&self) -> NonZeroU32 {
        self.output_sample_rate_hz
    }

    pub fn push(&mut self, samples: &[f32]) -> Result<Vec<f32>> {
        let mut output = Vec::new();
        self.push_into(samples, &mut output)?;
        Ok(output)
    }

    pub fn push_into(&mut self, samples: &[f32], output: &mut Vec<f32>) -> Result<()> {
        let frames = self.validate_source_samples(samples)?;
        self.received_source_frames += frames;
        if !self.resampling_required() {
            self.emitted_output_frames += frames;
            output.extend_from_slice(samples);
            return Ok(());
        }
        self.append_buffered_source(samples);
        self.process_available(None, output)
    }

    pub fn finish(&mut self) -> Result<Vec<f32>> {
        let mut output = Vec::new();
        self.finish_into(&mut output)?;
        Ok(output)
    }

    pub fn finish_into(&mut self, output: &mut Vec<f32>) -> Result<()> {
        if !self.resampling_required() {
            return Ok(());
        }
        let expected_output_frames =
            (self.ratio * self.received_source_frames as f64).ceil() as usize;
        self.process_available(Some(expected_output_frames), output)
    }

    fn validate_source_samples(&self, samples: &[f32]) -> Result<usize> {
        validate_channel_alignment(L::CHANNELS, samples.len())?;
        Ok(samples.len() / L::CHANNELS)
    }

    fn append_buffered_source(&mut self, samples: &[f32]) {
        self.compact_buffered_source();
        for frame in samples.chunks_exact(L::CHANNELS) {
            for (channel, sample) in frame.iter().enumerate() {
                self.buffered_source[channel].push(*sample);
            }
        }
    }

    fn buffered_source_frames(&self) -> usize {
        self.buffered_source
            .first()
            .map(|samples| samples.len().saturating_sub(self.buffered_source_start))
            .unwrap_or_default()
    }

    fn compact_buffered_source(&mut self) {
        if self.buffered_source_start == 0 {
            return;
        }
        if self.buffered_source_frames() == 0 {
            for samples in &mut self.buffered_source {
                samples.clear();
            }
            self.buffered_source_start = 0;
            return;
        }
        if self.buffered_source_start < SOURCE_BUFFER_COMPACT_FRAMES {
            return;
        }
        for samples in &mut self.buffered_source {
            let keep = samples.len() - self.buffered_source_start;
            samples.copy_within(self.buffered_source_start.., 0);
            samples.truncate(keep);
        }
        self.buffered_source_start = 0;
    }

    fn process_available(
        &mut self,
        expected_output_frames: Option<usize>,
        output: &mut Vec<f32>,
    ) -> Result<()> {
        while self.buffered_source_frames() >= self.resampler()?.input_frames_next() {
            self.process_next_chunk(None, expected_output_frames, output)?;
            if self.reached_expected_output(expected_output_frames) {
                return Ok(());
            }
        }
        if let Some(expected_output_frames) = expected_output_frames {
            let buffered_frames = self.buffered_source_frames();
            if buffered_frames > 0 {
                self.process_next_chunk(
                    Some(buffered_frames),
                    Some(expected_output_frames),
                    output,
                )?;
            }
            while self.emitted_output_frames < expected_output_frames {
                self.process_next_chunk(Some(0), Some(expected_output_frames), output)?;
            }
        }
        Ok(())
    }

    fn process_next_chunk(
        &mut self,
        partial_len: Option<usize>,
        expected_output_frames: Option<usize>,
        output: &mut Vec<f32>,
    ) -> Result<()> {
        let input_frames = self.resampler()?.input_frames_next();
        let output_frames = self.resampler()?.output_frames_next();
        let valid_input = partial_len.unwrap_or(input_frames);
        resize_channels(&mut self.input_scratch, input_frames);
        for (channel, samples) in self.input_scratch.iter_mut().enumerate() {
            if valid_input < input_frames {
                samples[valid_input..].fill(0.0);
            }
            if valid_input > 0 {
                let start = self.buffered_source_start;
                samples[..valid_input]
                    .copy_from_slice(&self.buffered_source[channel][start..start + valid_input]);
            }
        }
        resize_channels(&mut self.output_scratch, output_frames);
        let indexing = partial_len.map(|partial_len| Indexing {
            input_offset: 0,
            output_offset: 0,
            partial_len: Some(partial_len),
            active_channels_mask: None,
        });
        let (consumed, written) = {
            let input = SequentialSliceOfVecs::new(&self.input_scratch, L::CHANNELS, input_frames)
                .map_err(pcm_resampler_error)?;
            let mut resampled = SequentialSliceOfVecs::new_mut(
                &mut self.output_scratch,
                L::CHANNELS,
                output_frames,
            )
            .map_err(pcm_resampler_error)?;
            self.resampler
                .as_mut()
                .ok_or(PcmError::ResamplerNotInitialized)?
                .process_into_buffer(&input, &mut resampled, indexing.as_ref())
                .map_err(pcm_resampler_error)?
        };
        if partial_len.is_none() {
            self.buffered_source_start += consumed;
            self.compact_buffered_source();
        } else {
            for samples in &mut self.buffered_source {
                samples.clear();
            }
            self.buffered_source_start = 0;
        }
        self.append_output_samples(written, expected_output_frames, output);
        Ok(())
    }

    fn append_output_samples(
        &mut self,
        written: usize,
        expected_output_frames: Option<usize>,
        output: &mut Vec<f32>,
    ) {
        let trim = self.trim_output_frames.min(written);
        self.trim_output_frames -= trim;
        for frame in trim..written {
            if self.reached_expected_output(expected_output_frames) {
                break;
            }
            for channel_samples in self.output_scratch.iter().take(L::CHANNELS) {
                output.push(channel_samples[frame].clamp(-1.0, 1.0));
            }
            self.emitted_output_frames += 1;
        }
    }

    fn reached_expected_output(&self, expected_output_frames: Option<usize>) -> bool {
        expected_output_frames.is_some_and(|expected| self.emitted_output_frames >= expected)
    }

    fn resampler(&self) -> Result<&Async<f32>> {
        self.resampler
            .as_ref()
            .ok_or(PcmError::ResamplerNotInitialized.into())
    }
}

pub fn s16_to_f32(sample: i16) -> f32 {
    if sample < 0 {
        sample as f32 / 32768.0
    } else {
        sample as f32 / 32767.0
    }
}

pub fn f32_to_s16(sample: f32) -> i16 {
    let sample = sample.clamp(-1.0, 1.0);
    if sample < 0.0 {
        (sample * 32768.0).round() as i16
    } else {
        (sample * 32767.0).round() as i16
    }
}

pub fn decode_mulaw(sample: u8) -> i16 {
    const BIAS: i32 = 0x84;

    let sample = !sample;
    let magnitude = ((((sample & 0x0f) as i32) << 3) + BIAS) << ((sample & 0x70) >> 4);
    let decoded = if sample & 0x80 == 0 {
        magnitude - BIAS
    } else {
        BIAS - magnitude
    };
    decoded.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

pub fn decode_alaw(sample: u8) -> i16 {
    let sample = sample ^ 0x55;
    let segment = (sample & 0x70) >> 4;
    let mut magnitude = ((sample & 0x0f) as i32) << 4;
    if segment == 0 {
        magnitude += 8;
    } else {
        magnitude += 0x108;
        if segment > 1 {
            magnitude <<= segment - 1;
        }
    }
    let decoded = if sample & 0x80 == 0 {
        -magnitude
    } else {
        magnitude
    };
    decoded.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

impl<Raw> DecodedFrame<Raw>
where
    Raw: FrameRaw,
{
    pub fn to_mono_s16le_bytes(&self) -> Result<Vec<u8>> {
        interleaved_i16_to_mono_s16le(&self.pcm, self.pcm_layout.channels)
    }
}

pub fn interleaved_i16_to_mono_s16le(samples: &[i16], channels: usize) -> Result<Vec<u8>> {
    NonZeroUsize::new(channels).ok_or(PcmError::ChannelCountZero)?;
    validate_channel_alignment(channels, samples.len())?;
    let mut mono = Vec::with_capacity(samples.len() / channels * std::mem::size_of::<i16>());
    for frame in samples.chunks_exact(channels) {
        let summed = frame.iter().map(|sample| i32::from(*sample)).sum::<i32>();
        let clamped = (summed / channels as i32).clamp(i32::from(i16::MIN), i32::from(i16::MAX));
        mono.extend((clamped as i16).to_le_bytes());
    }
    Ok(mono)
}

pub fn s16le_rms(samples: &[u8]) -> Result<f32> {
    checked_byte_sample_count::<S16Le>(samples.len())?;
    let mut square_sum = 0_f64;
    let mut count = 0_u64;
    for sample in samples.chunks_exact(2) {
        let sample = f64::from(i16::from_le_bytes([sample[0], sample[1]]));
        square_sum += sample * sample;
        count += 1;
    }
    Ok(if count == 0 {
        0.0
    } else {
        (square_sum / count as f64).sqrt() as f32
    })
}

pub fn validate_channel_alignment(channels: usize, samples: usize) -> Result<()> {
    if channels == 0 {
        return Err(PcmError::ChannelCountZero.into());
    }
    if !samples.is_multiple_of(channels) {
        return Err(PcmError::ChannelAlignment { channels, samples }.into());
    }
    Ok(())
}

pub fn checked_byte_sample_count<E>(byte_len: usize) -> Result<usize>
where
    E: ByteSampleEncoding,
{
    if !byte_len.is_multiple_of(E::BYTES_PER_SAMPLE) {
        return Err(PcmError::SampleAlignment {
            encoding: E::NAME,
            byte_len,
            sample_bytes: E::BYTES_PER_SAMPLE,
        }
        .into());
    }
    Ok(byte_len / E::BYTES_PER_SAMPLE)
}

fn validate_pcm_bytes(encoding: PcmEncoding, byte_len: usize, channels: usize) -> Result<()> {
    let sample_count = encoding.visit(CheckedPcmByteSampleCount { byte_len })?;
    validate_channel_alignment(channels, sample_count)
}

fn high_quality_sinc_resampler(
    input_sample_rate_hz: NonZeroU32,
    output_sample_rate_hz: NonZeroU32,
    chunk_frames: usize,
    channels: usize,
) -> Result<Async<f32>> {
    Async::<f32>::new_sinc(
        f64::from(output_sample_rate_hz.get()) / f64::from(input_sample_rate_hz.get()),
        SINC_MAX_RELATIVE_RATIO,
        &SincInterpolationParameters {
            sinc_len: SINC_FILTER_LEN,
            f_cutoff: SINC_CUTOFF,
            oversampling_factor: SINC_OVERSAMPLING_FACTOR,
            interpolation: SincInterpolationType::Cubic,
            window: WindowFunction::BlackmanHarris2,
        },
        chunk_frames,
        channels,
        FixedAsync::Input,
    )
    .map_err(pcm_resampler_error)
}

fn resize_channels(channels: &mut [Vec<f32>], frames: usize) {
    for samples in channels {
        samples.resize(frames, 0.0);
    }
}

fn pcm_resampler_error(error: impl std::fmt::Display) -> Error {
    PcmError::Resampler(error.to_string()).into()
}
