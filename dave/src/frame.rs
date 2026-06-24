use std::{marker::PhantomData, time::Duration};

use aead::KeyInit;
use serde::{Deserialize, Serialize};

use crate::{
    error::{EncryptError, FrameDecryptError},
    gcm::Aes128Gcm8,
    leb128,
};

pub const OPUS_SILENCE_FRAME: [u8; 3] = [0xF8, 0xFF, 0xFE];

const MARKER: [u8; 2] = [0xFA, 0xFA];
const KEY_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TRUNCATED_NONCE_BYTES: usize = 4;
const TRUNCATED_NONCE_OFFSET: usize = NONCE_BYTES - TRUNCATED_NONCE_BYTES;
const TAG_BYTES: usize = 8;
const SUPPLEMENTAL_BASE_BYTES: usize = TAG_BYTES + 1 + MARKER.len();
const TRANSFORM_PADDING_BYTES: usize = 64;
pub(crate) const MAX_CIPHERTEXT_VALIDATION_RETRIES: usize = 10;
pub(crate) const RATCHET_GENERATION_SHIFT_BITS: usize = 8 * (TRUNCATED_NONCE_BYTES - 1);
pub(crate) const GENERATION_WRAP: u32 = 1 << 8;
pub(crate) const CIPHER_EXPIRY: Duration = Duration::from_secs(10);
pub(crate) const RATCHET_EXPIRY: Duration = Duration::from_secs(10);
pub(crate) const MAX_GENERATION_GAP: u32 = 250;
pub(crate) const MAX_MISSING_NONCES: u64 = 1000;
pub(crate) const MAX_FRAMES_PER_SECOND: u64 = 50 + 2 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum MediaType {
    Audio,
    Video,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Codec {
    Opus,
    Vp8,
    Vp9,
    H264,
    H265,
    Av1,
}

mod sealed {
    pub(crate) trait Sealed: Sized {
        fn process_frame(
            frame: &[u8],
            processor: &mut super::OutboundFrameProcessor,
        ) -> super::FrameProcessResult;

        fn validate_processed_frame(
            _processor: &super::OutboundFrameProcessor,
            _encrypted_frame: &[u8],
        ) -> bool {
            true
        }
    }
}

#[allow(private_bounds)]
pub trait FrameCodec: sealed::Sealed + Copy + Send + Sync + 'static {
    const MEDIA_TYPE: MediaType;
    const CODEC: Codec;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Opus;

impl sealed::Sealed for Opus {
    fn process_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
        process_fully_encrypted_frame(frame, processor)
    }
}

impl FrameCodec for Opus {
    const MEDIA_TYPE: MediaType = MediaType::Audio;
    const CODEC: Codec = Codec::Opus;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Vp8;

impl sealed::Sealed for Vp8 {
    fn process_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
        process_vp8_frame(frame, processor)
    }
}

impl FrameCodec for Vp8 {
    const MEDIA_TYPE: MediaType = MediaType::Video;
    const CODEC: Codec = Codec::Vp8;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Vp9;

impl sealed::Sealed for Vp9 {
    fn process_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
        process_fully_encrypted_frame(frame, processor)
    }
}

impl FrameCodec for Vp9 {
    const MEDIA_TYPE: MediaType = MediaType::Video;
    const CODEC: Codec = Codec::Vp9;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H264;

impl sealed::Sealed for H264 {
    fn process_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
        process_h26x_frame::<H264Codec>(frame, processor)
    }

    fn validate_processed_frame(
        processor: &OutboundFrameProcessor,
        encrypted_frame: &[u8],
    ) -> bool {
        validate_h26x_encrypted_frame(processor, encrypted_frame)
    }
}

impl FrameCodec for H264 {
    const MEDIA_TYPE: MediaType = MediaType::Video;
    const CODEC: Codec = Codec::H264;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H265;

impl sealed::Sealed for H265 {
    fn process_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
        process_h26x_frame::<H265Codec>(frame, processor)
    }

    fn validate_processed_frame(
        processor: &OutboundFrameProcessor,
        encrypted_frame: &[u8],
    ) -> bool {
        validate_h26x_encrypted_frame(processor, encrypted_frame)
    }
}

impl FrameCodec for H265 {
    const MEDIA_TYPE: MediaType = MediaType::Video;
    const CODEC: Codec = Codec::H265;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Av1;

impl sealed::Sealed for Av1 {
    fn process_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
        process_av1_frame(frame, processor)
    }
}

impl FrameCodec for Av1 {
    const MEDIA_TYPE: MediaType = MediaType::Video;
    const CODEC: Codec = Codec::Av1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaFrame<'a, C>
where
    C: FrameCodec,
{
    payload: &'a [u8],
    _codec: PhantomData<C>,
}

impl<'a, C> MediaFrame<'a, C>
where
    C: FrameCodec,
{
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            _codec: PhantomData,
        }
    }

    pub fn media_type(self) -> MediaType {
        C::MEDIA_TYPE
    }

    pub fn codec(self) -> Codec {
        C::CODEC
    }

    pub fn payload(self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicMediaFrame<'a> {
    pub media_type: MediaType,
    pub codec: Codec,
    pub payload: &'a [u8],
}

pub(crate) enum TypedMediaFrame<'a> {
    Opus(MediaFrame<'a, Opus>),
    Vp8(MediaFrame<'a, Vp8>),
    Vp9(MediaFrame<'a, Vp9>),
    H264(MediaFrame<'a, H264>),
    H265(MediaFrame<'a, H265>),
    Av1(MediaFrame<'a, Av1>),
}

pub(crate) trait TypedMediaFrameVisitor<'a> {
    type Output;

    fn visit<C>(&mut self, frame: MediaFrame<'a, C>) -> Self::Output
    where
        C: FrameCodec;
}

impl<'a> TypedMediaFrame<'a> {
    pub(crate) fn visit<V>(self, visitor: &mut V) -> V::Output
    where
        V: TypedMediaFrameVisitor<'a>,
    {
        match self {
            Self::Opus(frame) => visitor.visit(frame),
            Self::Vp8(frame) => visitor.visit(frame),
            Self::Vp9(frame) => visitor.visit(frame),
            Self::H264(frame) => visitor.visit(frame),
            Self::H265(frame) => visitor.visit(frame),
            Self::Av1(frame) => visitor.visit(frame),
        }
    }
}

impl<'a> DynamicMediaFrame<'a> {
    pub fn new(media_type: MediaType, codec: Codec, payload: &'a [u8]) -> Self {
        Self {
            media_type,
            codec,
            payload,
        }
    }

    pub(crate) fn typed(self) -> Option<TypedMediaFrame<'a>> {
        match (self.media_type, self.codec) {
            (MediaType::Audio, Codec::Opus) => {
                Some(TypedMediaFrame::Opus(MediaFrame::<Opus>::new(self.payload)))
            }
            (MediaType::Video, Codec::Vp8) => {
                Some(TypedMediaFrame::Vp8(MediaFrame::<Vp8>::new(self.payload)))
            }
            (MediaType::Video, Codec::Vp9) => {
                Some(TypedMediaFrame::Vp9(MediaFrame::<Vp9>::new(self.payload)))
            }
            (MediaType::Video, Codec::H264) => {
                Some(TypedMediaFrame::H264(MediaFrame::<H264>::new(self.payload)))
            }
            (MediaType::Video, Codec::H265) => {
                Some(TypedMediaFrame::H265(MediaFrame::<H265>::new(self.payload)))
            }
            (MediaType::Video, Codec::Av1) => {
                Some(TypedMediaFrame::Av1(MediaFrame::<Av1>::new(self.payload)))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameProcessResult {
    Processed,
    FallbackAllEncrypted,
}

#[derive(Clone)]
pub(crate) struct FrameCipher {
    cipher: Aes128Gcm8,
}

impl FrameCipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self, FrameDecryptError> {
        if key.len() != KEY_BYTES {
            return Err(FrameDecryptError::InvalidKey);
        }
        Ok(Self {
            cipher: Aes128Gcm8::new_from_slice(key).map_err(|_| FrameDecryptError::InvalidKey)?,
        })
    }

    pub(crate) fn encrypt_processed(
        &self,
        truncated_nonce: u32,
        processor: &mut OutboundFrameProcessor,
        output: &mut Vec<u8>,
    ) -> Result<usize, EncryptError> {
        processor.ciphertext.clear();
        processor
            .ciphertext
            .extend_from_slice(&processor.encrypted_bytes);
        output.clear();
        let nonce = nonce_from_truncated(truncated_nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                &nonce,
                &processor.unencrypted_bytes,
                &mut processor.ciphertext,
            )
            .map_err(|_| EncryptError::Aead)?;
        processor.reconstruct_encrypted_frame(output);
        output.extend_from_slice(&tag);
        write_supplemental_tail(truncated_nonce, &processor.unencrypted_ranges, output)?;
        Ok(output.len())
    }

    pub(crate) fn decrypt_into(
        &self,
        generation: u32,
        parsed: &ParsedFrame<'_, '_>,
        output: &mut Vec<u8>,
        scratch: &mut FrameDecryptScratch,
    ) -> Result<usize, FrameDecryptError> {
        if parsed.unencrypted_ranges.is_empty() {
            return self.decrypt_contiguous_into(generation, parsed, output);
        }

        scratch.prepare(parsed.authenticated_len(), parsed.ciphertext_len());
        parsed.interleaved_plan().split(
            parsed.interleaved_frame,
            &mut scratch.authenticated,
            &mut scratch.encrypted,
        );

        let nonce = nonce_from_truncated(parsed.truncated_nonce);
        self.cipher
            .decrypt_in_place_detached(
                &nonce,
                &scratch.authenticated,
                &mut scratch.encrypted,
                parsed.tag,
            )
            .map_err(|_| FrameDecryptError::Aead { generation })?;

        output.clear();
        output.reserve(parsed.interleaved_frame.len());
        parsed
            .interleaved_plan()
            .reconstruct(&scratch.authenticated, &scratch.encrypted, output);
        Ok(output.len())
    }

    fn decrypt_contiguous_into(
        &self,
        generation: u32,
        parsed: &ParsedFrame<'_, '_>,
        output: &mut Vec<u8>,
    ) -> Result<usize, FrameDecryptError> {
        output.clear();
        output.extend_from_slice(parsed.interleaved_frame);
        let nonce = nonce_from_truncated(parsed.truncated_nonce);
        self.cipher
            .decrypt_in_place_detached(&nonce, &[], output, parsed.tag)
            .map_err(|_| FrameDecryptError::Aead { generation })?;
        Ok(output.len())
    }
}

pub(crate) fn max_ciphertext_len<C>(frame: MediaFrame<'_, C>) -> usize
where
    C: FrameCodec,
{
    frame.payload.len()
        + TAG_BYTES
        + leb128::size(u64::from(u32::MAX))
        + 1
        + MARKER.len()
        + TRANSFORM_PADDING_BYTES
}

pub(crate) struct ParsedFrame<'frame, 'ranges> {
    pub(crate) encrypted: bool,
    pub(crate) truncated_nonce: u32,
    interleaved_frame: &'frame [u8],
    unencrypted_ranges: &'ranges [UnencryptedRange],
    pub(crate) tag: &'frame [u8],
}

#[derive(Default)]
pub(crate) struct FrameParseScratch {
    unencrypted_ranges: Vec<UnencryptedRange>,
}

#[derive(Default)]
pub(crate) struct FrameDecryptScratch {
    authenticated: Vec<u8>,
    encrypted: Vec<u8>,
}

impl FrameDecryptScratch {
    fn prepare(&mut self, authenticated_len: usize, encrypted_len: usize) {
        self.authenticated.clear();
        self.encrypted.clear();
        if self.authenticated.capacity() < authenticated_len {
            self.authenticated
                .reserve(authenticated_len - self.authenticated.capacity());
        }
        if self.encrypted.capacity() < encrypted_len {
            self.encrypted
                .reserve(encrypted_len - self.encrypted.capacity());
        }
    }
}

impl ParsedFrame<'_, '_> {
    fn authenticated_len(&self) -> usize {
        self.unencrypted_ranges.iter().map(|range| range.len).sum()
    }

    fn ciphertext_len(&self) -> usize {
        self.interleaved_frame.len() - self.authenticated_len()
    }

    fn interleaved_plan(&self) -> InterleavedFramePlan<'_> {
        InterleavedFramePlan {
            ranges: self.unencrypted_ranges,
            frame_len: self.interleaved_frame.len(),
        }
    }
}

struct InterleavedFramePlan<'a> {
    ranges: &'a [UnencryptedRange],
    frame_len: usize,
}

impl InterleavedFramePlan<'_> {
    fn split(&self, frame: &[u8], authenticated: &mut Vec<u8>, encrypted: &mut Vec<u8>) {
        debug_assert_eq!(frame.len(), self.frame_len);
        authenticated.clear();
        encrypted.clear();

        let mut frame_index = 0;
        for range in self.ranges {
            if range.offset > frame_index {
                encrypted.extend_from_slice(&frame[frame_index..range.offset]);
            }
            authenticated.extend_from_slice(&frame[range.offset..range.end()]);
            frame_index = range.end();
        }
        if frame_index < frame.len() {
            encrypted.extend_from_slice(&frame[frame_index..]);
        }
    }

    fn reconstruct(&self, authenticated: &[u8], encrypted: &[u8], output: &mut Vec<u8>) {
        output.clear();
        output.reserve(self.frame_len);
        let mut frame_index = 0;
        let mut authenticated_index = 0;
        let mut encrypted_index = 0;
        for range in self.ranges {
            if range.offset > frame_index {
                let len = range.offset - frame_index;
                output.extend_from_slice(&encrypted[encrypted_index..encrypted_index + len]);
                encrypted_index += len;
            }

            output.extend_from_slice(
                &authenticated[authenticated_index..authenticated_index + range.len],
            );
            authenticated_index += range.len;
            frame_index = range.end();
        }
        if encrypted_index < encrypted.len() {
            output.extend_from_slice(&encrypted[encrypted_index..]);
        }
        debug_assert_eq!(authenticated_index, authenticated.len());
        debug_assert_eq!(output.len(), self.frame_len);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnencryptedRange {
    offset: usize,
    len: usize,
}

impl UnencryptedRange {
    fn end(self) -> usize {
        self.offset + self.len
    }
}

#[derive(Default)]
pub(crate) struct OutboundFrameProcessor {
    frame_index: usize,
    unencrypted_ranges: Vec<UnencryptedRange>,
    unencrypted_bytes: Vec<u8>,
    encrypted_bytes: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl OutboundFrameProcessor {
    pub(crate) fn process<C>(&mut self, frame: &[u8])
    where
        C: FrameCodec,
    {
        self.reset();
        self.unencrypted_bytes.reserve(frame.len());
        self.encrypted_bytes.reserve(frame.len());
        if <C as sealed::Sealed>::process_frame(frame, self)
            == FrameProcessResult::FallbackAllEncrypted
        {
            self.reset();
            self.add_encrypted_bytes(frame);
        }
        self.ciphertext.resize(self.encrypted_bytes.len(), 0);
    }

    #[cfg(test)]
    fn unencrypted_ranges(&self) -> usize {
        self.unencrypted_ranges.len()
    }

    #[cfg(test)]
    fn encrypted_bytes(&self) -> usize {
        self.encrypted_bytes.len()
    }

    fn reset(&mut self) {
        self.frame_index = 0;
        self.unencrypted_ranges.clear();
        self.unencrypted_bytes.clear();
        self.encrypted_bytes.clear();
        self.ciphertext.clear();
    }

    fn add_unencrypted_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(range) = self.unencrypted_ranges.last_mut()
            && range.end() == self.frame_index
        {
            range.len += bytes.len();
        } else {
            self.unencrypted_ranges.push(UnencryptedRange {
                offset: self.frame_index,
                len: bytes.len(),
            });
        }
        self.unencrypted_bytes.extend_from_slice(bytes);
        self.frame_index += bytes.len();
    }

    fn add_encrypted_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.encrypted_bytes.extend_from_slice(bytes);
        self.frame_index += bytes.len();
    }

    fn reconstruct_encrypted_frame(&self, output: &mut Vec<u8>) {
        InterleavedFramePlan {
            ranges: &self.unencrypted_ranges,
            frame_len: self.frame_index,
        }
        .reconstruct(&self.unencrypted_bytes, &self.ciphertext, output);
    }
}

fn plain_frame(frame: &[u8]) -> ParsedFrame<'_, 'static> {
    ParsedFrame {
        encrypted: false,
        truncated_nonce: 0,
        interleaved_frame: frame,
        unencrypted_ranges: &[],
        tag: &[],
    }
}

pub(crate) fn parse_frame<'frame, 'scratch>(
    frame: &'frame [u8],
    scratch: &'scratch mut FrameParseScratch,
) -> Result<ParsedFrame<'frame, 'scratch>, FrameDecryptError> {
    if frame.len() < SUPPLEMENTAL_BASE_BYTES {
        return Ok(plain_frame(frame));
    }
    if frame[frame.len() - MARKER.len()..] != MARKER {
        return Ok(plain_frame(frame));
    }

    let supplemental_size = usize::from(frame[frame.len() - MARKER.len() - 1]);
    if supplemental_size < SUPPLEMENTAL_BASE_BYTES || supplemental_size > frame.len() {
        return Ok(plain_frame(frame));
    }
    let supplemental = &frame[frame.len() - supplemental_size..];
    let tag = &supplemental[..TAG_BYTES];
    let nonce_and_ranges = &supplemental[TAG_BYTES..supplemental.len() - MARKER.len() - 1];
    let Some((truncated_nonce, nonce_len)) = leb128::read(nonce_and_ranges) else {
        return Ok(plain_frame(frame));
    };
    if truncated_nonce > u64::from(u32::MAX) {
        return Ok(plain_frame(frame));
    }
    let interleaved_frame = &frame[..frame.len() - supplemental_size];
    match parse_unencrypted_ranges(
        &nonce_and_ranges[nonce_len..],
        interleaved_frame.len(),
        &mut scratch.unencrypted_ranges,
    ) {
        Ok(()) => {}
        Err(FrameDecryptError::MalformedFrame) => return Ok(plain_frame(frame)),
        Err(error) => return Err(error),
    }

    Ok(ParsedFrame {
        encrypted: true,
        truncated_nonce: truncated_nonce as u32,
        interleaved_frame,
        unencrypted_ranges: &scratch.unencrypted_ranges,
        tag,
    })
}

fn parse_unencrypted_ranges(
    mut bytes: &[u8],
    frame_len: usize,
    ranges: &mut Vec<UnencryptedRange>,
) -> Result<(), FrameDecryptError> {
    ranges.clear();
    let mut previous_end = 0;
    while !bytes.is_empty() {
        let Some((offset, offset_len)) = leb128::read(bytes) else {
            return Err(FrameDecryptError::MalformedFrame);
        };
        bytes = &bytes[offset_len..];
        let Some((len, len_len)) = leb128::read(bytes) else {
            return Err(FrameDecryptError::MalformedFrame);
        };
        bytes = &bytes[len_len..];

        let offset = usize::try_from(offset).map_err(|_| FrameDecryptError::MalformedFrame)?;
        let len = usize::try_from(len).map_err(|_| FrameDecryptError::MalformedFrame)?;
        let end = offset
            .checked_add(len)
            .ok_or(FrameDecryptError::MalformedFrame)?;
        if offset < previous_end || end > frame_len {
            return Err(FrameDecryptError::MalformedFrame);
        }
        ranges.push(UnencryptedRange { offset, len });
        previous_end = end;
    }
    Ok(())
}

fn nonce_from_truncated(truncated_nonce: u32) -> [u8; NONCE_BYTES] {
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce[TRUNCATED_NONCE_OFFSET..].copy_from_slice(&truncated_nonce.to_le_bytes());
    nonce
}

fn write_supplemental_tail(
    truncated_nonce: u32,
    ranges: &[UnencryptedRange],
    output: &mut Vec<u8>,
) -> Result<(), EncryptError> {
    let nonce_size = leb128::size(u64::from(truncated_nonce));
    let ranges_size = unencrypted_ranges_size(ranges);
    let supplemental_size = TAG_BYTES + nonce_size + ranges_size + 1 + MARKER.len();
    let supplemental_size =
        u8::try_from(supplemental_size).map_err(|_| EncryptError::SupplementalDataTooLarge)?;
    let start = output.len();
    output.resize(start + nonce_size + ranges_size + 1 + MARKER.len(), 0);
    leb128::write(
        u64::from(truncated_nonce),
        &mut output[start..start + nonce_size],
    )
    .ok_or(EncryptError::FrameEncoding)?;
    let mut offset = start + nonce_size;
    for range in ranges {
        let written = leb128::write(range.offset as u64, &mut output[offset..])
            .ok_or(EncryptError::FrameEncoding)?;
        offset += written;
        let written = leb128::write(range.len as u64, &mut output[offset..])
            .ok_or(EncryptError::FrameEncoding)?;
        offset += written;
    }
    output[offset] = supplemental_size;
    output[offset + 1..].copy_from_slice(&MARKER);
    Ok(())
}

fn unencrypted_ranges_size(ranges: &[UnencryptedRange]) -> usize {
    ranges
        .iter()
        .map(|range| leb128::size(range.offset as u64) + leb128::size(range.len as u64))
        .sum()
}

fn process_fully_encrypted_frame(
    frame: &[u8],
    processor: &mut OutboundFrameProcessor,
) -> FrameProcessResult {
    processor.add_encrypted_bytes(frame);
    FrameProcessResult::Processed
}

fn process_vp8_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
    if frame.is_empty() {
        return FrameProcessResult::FallbackAllEncrypted;
    }
    let unencrypted = if frame[0] & 0x01 == 0 { 10 } else { 1 };
    if unencrypted > frame.len() {
        return FrameProcessResult::FallbackAllEncrypted;
    }
    processor.add_unencrypted_bytes(&frame[..unencrypted]);
    processor.add_encrypted_bytes(&frame[unencrypted..]);
    FrameProcessResult::Processed
}

pub(crate) fn validate_processed_frame<C>(
    processor: &OutboundFrameProcessor,
    encrypted_frame: &[u8],
) -> bool
where
    C: FrameCodec,
{
    <C as sealed::Sealed>::validate_processed_frame(processor, encrypted_frame)
}

trait H26xCodec {
    const NAL_HEADER_BYTES: usize;

    fn nal_type(header: u8) -> u8;
    fn encrypted_payload_unencrypted_prefix(nalu: &[u8]) -> Option<usize>;
    fn encrypts_payload(nal_type: u8) -> bool;
}

struct H264Codec;

impl H26xCodec for H264Codec {
    const NAL_HEADER_BYTES: usize = 1;

    fn nal_type(header: u8) -> u8 {
        const NAL_TYPE_MASK: u8 = 0x1f;
        header & NAL_TYPE_MASK
    }

    fn encrypted_payload_unencrypted_prefix(nalu: &[u8]) -> Option<usize> {
        bytes_covering_h264_pps(nalu.get(Self::NAL_HEADER_BYTES..)?)
            .map(|pps_bytes| Self::NAL_HEADER_BYTES + pps_bytes)
    }

    fn encrypts_payload(nal_type: u8) -> bool {
        const NAL_TYPE_SLICE: u8 = 1;
        const NAL_TYPE_IDR: u8 = 5;
        nal_type == NAL_TYPE_SLICE || nal_type == NAL_TYPE_IDR
    }
}

struct H265Codec;

impl H26xCodec for H265Codec {
    const NAL_HEADER_BYTES: usize = 2;

    fn nal_type(header: u8) -> u8 {
        const NAL_TYPE_MASK: u8 = 0x7e;
        (header & NAL_TYPE_MASK) >> 1
    }

    fn encrypted_payload_unencrypted_prefix(nalu: &[u8]) -> Option<usize> {
        (nalu.len() >= Self::NAL_HEADER_BYTES).then_some(Self::NAL_HEADER_BYTES)
    }

    fn encrypts_payload(nal_type: u8) -> bool {
        const VCL_NAL_TYPE_CUTOFF: u8 = 32;
        nal_type < VCL_NAL_TYPE_CUTOFF
    }
}

fn process_h26x_frame<C>(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult
where
    C: H26xCodec,
{
    if frame.len() < H26X_SHORT_START_SEQUENCE_BYTES + C::NAL_HEADER_BYTES {
        return FrameProcessResult::FallbackAllEncrypted;
    }
    let Some(mut nalu) = find_next_h26x_nalu(frame, 0) else {
        return FrameProcessResult::FallbackAllEncrypted;
    };
    while nalu.start < frame.len().saturating_sub(1) {
        let nal_type = C::nal_type(frame[nalu.start]);
        processor.add_unencrypted_bytes(&H26X_LONG_START_CODE);
        let next = find_next_h26x_nalu(frame, nalu.start);
        let next_start = next
            .map(|next| next.start - next.start_code_len)
            .unwrap_or(frame.len());
        if C::encrypts_payload(nal_type) {
            let Some(unencrypted) =
                C::encrypted_payload_unencrypted_prefix(&frame[nalu.start..next_start])
            else {
                return FrameProcessResult::FallbackAllEncrypted;
            };
            if nalu.start + unencrypted > next_start {
                return FrameProcessResult::FallbackAllEncrypted;
            }
            processor.add_unencrypted_bytes(&frame[nalu.start..nalu.start + unencrypted]);
            processor.add_encrypted_bytes(&frame[nalu.start + unencrypted..next_start]);
        } else {
            processor.add_unencrypted_bytes(&frame[nalu.start..next_start]);
        }
        let Some(next) = next else {
            break;
        };
        nalu = next;
    }
    FrameProcessResult::Processed
}

fn process_av1_frame(frame: &[u8], processor: &mut OutboundFrameProcessor) -> FrameProcessResult {
    const OBU_HAS_EXTENSION: u8 = 0b0000_0100;
    const OBU_HAS_SIZE: u8 = 0b0000_0010;
    const OBU_TYPE_MASK: u8 = 0b0111_1000;
    const OBU_TYPE_TEMPORAL_DELIMITER: u8 = 2;
    const OBU_TYPE_TILE_LIST: u8 = 8;
    const OBU_TYPE_PADDING: u8 = 15;

    let mut index = 0;
    while index < frame.len() {
        let obu_header_index = index;
        let Some(mut obu_header) = frame.get(obu_header_index).copied() else {
            return FrameProcessResult::FallbackAllEncrypted;
        };
        index += 1;

        let has_extension = obu_header & OBU_HAS_EXTENSION != 0;
        let has_size = obu_header & OBU_HAS_SIZE != 0;
        let obu_type = (obu_header & OBU_TYPE_MASK) >> 3;
        if has_extension {
            index += 1;
        }
        if index >= frame.len() {
            return FrameProcessResult::FallbackAllEncrypted;
        }

        let payload_size = if has_size {
            let Some((payload_size, size_len)) = leb128::read(&frame[index..]) else {
                return FrameProcessResult::FallbackAllEncrypted;
            };
            index += size_len;
            let Ok(payload_size) = usize::try_from(payload_size) else {
                return FrameProcessResult::FallbackAllEncrypted;
            };
            payload_size
        } else {
            frame.len() - index
        };
        let payload_index = index;
        let Some(next_index) = index.checked_add(payload_size) else {
            return FrameProcessResult::FallbackAllEncrypted;
        };
        if next_index > frame.len() {
            return FrameProcessResult::FallbackAllEncrypted;
        }
        index = next_index;

        if matches!(
            obu_type,
            OBU_TYPE_TEMPORAL_DELIMITER | OBU_TYPE_TILE_LIST | OBU_TYPE_PADDING
        ) {
            continue;
        }

        let rewrite_without_size = index == frame.len() && has_size;
        if rewrite_without_size {
            obu_header &= !OBU_HAS_SIZE;
        }
        processor.add_unencrypted_bytes(&[obu_header]);
        if has_extension {
            processor.add_unencrypted_bytes(&frame[obu_header_index + 1..obu_header_index + 2]);
        }
        if has_size && !rewrite_without_size {
            let mut size_buffer = [0; 10];
            let Some(written) = leb128::write(payload_size as u64, &mut size_buffer) else {
                return FrameProcessResult::FallbackAllEncrypted;
            };
            processor.add_unencrypted_bytes(&size_buffer[..written]);
        }
        processor.add_encrypted_bytes(&frame[payload_index..payload_index + payload_size]);
    }
    FrameProcessResult::Processed
}

const H26X_LONG_START_CODE: [u8; 4] = [0, 0, 0, 1];
const H26X_SHORT_START_SEQUENCE_BYTES: usize = 3;

#[derive(Clone, Copy)]
struct H26XNalu {
    start: usize,
    start_code_len: usize,
}

fn find_next_h26x_nalu(frame: &[u8], search_start: usize) -> Option<H26XNalu> {
    if frame.len() < H26X_SHORT_START_SEQUENCE_BYTES {
        return None;
    }
    let mut index = search_start;
    while index < frame.len() - H26X_SHORT_START_SEQUENCE_BYTES {
        if frame[index + 2] > 1 {
            index += H26X_SHORT_START_SEQUENCE_BYTES;
        } else if frame[index + 2] == 1 {
            if frame[index] == 0 && frame[index + 1] == 0 {
                let start_code_len = if index >= 1 && frame[index - 1] == 0 {
                    4
                } else {
                    3
                };
                return Some(H26XNalu {
                    start: index + H26X_SHORT_START_SEQUENCE_BYTES,
                    start_code_len,
                });
            }
            index += H26X_SHORT_START_SEQUENCE_BYTES;
        } else {
            index += 1;
        }
    }
    None
}

fn bytes_covering_h264_pps(payload: &[u8]) -> Option<usize> {
    const EMULATION_PREVENTION_BYTE: u8 = 0x03;
    let mut bit_index = 0;
    let mut zero_bit_count = 0;
    let mut parsed_values = 0;
    while bit_index < payload.len() * 8 && parsed_values < 3 {
        let byte_index = bit_index / 8;
        let intra_byte_index = bit_index % 8;
        let payload_byte = payload[byte_index];
        if intra_byte_index == 0
            && byte_index >= 2
            && payload_byte == EMULATION_PREVENTION_BYTE
            && payload[byte_index - 1] == 0
            && payload[byte_index - 2] == 0
        {
            bit_index += 8;
            continue;
        }
        if payload_byte & (1 << (7 - intra_byte_index)) == 0 {
            zero_bit_count += 1;
            bit_index += 1;
            if zero_bit_count >= 32 {
                return None;
            }
        } else {
            parsed_values += 1;
            bit_index += 1 + zero_bit_count;
            zero_bit_count = 0;
        }
    }
    (parsed_values == 3).then_some(bit_index / 8 + 1)
}

fn validate_h26x_encrypted_frame(
    processor: &OutboundFrameProcessor,
    encrypted_frame: &[u8],
) -> bool {
    const PADDING: usize = H26X_SHORT_START_SEQUENCE_BYTES - 1;
    let mut encrypted_section_start = 0;
    for range in &processor.unencrypted_ranges {
        if encrypted_section_start == range.offset {
            encrypted_section_start += range.len;
            continue;
        }
        let start = encrypted_section_start.saturating_sub(PADDING);
        let end = (range.offset + PADDING).min(encrypted_frame.len());
        if find_next_h26x_nalu(&encrypted_frame[start..end], 0).is_some() {
            return false;
        }
        encrypted_section_start = range.end();
    }
    if encrypted_section_start == processor.frame_index {
        return true;
    }
    let start = encrypted_section_start.saturating_sub(PADDING);
    find_next_h26x_nalu(&encrypted_frame[start..], 0).is_none()
}

#[cfg(test)]
mod tests {
    use crate::leb128;

    use super::{
        Av1, FrameCipher, FrameDecryptScratch, FrameParseScratch, H264, H265, InterleavedFramePlan,
        KEY_BYTES, MARKER, MediaFrame, Opus, OutboundFrameProcessor, TAG_BYTES, UnencryptedRange,
        Vp8, Vp9, nonce_from_truncated, parse_frame,
    };

    #[test]
    fn decrypts_frame_with_unencrypted_ranges() {
        let plaintext = b"0123456789abcdef";
        let ranges = [
            UnencryptedRange { offset: 2, len: 4 },
            UnencryptedRange { offset: 10, len: 2 },
        ];
        let cipher = FrameCipher::new(&[7; KEY_BYTES]).unwrap();
        let frame = encrypted_frame_with_ranges(&cipher, 1, plaintext, &ranges);
        let mut parse_scratch = FrameParseScratch::default();
        let parsed = parse_frame(&frame, &mut parse_scratch).unwrap();
        let mut output = Vec::new();
        let mut scratch = FrameDecryptScratch::default();

        cipher
            .decrypt_into(0, &parsed, &mut output, &mut scratch)
            .unwrap();

        assert_eq!(output, plaintext);
    }

    #[test]
    fn malformed_unencrypted_range_overflow_fails_protocol_frame_check() {
        let mut frame = b"abc".to_vec();
        frame.extend_from_slice(&[0; TAG_BYTES]);
        push_leb128(1, &mut frame);
        push_leb128(2, &mut frame);
        push_leb128(2, &mut frame);
        frame.push((TAG_BYTES + 3 + 1 + MARKER.len()) as u8);
        frame.extend_from_slice(&MARKER);

        assert!(
            !parse_frame(&frame, &mut FrameParseScratch::default())
                .unwrap()
                .encrypted
        );
    }

    #[test]
    fn opus_and_vp9_are_fully_encrypted() {
        assert_partition::<Opus>(b"opus", 0, 4);
        assert_partition::<Vp9>(b"vp9-frame", 0, 9);
    }

    #[test]
    fn vp8_keeps_packetizer_header_authenticated() {
        assert_partition::<Vp8>(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 1, 1);
        assert_partition::<Vp8>(&[1, 2, 3], 1, 2);
    }

    #[test]
    fn h264_and_h265_keep_nal_headers_authenticated() {
        let h264 = [0, 0, 0, 1, 0x65, 0xe0, 0x12, 0x34, 0x56, 0x78];
        let h265 = [0, 0, 0, 1, 0x26, 0x01, 0xaa, 0xbb, 0xcc];

        assert_partition::<H264>(&h264, 1, 4);
        assert_partition::<H265>(&h265, 1, 3);
    }

    #[test]
    fn av1_keeps_obu_header_authenticated() {
        let av1 = [0b0000_1010, 3, 0xaa, 0xbb, 0xcc];

        assert_partition::<Av1>(&av1, 1, 3);
    }

    fn assert_partition<C>(frame: &[u8], unencrypted_ranges: usize, encrypted_bytes: usize)
    where
        C: super::FrameCodec,
    {
        let mut processor = OutboundFrameProcessor::default();

        processor.process::<C>(MediaFrame::<C>::new(frame).payload());

        assert_eq!(processor.unencrypted_ranges(), unencrypted_ranges);
        assert_eq!(processor.encrypted_bytes(), encrypted_bytes);
    }

    fn encrypted_frame_with_ranges(
        cipher: &FrameCipher,
        truncated_nonce: u32,
        plaintext: &[u8],
        ranges: &[UnencryptedRange],
    ) -> Vec<u8> {
        let mut authenticated = Vec::new();
        let mut encrypted = Vec::new();
        let plan = InterleavedFramePlan {
            ranges,
            frame_len: plaintext.len(),
        };
        plan.split(plaintext, &mut authenticated, &mut encrypted);

        let nonce = nonce_from_truncated(truncated_nonce);
        let tag = cipher
            .cipher
            .encrypt_in_place_detached(&nonce, &authenticated, &mut encrypted)
            .unwrap();

        let mut frame = Vec::new();
        plan.reconstruct(&authenticated, &encrypted, &mut frame);
        frame.extend_from_slice(&tag);
        push_leb128(u64::from(truncated_nonce), &mut frame);
        for range in ranges {
            push_leb128(range.offset as u64, &mut frame);
            push_leb128(range.len as u64, &mut frame);
        }
        frame.push(supplemental_size(truncated_nonce, ranges) as u8);
        frame.extend_from_slice(&MARKER);
        frame
    }

    fn push_leb128(value: u64, output: &mut Vec<u8>) {
        let start = output.len();
        output.resize(start + leb128::size(value), 0);
        leb128::write(value, &mut output[start..]).unwrap();
    }

    fn supplemental_size(truncated_nonce: u32, ranges: &[UnencryptedRange]) -> usize {
        TAG_BYTES
            + leb128::size(u64::from(truncated_nonce))
            + ranges
                .iter()
                .map(|range| leb128::size(range.offset as u64) + leb128::size(range.len as u64))
                .sum::<usize>()
            + 1
            + MARKER.len()
    }
}
