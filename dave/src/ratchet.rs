use std::{
    cmp::max,
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use hmac::{Hmac, KeyInit as _, Mac};
use openmls::prelude::{TlsSerialize, TlsSize, VLBytes};
use sha2::Sha256;
use tls_codec::Serialize;
use zeroize::Zeroizing;

use crate::{
    error::{EncryptError, FrameDecryptError, UpdateRatchetsError},
    frame::{
        CIPHER_EXPIRY, FrameCipher, FrameCodec, FrameParseScratch, GENERATION_WRAP,
        MAX_CIPHERTEXT_VALIDATION_RETRIES, MAX_FRAMES_PER_SECOND, MAX_GENERATION_GAP,
        MAX_MISSING_NONCES, MediaFrame, MediaType, OPUS_SILENCE_FRAME, OutboundFrameProcessor,
        ParsedFrame, RATCHET_EXPIRY, RATCHET_GENERATION_SHIFT_BITS,
    },
    passthrough::{PassthroughMode, PlaintextPassthrough},
};

#[derive(Debug, TlsSerialize, TlsSize)]
struct KdfLabel {
    length: u16,
    label: VLBytes,
    context: VLBytes,
}

type SecretBytes = Zeroizing<Vec<u8>>;

#[derive(Clone)]
struct RatchetGenerationSecrets {
    key: SecretBytes,
    nonce: SecretBytes,
}

#[derive(Clone)]
pub(crate) struct HashRatchet {
    next_secret: SecretBytes,
    next_generation: u32,
    cache: HashMap<u32, RatchetGenerationSecrets>,
}

impl HashRatchet {
    pub(crate) fn new(secret: Vec<u8>) -> Self {
        Self {
            next_secret: Zeroizing::new(secret),
            next_generation: 0,
            cache: HashMap::new(),
        }
    }

    pub(crate) fn get(&mut self, generation: u32) -> Result<(&[u8], &[u8]), UpdateRatchetsError> {
        if !self.cache.contains_key(&generation) {
            if self.next_generation > generation {
                return Err(UpdateRatchetsError::DeriveSecret);
            }
            while self.next_generation <= generation {
                self.next()?;
            }
        }
        let key = self
            .cache
            .get(&generation)
            .ok_or(UpdateRatchetsError::DeriveSecret)?;
        Ok((&key.key, &key.nonce))
    }

    pub(crate) fn erase(&mut self, generation: u32) {
        self.cache.remove(&generation);
    }

    fn next(&mut self) -> Result<(), UpdateRatchetsError> {
        let generation = self.next_generation;
        let key = derive_tree_secret(&self.next_secret, "key", generation, 16)?;
        let nonce = derive_tree_secret(&self.next_secret, "nonce", generation, 12)?;
        self.next_secret = derive_tree_secret(&self.next_secret, "secret", generation, 32)?;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.cache
            .insert(generation, RatchetGenerationSecrets { key, nonce });
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Encryptor {
    active_ratchet: Option<HashRatchet>,
    pending_ratchet: Option<HashRatchet>,
    cipher: Option<FrameCipher>,
    current_generation: u32,
    truncated_nonce: u32,
    frame_processor: OutboundFrameProcessor,
}

impl Encryptor {
    pub(crate) fn stage_ratchet(&mut self, ratchet: HashRatchet) {
        self.pending_ratchet = Some(ratchet);
    }

    pub(crate) fn activate_pending(&mut self) -> bool {
        let Some(ratchet) = self.pending_ratchet.take() else {
            return false;
        };
        self.active_ratchet = Some(ratchet);
        self.cipher = None;
        self.current_generation = 0;
        self.truncated_nonce = 0;
        true
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn ready(&self) -> bool {
        self.active_ratchet.is_some()
    }

    pub(crate) fn encrypt_into<C>(
        &mut self,
        frame: MediaFrame<'_, C>,
        output: &mut Vec<u8>,
    ) -> Result<usize, EncryptError>
    where
        C: FrameCodec,
    {
        output.reserve(frame.max_ciphertext_len());
        self.frame_processor.process::<C>(frame.payload());
        for _ in 0..MAX_CIPHERTEXT_VALIDATION_RETRIES {
            let truncated_nonce = self.advance_cipher()?;
            let Self {
                cipher,
                frame_processor,
                ..
            } = self;
            let Some(cipher) = cipher.as_ref() else {
                return Err(EncryptError::MissingRatchetKey);
            };
            let len = cipher.encrypt_processed(truncated_nonce, frame_processor, output)?;
            if frame_processor.validate_processed::<C>(output) {
                return Ok(len);
            }
        }
        Err(EncryptError::TooManyAttempts)
    }

    fn advance_cipher(&mut self) -> Result<u32, EncryptError> {
        let Some(ratchet) = self.active_ratchet.as_mut() else {
            return Err(EncryptError::SenderNotReady);
        };
        self.truncated_nonce = self.truncated_nonce.wrapping_add(1);
        let generation = compute_wrapped_generation(
            self.current_generation,
            self.truncated_nonce >> RATCHET_GENERATION_SHIFT_BITS,
        );
        if generation != self.current_generation || self.cipher.is_none() {
            self.current_generation = generation;
            let (key, _) = ratchet
                .get(generation)
                .map_err(|_| EncryptError::MissingRatchetKey)?;
            self.cipher = Some(FrameCipher::new(key).map_err(|_| EncryptError::InvalidKey)?);
        }
        Ok(self.truncated_nonce)
    }
}

pub(crate) struct Decryptor {
    clock: Instant,
    managers: VecDeque<CryptorManager>,
    passthrough: PlaintextPassthrough,
    frame_parse_scratch: FrameParseScratch,
    frame_decrypt_scratch: crate::frame::FrameDecryptScratch,
}

impl Default for Decryptor {
    fn default() -> Self {
        Self {
            clock: Instant::now(),
            managers: VecDeque::new(),
            passthrough: PlaintextPassthrough::disabled(),
            frame_parse_scratch: FrameParseScratch::default(),
            frame_decrypt_scratch: crate::frame::FrameDecryptScratch::default(),
        }
    }
}

impl Decryptor {
    pub(crate) fn with_plaintext_passthrough(passthrough: PlaintextPassthrough) -> Self {
        Self {
            passthrough,
            ..Self::default()
        }
    }

    pub(crate) fn transition_to_ratchet(&mut self, ratchet: HashRatchet) {
        self.update_manager_expiry(RATCHET_EXPIRY);
        self.managers
            .push_back(CryptorManager::new(self.clock, ratchet));
    }

    pub(crate) fn transition_to_passthrough(&mut self, mode: PassthroughMode) {
        self.passthrough.apply(mode);
    }

    pub(crate) fn decrypt(
        &mut self,
        media_type: MediaType,
        encrypted_frame: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<usize, FrameDecryptError> {
        self.cleanup_expired_managers();
        if media_type == MediaType::Audio && encrypted_frame == OPUS_SILENCE_FRAME {
            output.clear();
            output.extend_from_slice(encrypted_frame);
            return Ok(encrypted_frame.len());
        }
        let parsed = self.frame_parse_scratch.parse(encrypted_frame)?;
        if !parsed.encrypted {
            if self.passthrough.allows_plaintext() {
                output.clear();
                output.extend_from_slice(encrypted_frame);
                return Ok(encrypted_frame.len());
            }
            return Err(FrameDecryptError::PassthroughDisabled);
        }

        let manager_count = self.managers.len();
        let mut last_error = None;
        let frame_scratch = &mut self.frame_decrypt_scratch;
        for manager in self.managers.iter_mut().rev() {
            match manager.decrypt(&parsed, output, frame_scratch) {
                Ok(len) => return Ok(len),
                Err(error) => last_error = Some(error),
            }
        }
        if let Some(
            error @ (FrameDecryptError::ReplayedNonce
            | FrameDecryptError::MissingCryptor { .. }
            | FrameDecryptError::Aead { .. }),
        ) = last_error
            && manager_count == 1
        {
            return Err(error);
        }
        Err(FrameDecryptError::NoValidCryptor {
            media_type,
            encrypted_size: encrypted_frame.len(),
            plaintext_capacity: output.capacity(),
            manager_count,
        })
    }

    fn update_manager_expiry(&mut self, duration: Duration) {
        let expiry = self.clock.elapsed() + duration;
        for manager in &mut self.managers {
            manager.update_expiry(expiry);
        }
    }

    fn cleanup_expired_managers(&mut self) {
        while self.managers.front().is_some_and(CryptorManager::expired) {
            self.managers.pop_front();
        }
    }
}

struct ExpiringCipher {
    cipher: FrameCipher,
    expiry: Option<Duration>,
}

#[derive(Default)]
struct MissingNonceWindow {
    order: VecDeque<u64>,
    members: HashSet<u64>,
}

impl MissingNonceWindow {
    fn contains(&self, nonce: u64) -> bool {
        self.members.contains(&nonce)
    }

    fn remove(&mut self, nonce: u64) {
        self.members.remove(&nonce);
    }

    fn prune_before(&mut self, oldest: u64) {
        while self.order.front().is_some_and(|nonce| *nonce < oldest) {
            let nonce = self.order.pop_front().expect("front checked");
            self.members.remove(&nonce);
        }
    }

    fn push_back(&mut self, nonce: u64) {
        if self.members.insert(nonce) {
            self.order.push_back(nonce);
        }
    }
}

struct CryptorManager {
    clock: Instant,
    ratchet: HashRatchet,
    ciphers: HashMap<u32, ExpiringCipher>,
    ratchet_created_at: Duration,
    ratchet_expiry: Option<Duration>,
    oldest_generation: u32,
    newest_generation: u32,
    newest_nonce: Option<u64>,
    missing_nonces: MissingNonceWindow,
}

impl CryptorManager {
    fn new(clock: Instant, ratchet: HashRatchet) -> Self {
        Self {
            clock,
            ratchet,
            ciphers: HashMap::new(),
            ratchet_created_at: clock.elapsed(),
            ratchet_expiry: None,
            oldest_generation: 0,
            newest_generation: 0,
            newest_nonce: None,
            missing_nonces: MissingNonceWindow::default(),
        }
    }

    fn decrypt(
        &mut self,
        parsed: &ParsedFrame<'_, '_>,
        output: &mut Vec<u8>,
        scratch: &mut crate::frame::FrameDecryptScratch,
    ) -> Result<usize, FrameDecryptError> {
        let generation = compute_wrapped_generation(
            self.oldest_generation,
            parsed.truncated_nonce >> RATCHET_GENERATION_SHIFT_BITS,
        );
        if !self.can_process_nonce(generation, parsed.truncated_nonce) {
            return Err(FrameDecryptError::ReplayedNonce);
        }
        let cipher = self.cipher(generation)?;
        let len = cipher.decrypt_into(generation, parsed, output, scratch)?;
        self.report_success(generation, parsed.truncated_nonce);
        Ok(len)
    }

    fn cipher(&mut self, generation: u32) -> Result<&FrameCipher, FrameDecryptError> {
        self.cleanup_expired_ciphers();
        if generation < self.oldest_generation
            || generation > self.newest_generation + MAX_GENERATION_GAP
            || generation > self.max_lifetime_generation()
        {
            return Err(FrameDecryptError::MissingCryptor { generation });
        }
        if !self.ciphers.contains_key(&generation) {
            let (key, _) = self
                .ratchet
                .get(generation)
                .map_err(|_| FrameDecryptError::MissingCryptor { generation })?;
            let expiry =
                (generation < self.newest_generation).then(|| self.clock.elapsed() + CIPHER_EXPIRY);
            self.ciphers.insert(
                generation,
                ExpiringCipher {
                    cipher: FrameCipher::new(key)?,
                    expiry,
                },
            );
        }
        self.ciphers
            .get(&generation)
            .map(|cipher| &cipher.cipher)
            .ok_or(FrameDecryptError::MissingCryptor { generation })
    }

    fn report_success(&mut self, generation: u32, nonce: u32) {
        let wrapped_nonce = wrapped_nonce(generation, nonce);
        match self.newest_nonce {
            None => self.newest_nonce = Some(wrapped_nonce),
            Some(newest) if wrapped_nonce > newest => {
                let oldest_missing = wrapped_nonce.saturating_sub(MAX_MISSING_NONCES);
                self.missing_nonces.prune_before(oldest_missing);
                for missing in max(oldest_missing, newest + 1)..wrapped_nonce {
                    self.missing_nonces.push_back(missing);
                }
                self.newest_nonce = Some(wrapped_nonce);
            }
            Some(_) => self.missing_nonces.remove(wrapped_nonce),
        }

        if generation <= self.newest_generation || !self.ciphers.contains_key(&generation) {
            return;
        }
        self.newest_generation = generation;
        let expiry = self.clock.elapsed() + CIPHER_EXPIRY;
        for (cipher_generation, cipher) in &mut self.ciphers {
            if *cipher_generation < self.newest_generation {
                cipher.expiry = Some(expiry);
            }
        }
    }

    fn can_process_nonce(&self, generation: u32, nonce: u32) -> bool {
        let wrapped = wrapped_nonce(generation, nonce);
        self.newest_nonce
            .is_none_or(|newest| wrapped > newest || self.missing_nonces.contains(wrapped))
    }

    fn cleanup_expired_ciphers(&mut self) {
        let elapsed = self.clock.elapsed();
        self.ciphers
            .retain(|_, cipher| cipher.expiry.is_none_or(|expiry| expiry > elapsed));
        while self.oldest_generation < self.newest_generation
            && !self.ciphers.contains_key(&self.oldest_generation)
        {
            self.ratchet.erase(self.oldest_generation);
            self.oldest_generation += 1;
        }
    }

    fn update_expiry(&mut self, expiry: Duration) {
        self.ratchet_expiry = Some(expiry);
    }

    fn expired(&self) -> bool {
        self.ratchet_expiry
            .is_some_and(|expiry| expiry < self.clock.elapsed())
    }

    fn max_lifetime_generation(&self) -> u32 {
        let frames =
            MAX_FRAMES_PER_SECOND * (self.clock.elapsed() - self.ratchet_created_at).as_secs();
        (frames >> RATCHET_GENERATION_SHIFT_BITS) as u32
    }
}

fn compute_wrapped_generation(oldest: u32, generation: u32) -> u32 {
    let remainder = oldest % GENERATION_WRAP;
    let factor = oldest / GENERATION_WRAP + u32::from(generation < remainder);
    factor * GENERATION_WRAP + generation
}

fn wrapped_nonce(generation: u32, nonce: u32) -> u64 {
    let masked = u64::from(nonce) & ((1 << RATCHET_GENERATION_SHIFT_BITS) - 1);
    (u64::from(generation) << RATCHET_GENERATION_SHIFT_BITS) | masked
}

fn derive_tree_secret(
    secret: &[u8],
    label: &str,
    generation: u32,
    length: usize,
) -> Result<SecretBytes, UpdateRatchetsError> {
    let label = format!("MLS 1.0 {label}");
    let info = KdfLabel {
        length: length as u16,
        label: label.as_bytes().into(),
        context: generation.to_be_bytes().as_slice().into(),
    }
    .tls_serialize_detached()
    .map_err(|_| UpdateRatchetsError::DeriveSecret)?;
    hkdf_expand(secret, &info, length)
}

fn hkdf_expand(
    secret: &[u8],
    info: &[u8],
    length: usize,
) -> Result<SecretBytes, UpdateRatchetsError> {
    let mut okm = Zeroizing::new(Vec::with_capacity(length));
    let mut block = Zeroizing::new(Vec::new());
    let mut counter = 1_u8;
    while okm.len() < length {
        let mut hmac = Hmac::<Sha256>::new_from_slice(secret)
            .map_err(|_| UpdateRatchetsError::DeriveSecret)?;
        hmac.update(&block);
        hmac.update(info);
        hmac.update(&[counter]);
        block = Zeroizing::new(hmac.finalize().into_bytes().to_vec());
        okm.extend_from_slice(&block);
        counter = counter
            .checked_add(1)
            .ok_or(UpdateRatchetsError::DeriveSecret)?;
    }
    okm.truncate(length);
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        error::FrameDecryptError,
        frame::{
            Av1, FrameCodec, H264, H265, MediaFrame, MediaType, OPUS_SILENCE_FRAME, Opus, Vp8, Vp9,
        },
    };

    use super::{Decryptor, Encryptor, HashRatchet, MissingNonceWindow, PassthroughMode};

    #[test]
    fn hash_ratchet_matches_reference_vector() {
        let mut ratchet = HashRatchet::new(vec![
            206, 221, 97, 177, 184, 161, 202, 105, 4, 101, 84, 40, 44, 247, 11, 123,
        ]);
        let (key, nonce) = ratchet.get(0).unwrap();

        assert_eq!(
            key,
            &[
                117, 48, 249, 169, 148, 94, 45, 46, 6, 208, 101, 31, 123, 42, 134, 75
            ],
        );
        assert_eq!(nonce, &[48, 30, 95, 75, 116, 9, 15, 152, 94, 114, 107, 178]);
    }

    #[test]
    fn missing_nonce_window_removes_members_without_disturbing_eviction_order() {
        let mut window = MissingNonceWindow::default();

        window.push_back(10);
        window.push_back(11);
        window.push_back(12);
        window.remove(11);
        window.prune_before(12);

        assert!(!window.contains(10));
        assert!(!window.contains(11));
        assert!(window.contains(12));
    }

    #[test]
    fn opus_frame_round_trip_uses_staged_sender_activation() {
        let secret = vec![7; 16];
        let mut sender = Encryptor::default();
        let mut receiver = Decryptor::default();
        sender.stage_ratchet(HashRatchet::new(secret.clone()));
        receiver.transition_to_ratchet(HashRatchet::new(secret));

        assert!(!sender.ready());
        assert!(sender.activate_pending());

        let mut encrypted = Vec::new();
        sender
            .encrypt_into(MediaFrame::<Opus>::new(b"opus"), &mut encrypted)
            .unwrap();
        let mut decrypted = Vec::new();
        receiver
            .decrypt(MediaType::Audio, &encrypted, &mut decrypted)
            .unwrap();

        assert_eq!(decrypted, b"opus");
    }

    #[test]
    fn encrypt_into_writes_transformed_payload_to_caller_buffer() {
        let secret = vec![7; 16];
        let mut sender = Encryptor::default();
        let mut receiver = Decryptor::default();
        sender.stage_ratchet(HashRatchet::new(secret.clone()));
        receiver.transition_to_ratchet(HashRatchet::new(secret));
        assert!(sender.activate_pending());

        let mut encrypted = Vec::new();
        sender
            .encrypt_into(MediaFrame::<Opus>::new(b"opus"), &mut encrypted)
            .unwrap();

        assert_ne!(encrypted, b"opus");

        let mut decrypted = Vec::new();
        receiver
            .decrypt(MediaType::Audio, &encrypted, &mut decrypted)
            .unwrap();

        assert_eq!(decrypted, b"opus");
    }

    #[test]
    fn all_supported_codecs_round_trip() {
        assert_round_trip::<Opus>(b"opus", b"opus", MediaType::Audio);
        assert_round_trip::<Vp8>(
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            MediaType::Video,
        );
        assert_round_trip::<Vp9>(b"vp9-frame", b"vp9-frame", MediaType::Video);
        assert_round_trip::<H264>(
            &[0, 0, 0, 1, 0x65, 0xe0, 0x12, 0x34, 0x56, 0x78],
            &[0, 0, 0, 1, 0x65, 0xe0, 0x12, 0x34, 0x56, 0x78],
            MediaType::Video,
        );
        assert_round_trip::<H265>(
            &[0, 0, 0, 1, 0x26, 0x01, 0xaa, 0xbb, 0xcc],
            &[0, 0, 0, 1, 0x26, 0x01, 0xaa, 0xbb, 0xcc],
            MediaType::Video,
        );
        assert_round_trip::<Av1>(
            &[0b0000_1000, 0xaa, 0xbb, 0xcc],
            &[0b0000_1000, 0xaa, 0xbb, 0xcc],
            MediaType::Video,
        );
    }

    fn assert_round_trip<C>(payload: &[u8], expected: &[u8], media_type: MediaType)
    where
        C: FrameCodec,
    {
        let secret = vec![7; 16];
        let mut sender = Encryptor::default();
        let mut receiver = Decryptor::default();
        sender.stage_ratchet(HashRatchet::new(secret.clone()));
        receiver.transition_to_ratchet(HashRatchet::new(secret));
        assert!(sender.activate_pending());

        let mut encrypted = Vec::new();
        sender
            .encrypt_into(MediaFrame::<C>::new(payload), &mut encrypted)
            .unwrap();

        let mut decrypted = Vec::new();
        receiver
            .decrypt(media_type, &encrypted, &mut decrypted)
            .unwrap();

        assert_eq!(decrypted, expected);
    }

    #[test]
    fn decryptor_starts_with_plain_passthrough_disabled() {
        let mut decryptor = Decryptor::default();
        let mut decrypted = Vec::new();

        let error = decryptor
            .decrypt(MediaType::Audio, b"plain opus", &mut decrypted)
            .unwrap_err();

        assert_eq!(error, FrameDecryptError::PassthroughDisabled);
    }

    #[test]
    fn opus_silence_passthrough_is_always_accepted() {
        let mut decryptor = Decryptor::default();
        let mut decrypted = Vec::new();

        decryptor
            .decrypt(MediaType::Audio, &OPUS_SILENCE_FRAME, &mut decrypted)
            .unwrap();

        assert_eq!(decrypted, OPUS_SILENCE_FRAME);
    }

    #[test]
    fn opus_silence_exception_is_audio_only() {
        let mut decryptor = Decryptor::default();
        let mut decrypted = Vec::new();

        assert_eq!(
            decryptor.decrypt(MediaType::Video, &OPUS_SILENCE_FRAME, &mut decrypted),
            Err(FrameDecryptError::PassthroughDisabled)
        );
    }

    #[test]
    fn malformed_protocol_candidate_passes_only_when_passthrough_enabled() {
        let mut frame = b"plain opus".to_vec();
        frame.extend_from_slice(&[0; 8]);
        frame.push(3);
        frame.extend_from_slice(&[0xFA, 0xFA]);

        let mut decryptor = Decryptor::default();
        let mut decrypted = Vec::new();
        assert_eq!(
            decryptor.decrypt(MediaType::Audio, &frame, &mut decrypted),
            Err(FrameDecryptError::PassthroughDisabled)
        );

        decryptor.transition_to_passthrough(PassthroughMode::enabled());
        decryptor
            .decrypt(MediaType::Audio, &frame, &mut decrypted)
            .unwrap();
        assert_eq!(decrypted, frame);
    }

    #[test]
    fn disabled_after_does_not_open_disabled_plaintext_passthrough() {
        let mut decryptor = Decryptor::default();
        let mut decrypted = Vec::new();
        decryptor
            .transition_to_passthrough(PassthroughMode::disabled_after(Duration::from_secs(10)));

        assert_eq!(
            decryptor.decrypt(MediaType::Audio, b"plain opus", &mut decrypted),
            Err(FrameDecryptError::PassthroughDisabled)
        );
    }

    #[test]
    fn disabled_after_bounds_permanent_plaintext_passthrough() {
        let mut decryptor = Decryptor::default();
        decryptor.transition_to_passthrough(PassthroughMode::enabled());
        decryptor
            .transition_to_passthrough(PassthroughMode::disabled_after(Duration::from_secs(10)));

        assert!(decryptor.passthrough.allows_plaintext());
        assert!(decryptor.passthrough.until().is_some());
    }
}
