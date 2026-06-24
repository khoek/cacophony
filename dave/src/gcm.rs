use aead::{Error, Key, KeyInit, KeySizeUser};
use aes::Aes128;
use cipher::{BlockCipherEncrypt, InnerIvInit, StreamCipherCore, array::Array, consts::U16};
use ctr::{CtrCore, flavors::Ctr32BE};
use ghash::{GHash, universal_hash::UniversalHash};
use subtle::ConstantTimeEq;

type Block = Array<u8, U16>;

#[derive(Clone)]
pub(crate) struct Aes128Gcm8 {
    cipher: Aes128,
    ghash: GHash,
}

impl KeySizeUser for Aes128Gcm8 {
    type KeySize = <Aes128 as cipher::KeySizeUser>::KeySize;
}

impl KeyInit for Aes128Gcm8 {
    fn new(key: &Key<Self>) -> Self {
        let cipher = <Aes128 as cipher::KeyInit>::new(key);
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);
        Self {
            cipher,
            ghash: GHash::new(&ghash_key),
        }
    }
}

impl Aes128Gcm8 {
    pub(crate) fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; 12],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 8], Error> {
        let (ctr, mask) = self.init_ctr(nonce);
        ctr.apply_keystream_partial(buffer.into());
        let tag = self.compute_tag(mask, associated_data, buffer);
        let mut truncated = [0_u8; 8];
        truncated.copy_from_slice(&tag[..8]);
        Ok(truncated)
    }

    pub(crate) fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; 12],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let (ctr, mask) = self.init_ctr(nonce);
        let expected = self.compute_tag(mask, associated_data, buffer);
        if expected[..8].ct_eq(tag).into() {
            ctr.apply_keystream_partial(buffer.into());
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn init_ctr(&self, nonce: &[u8; 12]) -> (CtrCore<&Aes128, Ctr32BE>, Block) {
        let mut j0 = ghash::Block::default();
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let mut ctr = CtrCore::<_, Ctr32BE>::inner_iv_init(&self.cipher, &j0);
        let mut mask = Block::default();
        ctr.write_keystream_block(&mut mask);
        (ctr, mask)
    }

    fn compute_tag(&self, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Block {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let mut lengths = ghash::Block::default();
        lengths[..8].copy_from_slice(&((associated_data.len() as u64) * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&((buffer.len() as u64) * 8).to_be_bytes());
        ghash.update(&[lengths]);

        let mut tag = ghash.finalize();
        for (tag, mask) in tag.iter_mut().zip(mask.iter()) {
            *tag ^= *mask;
        }
        tag
    }
}
