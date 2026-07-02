use std::fmt;

use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use p256::{
    ecdsa::{Signature as P256Signature, SigningKey, signature::Signer},
    elliptic_curve::rand_core::OsRng,
};
use scrypt::{Params as ScryptParams, scrypt};
use zeroize::Zeroize;

use crate::error::{DisplayableCodeError, FingerprintError, IdentityKeyError};

pub const DAVE_IDENTITY_KEY_VERSION: u16 = 1;
pub const PAIRWISE_FINGERPRINT_BYTES: usize = 64;
pub const PAIRWISE_FINGERPRINT_DISPLAY_DIGITS: usize = 45;
pub const EPOCH_AUTHENTICATOR_DISPLAY_DIGITS: usize = 30;
pub const DISPLAY_CODE_GROUP_DIGITS: usize = 5;

const PAIRWISE_FINGERPRINT_VERSION: [u8; 2] = [0, 0];
const PAIRWISE_FINGERPRINT_SALT: [u8; 16] = [
    0x24, 0xca, 0xb1, 0x7a, 0x7a, 0xf8, 0xec, 0x2b, 0x82, 0xb4, 0x12, 0xb9, 0x2d, 0xab, 0x19, 0x2e,
];
const PAIRWISE_FINGERPRINT_LOG_N: u8 = 14;
const PAIRWISE_FINGERPRINT_R: u32 = 8;
const PAIRWISE_FINGERPRINT_P: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityKeyPersistence {
    Ephemeral,
    Persistent,
}

pub struct IdentityKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    persistence: IdentityKeyPersistence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPublicKeyUpload {
    pub key_version: u16,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl IdentityKeyPair {
    pub fn generate(persistence: IdentityKeyPersistence) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self {
            private_key: signing_key.to_bytes().to_vec(),
            public_key: signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            persistence,
        }
    }

    pub fn from_p256_private_key(
        mut private_key: Vec<u8>,
        persistence: IdentityKeyPersistence,
    ) -> Result<Self, IdentityKeyError> {
        let signing_key = match SigningKey::from_bytes(private_key.as_slice().into()) {
            Ok(signing_key) => signing_key,
            Err(_) => {
                private_key.zeroize();
                return Err(IdentityKeyError::InvalidP256PrivateKey);
            }
        };
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Ok(Self {
            private_key,
            public_key,
            persistence,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn persistence(&self) -> IdentityKeyPersistence {
        self.persistence
    }

    pub fn duplicate_for_session(&self) -> Self {
        Self {
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
            persistence: self.persistence,
        }
    }

    pub fn persistent_public_key_upload(
        &self,
        client_auth_session_id: &str,
    ) -> Result<IdentityPublicKeyUpload, IdentityKeyError> {
        if self.persistence != IdentityKeyPersistence::Persistent {
            return Err(IdentityKeyError::EphemeralPublicKeyUpload);
        }
        let signable_data =
            persistent_public_key_signable_data(client_auth_session_id, &self.public_key)?;
        let signature: P256Signature = SigningKey::from_bytes(self.private_key.as_slice().into())
            .map_err(|_| IdentityKeyError::InvalidP256PrivateKey)?
            .sign(&signable_data);
        Ok(IdentityPublicKeyUpload {
            key_version: DAVE_IDENTITY_KEY_VERSION,
            public_key: self.public_key.clone(),
            signature: signature.to_der().as_bytes().to_vec(),
        })
    }

    pub(crate) fn into_signer(mut self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            std::mem::take(&mut self.private_key),
            std::mem::take(&mut self.public_key),
        )
    }
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityKeyPair")
            .field("private_key", &"***")
            .field("public_key", &self.public_key)
            .field("persistence", &self.persistence)
            .finish()
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPublicKey {
    pub user_id: u64,
    pub public_key: Vec<u8>,
}

#[derive(Default)]
pub enum SessionIdentity {
    #[default]
    Ephemeral,
    KeyPair(IdentityKeyPair),
}

impl SessionIdentity {
    pub fn ephemeral() -> Self {
        Self::Ephemeral
    }

    pub fn key_pair(key_pair: IdentityKeyPair) -> Self {
        Self::KeyPair(key_pair)
    }
}

impl fmt::Debug for SessionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ephemeral => formatter.write_str("SessionIdentity::Ephemeral"),
            Self::KeyPair(key_pair) => formatter
                .debug_tuple("SessionIdentity::KeyPair")
                .field(key_pair)
                .finish(),
        }
    }
}

pub fn pairwise_fingerprint(
    local: &IdentityPublicKey,
    remote: &IdentityPublicKey,
) -> Result<[u8; PAIRWISE_FINGERPRINT_BYTES], FingerprintError> {
    let mut inputs = [
        pairwise_fingerprint_input(local),
        pairwise_fingerprint_input(remote),
    ];
    if inputs[1] < inputs[0] {
        inputs.swap(0, 1);
    }

    let mut passphrase = Vec::with_capacity(inputs[0].len() + inputs[1].len());
    passphrase.extend_from_slice(&inputs[0]);
    passphrase.extend_from_slice(&inputs[1]);

    let mut fingerprint = [0; PAIRWISE_FINGERPRINT_BYTES];
    let params = ScryptParams::new(
        PAIRWISE_FINGERPRINT_LOG_N,
        PAIRWISE_FINGERPRINT_R,
        PAIRWISE_FINGERPRINT_P,
    )
    .map_err(|_| FingerprintError::InvalidScryptParams)?;
    scrypt(
        &passphrase,
        &PAIRWISE_FINGERPRINT_SALT,
        &params,
        &mut fingerprint,
    )
    .map_err(|_| FingerprintError::InvalidOutputLength)?;
    passphrase.zeroize();
    Ok(fingerprint)
}

pub fn pairwise_fingerprint_display_code(
    fingerprint: &[u8],
) -> Result<String, DisplayableCodeError> {
    displayable_code(
        fingerprint,
        PAIRWISE_FINGERPRINT_DISPLAY_DIGITS,
        DISPLAY_CODE_GROUP_DIGITS,
    )
}

pub fn epoch_authenticator_display_code(
    authenticator: &[u8],
) -> Result<String, DisplayableCodeError> {
    displayable_code(
        authenticator,
        EPOCH_AUTHENTICATOR_DISPLAY_DIGITS,
        DISPLAY_CODE_GROUP_DIGITS,
    )
}

pub fn displayable_code(
    input: &[u8],
    digit_count: usize,
    group_digits: usize,
) -> Result<String, DisplayableCodeError> {
    if group_digits == 0 || group_digits >= 8 {
        return Err(DisplayableCodeError::InvalidGroupSize(group_digits));
    }
    if digit_count == 0 || digit_count % group_digits != 0 {
        return Err(DisplayableCodeError::InvalidDigitCount {
            digit_count,
            group_digits,
        });
    }
    if input.len() < digit_count {
        return Err(DisplayableCodeError::InputTooShort {
            actual: input.len(),
            required: digit_count,
        });
    }

    let modulus = 10_u64.pow(group_digits as u32);
    let mut code = String::with_capacity(digit_count);
    for chunk in input[..digit_count].chunks_exact(group_digits) {
        let value = chunk
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        code.push_str(&format!(
            "{:0width$}",
            value % modulus,
            width = group_digits
        ));
    }
    Ok(code)
}

fn pairwise_fingerprint_input(identity: &IdentityPublicKey) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        PAIRWISE_FINGERPRINT_VERSION.len() + identity.public_key.len() + size_of::<u64>(),
    );
    input.extend_from_slice(&PAIRWISE_FINGERPRINT_VERSION);
    input.extend_from_slice(&identity.public_key);
    input.extend_from_slice(&identity.user_id.to_be_bytes());
    input
}

fn persistent_public_key_signable_data(
    client_auth_session_id: &str,
    public_key: &[u8],
) -> Result<Vec<u8>, IdentityKeyError> {
    if client_auth_session_id.is_empty() {
        return Err(IdentityKeyError::EmptyClientAuthSessionId);
    }

    let mut context = Vec::with_capacity(client_auth_session_id.len() + 1 + public_key.len());
    context.extend_from_slice(client_auth_session_id.as_bytes());
    context.push(b':');
    context.extend_from_slice(public_key);

    let mut signable_data =
        Vec::with_capacity(1 + b"MLS 1.0 DiscordSelfSignature".len() + 4 + context.len());
    signable_data.push(b"MLS 1.0 DiscordSelfSignature".len() as u8);
    signable_data.extend_from_slice(b"MLS 1.0 DiscordSelfSignature");
    signable_data.extend_from_slice(&mls_varint(context.len())?);
    signable_data.extend_from_slice(&context);
    Ok(signable_data)
}

fn mls_varint(value: usize) -> Result<Vec<u8>, IdentityKeyError> {
    if value < 0x40 {
        Ok(vec![value as u8])
    } else if value < 0x4000 {
        Ok((0x4000 | value as u16).to_be_bytes().to_vec())
    } else if value < 0x4000_0000 {
        Ok((0x8000_0000 | value as u32).to_be_bytes().to_vec())
    } else {
        Err(IdentityKeyError::MlsVectorTooLarge(value))
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier};

    use super::{
        IdentityKeyPair, IdentityKeyPersistence::Ephemeral, IdentityKeyPersistence::Persistent,
        persistent_public_key_signable_data,
    };
    use crate::{DAVE_IDENTITY_KEY_VERSION, IdentityKeyError};

    #[test]
    fn generated_identity_key_has_p256_public_key() {
        let key_pair = IdentityKeyPair::generate(Ephemeral);

        VerifyingKey::from_sec1_bytes(key_pair.public_key()).unwrap();
        assert_eq!(key_pair.persistence(), Ephemeral);
    }

    #[test]
    fn persistent_public_key_upload_signs_mls_self_signature_payload() {
        let key_pair = IdentityKeyPair::from_p256_private_key(vec![1; 32], Persistent).unwrap();
        let upload = key_pair
            .persistent_public_key_upload("auth-session")
            .unwrap();
        let signature = P256Signature::from_der(&upload.signature).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&upload.public_key).unwrap();

        assert_eq!(upload.key_version, DAVE_IDENTITY_KEY_VERSION);
        verifying_key
            .verify(
                &persistent_public_key_signable_data("auth-session", &upload.public_key).unwrap(),
                &signature,
            )
            .unwrap();
    }

    #[test]
    fn persistent_public_key_upload_rejects_ephemeral_keys_and_empty_auth_session_ids() {
        let ephemeral = IdentityKeyPair::from_p256_private_key(vec![1; 32], Ephemeral).unwrap();
        assert!(matches!(
            ephemeral.persistent_public_key_upload("auth-session"),
            Err(IdentityKeyError::EphemeralPublicKeyUpload)
        ));

        let persistent = IdentityKeyPair::from_p256_private_key(vec![1; 32], Persistent).unwrap();
        assert!(matches!(
            persistent.persistent_public_key_upload(""),
            Err(IdentityKeyError::EmptyClientAuthSessionId)
        ));
    }
}
