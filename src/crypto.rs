//! Cryptographic primitives of WalletConnect v2.
//!
//! * Peers agree on a symmetric key with X25519, then expand the shared
//!   secret with HKDF-SHA256 (no salt, no info) into 32 bytes.
//! * A topic is the hex-encoded SHA-256 of a key: `topic = sha256(sym_key)`.
//! * Messages travel inside base64 *envelopes*:
//!
//! | type | layout                                           | use                               |
//! |------|--------------------------------------------------|-----------------------------------|
//! | 0    | `0x00 ‖ iv(12) ‖ sealed`                         | everything once both share a key  |
//! | 1    | `0x01 ‖ sender_pub(32) ‖ iv(12) ‖ sealed`         | receiver doesn't know sender yet  |
//! | 2    | `0x02 ‖ plaintext`                               | unencrypted (link mode, auth)     |
//!
//! `sealed` is ChaCha20-Poly1305 ciphertext with the 16-byte tag appended
//! and no associated data.

use std::fmt;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub const KEY_LENGTH: usize = 32;
pub const IV_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

pub const TYPE_0: u8 = 0;
pub const TYPE_1: u8 = 1;
pub const TYPE_2: u8 = 2;

/// Base64 decoding that tolerates both the standard and the URL-safe
/// alphabet, padded or not (link-mode envelopes use base64url).
const STANDARD_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator failed");
    buf
}

/// Hex-encoded SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn decode_hex_32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| Error::InvalidKey(format!("{what}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidKey(format!("{what}: expected 32 bytes")))
}

// ---------------------------------------------------------------------------
// Topic
// ---------------------------------------------------------------------------

/// A relay topic: 32 bytes, hex encoded (64 chars).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Topic(String);

impl Topic {
    pub fn new(topic: impl Into<String>) -> Self {
        Topic(topic.into())
    }

    /// `sha256(key)` — how pairing and session topics are derived from their
    /// symmetric keys, and how response topics are derived from public keys.
    pub fn from_key(key: &[u8]) -> Self {
        Topic(sha256_hex(key))
    }

    /// A random topic (not tied to any key).
    pub fn generate() -> Self {
        Topic(hex::encode(random_bytes::<32>()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Topic({})", self.0)
    }
}

impl From<String> for Topic {
    fn from(s: String) -> Self {
        Topic(s)
    }
}

impl From<&str> for Topic {
    fn from(s: &str) -> Self {
        Topic(s.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

macro_rules! hex_serde {
    ($ty:ident, $what:literal) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(self.0))
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                decode_hex_32(&s, $what).map($ty).map_err(D::Error::custom)
            }
        }
    };
}

/// A 32-byte ChaCha20-Poly1305 key shared by the two peers of a pairing or a
/// session.
#[derive(Clone, PartialEq, Eq)]
pub struct SymKey([u8; KEY_LENGTH]);

hex_serde!(SymKey, "symmetric key");

impl SymKey {
    pub fn generate() -> Self {
        SymKey(random_bytes())
    }

    pub fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        SymKey(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        decode_hex_32(s, "symmetric key").map(SymKey)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }

    /// The topic messages encrypted with this key are published on.
    pub fn topic(&self) -> Topic {
        Topic::from_key(&self.0)
    }

    /// Seal `plaintext` into a type 0 envelope.
    pub fn encrypt(&self, plaintext: &[u8]) -> String {
        encrypt(self, plaintext, None)
    }

    /// Open a type 0 or type 1 envelope.
    pub fn decrypt(&self, encoded: &str) -> Result<Vec<u8>> {
        Envelope::decode(encoded)?.open(self)
    }
}

impl fmt::Debug for SymKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymKey(<redacted>)")
    }
}

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LENGTH]);

hex_serde!(PublicKey, "public key");

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        PublicKey(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        decode_hex_32(s, "public key").map(PublicKey)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }

    /// `sha256(public_key)`: the topic a type 1 response to this key goes to.
    pub fn topic(&self) -> Topic {
        Topic::from_key(&self.0)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

/// An X25519 key pair used for the session key agreement.
#[derive(Clone)]
pub struct KeyPair {
    secret: x25519_dalek::StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::from_secret(random_bytes())
    }

    pub fn from_secret(secret: [u8; KEY_LENGTH]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(secret);
        let public = PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes());
        KeyPair { secret, public }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn secret_bytes(&self) -> [u8; KEY_LENGTH] {
        self.secret.to_bytes()
    }

    /// `HKDF-SHA256(X25519(self, peer))`, the symmetric key both sides of a
    /// session end up with.
    pub fn derive_sym_key(&self, peer: &PublicKey) -> Result<SymKey> {
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer.0));
        if !shared.was_contributory() {
            return Err(Error::InvalidKey(
                "peer public key is a low-order point".into(),
            ));
        }
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut okm = [0u8; KEY_LENGTH];
        hkdf.expand(&[], &mut okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Ok(SymKey(okm))
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with `key`. With a `sender` public key the result is a
/// type 1 envelope, otherwise type 0.
pub fn encrypt(key: &SymKey, plaintext: &[u8], sender: Option<&PublicKey>) -> String {
    let iv: [u8; IV_LENGTH] = random_bytes();
    let sealed = ChaCha20Poly1305::new(&key.0.into())
        .encrypt(&iv.into(), plaintext)
        .expect("chacha20poly1305 encryption of an in-memory buffer cannot fail");
    Envelope {
        kind: if sender.is_some() { TYPE_1 } else { TYPE_0 },
        sender_public_key: sender.copied(),
        iv,
        sealed,
    }
    .encode()
}

/// Wrap `plaintext` in an (unencrypted) type 2 envelope.
pub fn encode_type2(plaintext: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(1 + plaintext.len());
    bytes.push(TYPE_2);
    bytes.extend_from_slice(plaintext);
    STANDARD.encode(bytes)
}

/// A decoded (but not yet decrypted) envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// [`TYPE_0`], [`TYPE_1`] or [`TYPE_2`].
    pub kind: u8,
    /// Present for type 1 envelopes.
    pub sender_public_key: Option<PublicKey>,
    /// Unused (all zero) for type 2 envelopes.
    pub iv: [u8; IV_LENGTH],
    /// Ciphertext and tag, or the plaintext for type 2.
    pub sealed: Vec<u8>,
}

impl Envelope {
    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = STANDARD_LENIENT
            .decode(encoded)
            .or_else(|_| URL_SAFE_LENIENT.decode(encoded))
            .map_err(|e| Error::InvalidEnvelope(format!("base64: {e}")))?;
        let (&kind, rest) = bytes
            .split_first()
            .ok_or_else(|| Error::InvalidEnvelope("empty".into()))?;
        let truncated = || Error::InvalidEnvelope(format!("type {kind} envelope is truncated"));
        match kind {
            TYPE_0 => {
                if rest.len() < IV_LENGTH + TAG_LENGTH {
                    return Err(truncated());
                }
                let (iv, sealed) = rest.split_at(IV_LENGTH);
                Ok(Envelope {
                    kind,
                    sender_public_key: None,
                    iv: iv.try_into().expect("split at IV_LENGTH"),
                    sealed: sealed.to_vec(),
                })
            }
            TYPE_1 => {
                if rest.len() < KEY_LENGTH + IV_LENGTH + TAG_LENGTH {
                    return Err(truncated());
                }
                let (pk, rest) = rest.split_at(KEY_LENGTH);
                let (iv, sealed) = rest.split_at(IV_LENGTH);
                Ok(Envelope {
                    kind,
                    sender_public_key: Some(PublicKey(pk.try_into().expect("split at KEY_LENGTH"))),
                    iv: iv.try_into().expect("split at IV_LENGTH"),
                    sealed: sealed.to_vec(),
                })
            }
            TYPE_2 => Ok(Envelope {
                kind,
                sender_public_key: None,
                iv: [0; IV_LENGTH],
                sealed: rest.to_vec(),
            }),
            other => Err(Error::InvalidEnvelope(format!("unknown type byte {other}"))),
        }
    }

    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(1 + KEY_LENGTH + IV_LENGTH + self.sealed.len());
        bytes.push(self.kind);
        if self.kind == TYPE_2 {
            bytes.extend_from_slice(&self.sealed);
            return STANDARD.encode(bytes);
        }
        if let Some(pk) = &self.sender_public_key {
            bytes.extend_from_slice(&pk.0);
        }
        bytes.extend_from_slice(&self.iv);
        bytes.extend_from_slice(&self.sealed);
        STANDARD.encode(bytes)
    }

    /// Decrypt with `key`. Type 2 envelopes are returned as-is.
    pub fn open(&self, key: &SymKey) -> Result<Vec<u8>> {
        if self.kind == TYPE_2 {
            return Ok(self.sealed.clone());
        }
        ChaCha20Poly1305::new(&key.0.into())
            .decrypt(&self.iv.into(), self.sealed.as_slice())
            .map_err(|_| Error::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_is_sha256_of_key() {
        // sha256 of 32 zero bytes
        let key = SymKey::from_bytes([0; 32]);
        assert_eq!(
            key.topic().as_str(),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    #[test]
    fn type0_roundtrip_and_tamper_detection() {
        let key = SymKey::generate();
        let enc = key.encrypt(b"hello");
        let env = Envelope::decode(&enc).unwrap();
        assert_eq!(env.kind, TYPE_0);
        assert_eq!(key.decrypt(&enc).unwrap(), b"hello");

        let other = SymKey::generate();
        assert!(matches!(other.decrypt(&enc), Err(Error::Decryption)));

        let mut env = env;
        env.sealed[0] ^= 1;
        assert!(matches!(env.open(&key), Err(Error::Decryption)));
    }

    #[test]
    fn type1_carries_sender_key() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        let key = sender.derive_sym_key(&receiver.public_key()).unwrap();
        let enc = encrypt(&key, b"{}", Some(&sender.public_key()));
        let env = Envelope::decode(&enc).unwrap();
        assert_eq!(env.kind, TYPE_1);
        assert_eq!(env.sender_public_key, Some(sender.public_key()));
        // The receiver can derive the same key from the embedded sender key.
        let rkey = receiver
            .derive_sym_key(&env.sender_public_key.unwrap())
            .unwrap();
        assert_eq!(env.open(&rkey).unwrap(), b"{}");
    }

    #[test]
    fn type2_is_plaintext() {
        let enc = encode_type2(b"{\"a\":1}");
        let env = Envelope::decode(&enc).unwrap();
        assert_eq!(env.kind, TYPE_2);
        assert_eq!(env.open(&SymKey::generate()).unwrap(), b"{\"a\":1}");
        assert_eq!(env.encode(), enc);
    }

    #[test]
    fn key_agreement_is_symmetric() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_eq!(
            a.derive_sym_key(&b.public_key()).unwrap(),
            b.derive_sym_key(&a.public_key()).unwrap()
        );
    }

    #[test]
    fn rejects_low_order_points() {
        let a = KeyPair::generate();
        assert!(a.derive_sym_key(&PublicKey::from_bytes([0; 32])).is_err());
    }

    #[test]
    fn rejects_malformed_envelopes() {
        assert!(Envelope::decode("").is_err());
        assert!(Envelope::decode("!!!").is_err());
        assert!(Envelope::decode(&STANDARD.encode([0u8; 10])).is_err());
        assert!(Envelope::decode(&STANDARD.encode([9u8; 40])).is_err());
    }

    #[test]
    fn accepts_base64url() {
        let key = SymKey::generate();
        // Find a ciphertext whose standard encoding uses '+' or '/'.
        let enc = loop {
            let e = key.encrypt(b"link mode payload");
            if e.contains('+') || e.contains('/') {
                break e;
            }
        };
        let url = enc.replace('+', "-").replace('/', "_").replace('=', "");
        assert_eq!(key.decrypt(&url).unwrap(), b"link mode payload");
    }
}
