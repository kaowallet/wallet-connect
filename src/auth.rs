//! Relay client authentication.
//!
//! Every relay client owns a long-lived Ed25519 key. Its `did:key` form is
//! the client id, and on connect the client presents a short-lived JWT
//! (`alg: EdDSA`) signed with that key in the `auth` query parameter:
//!
//! ```text
//! {"alg":"EdDSA","typ":"JWT"} . {"iss":"did:key:z6Mk…","sub":"<random>","aud":"wss://relay…","iat":…,"exp":…} . sig
//! ```

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use crate::time::now_secs;

pub const DID_KEY_PREFIX: &str = "did:key:";
/// Multicodec prefix of an Ed25519 public key (varint 0xed).
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];
/// Multibase prefix for base58btc.
const MULTIBASE_BASE58BTC: char = 'z';

pub const JWT_ALG: &str = "EdDSA";
pub const JWT_TYP: &str = "JWT";

/// Lifetime of the connection JWT used by the reference SDK.
pub const DEFAULT_JWT_TTL: Duration = Duration::from_secs(crate::time::ONE_DAY);

/// The relay identity of a client.
#[derive(Clone)]
pub struct IdentityKey(SigningKey);

impl IdentityKey {
    pub fn generate() -> Self {
        Self::from_seed(random_bytes())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        IdentityKey(SigningKey::from_bytes(&seed))
    }

    /// The 32-byte seed; persist it to keep the same client id across
    /// restarts (the relay keeps undelivered messages per client id).
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// `did:key:z6Mk…` — the client id the relay knows this client by.
    pub fn client_id(&self) -> String {
        encode_did_key(&self.public_key())
    }

    /// A connection JWT for relay `aud` with a random subject.
    pub fn sign_jwt(&self, aud: &str, ttl: Duration) -> String {
        let iat = now_secs();
        let claims = JwtClaims {
            iss: self.client_id(),
            sub: hex::encode(random_bytes::<32>()),
            aud: aud.to_owned(),
            iat,
            exp: iat + ttl.as_secs(),
            act: None,
        };
        encode_jwt(self, &claims)
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKey({})", self.client_id())
    }
}

/// `did:key` encoding of an Ed25519 public key.
pub fn encode_did_key(public_key: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&MULTICODEC_ED25519);
    bytes.extend_from_slice(public_key);
    format!(
        "{DID_KEY_PREFIX}{MULTIBASE_BASE58BTC}{}",
        bs58::encode(bytes).into_string()
    )
}

/// Inverse of [`encode_did_key`].
pub fn decode_did_key(did: &str) -> Result<[u8; 32]> {
    let multibase = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| Error::InvalidJwt(format!("issuer is not a did:key: {did}")))?;
    let encoded = multibase
        .strip_prefix(MULTIBASE_BASE58BTC)
        .ok_or_else(|| Error::InvalidJwt("did:key must be base58btc multibase".into()))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| Error::InvalidJwt(format!("did:key base58: {e}")))?;
    let key = bytes
        .strip_prefix(&MULTICODEC_ED25519)
        .ok_or_else(|| Error::InvalidJwt("did:key is not an Ed25519 key".into()))?;
    key.try_into()
        .map_err(|_| Error::InvalidJwt("did:key Ed25519 key must be 32 bytes".into()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// Claims of a relay auth JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// `did:key` of the signer.
    pub iss: String,
    pub sub: String,
    /// The relay URL the token is meant for.
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
}

fn b64_json<T: Serialize>(value: &T) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("jwt parts serialize"))
}

/// Sign `claims` with `key`. The claims' `iss` should be `key.client_id()`.
pub fn encode_jwt(key: &IdentityKey, claims: &JwtClaims) -> String {
    let header = JwtHeader {
        alg: JWT_ALG.into(),
        typ: JWT_TYP.into(),
    };
    let data = format!("{}.{}", b64_json(&header), b64_json(claims));
    let signature = key.0.sign(data.as_bytes());
    format!("{data}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// Check the signature of `jwt` against the key in its `iss` claim and
/// return the claims. Expiry is *not* checked; see [`verify_jwt`].
pub fn decode_jwt(jwt: &str) -> Result<JwtClaims> {
    let invalid = |m: &str| Error::InvalidJwt(m.to_owned());
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("expected three dot-separated parts"));
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part.trim_end_matches('='))
            .map_err(|e| Error::InvalidJwt(format!("base64url: {e}")))
    };
    let header: JwtHeader = serde_json::from_slice(&decode(h)?)
        .map_err(|e| Error::InvalidJwt(format!("header: {e}")))?;
    if header.alg != JWT_ALG || header.typ != JWT_TYP {
        return Err(invalid("JWT must use the EdDSA algorithm"));
    }
    let claims: JwtClaims = serde_json::from_slice(&decode(p)?)
        .map_err(|e| Error::InvalidJwt(format!("claims: {e}")))?;
    let public_key = decode_did_key(&claims.iss)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| Error::InvalidJwt(format!("issuer key: {e}")))?;
    let signature: [u8; 64] = decode(s)?
        .try_into()
        .map_err(|_| invalid("signature must be 64 bytes"))?;
    verifying_key
        .verify_strict(
            format!("{h}.{p}").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| invalid("bad signature"))?;
    Ok(claims)
}

/// [`decode_jwt`] plus an expiry check.
pub fn verify_jwt(jwt: &str) -> Result<JwtClaims> {
    let claims = decode_jwt(jwt)?;
    if claims.exp <= now_secs() {
        return Err(Error::InvalidJwt("token expired".into()));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_roundtrip() {
        let key = IdentityKey::generate();
        let did = key.client_id();
        assert!(did.starts_with("did:key:z6Mk"), "{did}");
        assert_eq!(decode_did_key(&did).unwrap(), key.public_key());
    }

    #[test]
    fn did_key_known_vector() {
        // From the did:key spec test vectors (Ed25519).
        let did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        let pk = decode_did_key(did).unwrap();
        assert_eq!(encode_did_key(&pk), did);
    }

    #[test]
    fn jwt_roundtrip_and_tampering() {
        let key = IdentityKey::generate();
        let jwt = key.sign_jwt("wss://relay.walletconnect.org", DEFAULT_JWT_TTL);
        let claims = verify_jwt(&jwt).unwrap();
        assert_eq!(claims.iss, key.client_id());
        assert_eq!(claims.aud, "wss://relay.walletconnect.org");
        assert_eq!(claims.exp - claims.iat, DEFAULT_JWT_TTL.as_secs());

        // Swap in a different issuer: signature no longer matches.
        let other = IdentityKey::generate();
        let forged = JwtClaims {
            iss: other.client_id(),
            ..claims.clone()
        };
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let forged_payload = b64_json(&forged);
        parts[1] = &forged_payload;
        assert!(decode_jwt(&parts.join(".")).is_err());
    }

    #[test]
    fn expired_jwt_is_rejected() {
        let key = IdentityKey::generate();
        let claims = JwtClaims {
            iss: key.client_id(),
            sub: "s".into(),
            aud: "a".into(),
            iat: 1,
            exp: 2,
            act: None,
        };
        let jwt = encode_jwt(&key, &claims);
        assert_eq!(decode_jwt(&jwt).unwrap(), claims);
        assert!(verify_jwt(&jwt).is_err());
    }
}
