//! Test vectors produced by the reference JavaScript SDK
//! (`@walletconnect/utils` and `@walletconnect/relay-auth` 2.26.0) from fixed
//! inputs. They pin key derivation, topic hashing, envelope layout, did:key,
//! the relay JWT and URI formatting to byte-for-byte compatibility.
//!
//! The X25519 keys are the RFC 7748 §6.1 test keys; the generator script lives
//! in `interop/js/vectors.mjs`.

use wallet_connect::auth::{IdentityKey, JwtClaims, decode_jwt, encode_jwt};
use wallet_connect::crypto::{
    Envelope, KeyPair, PublicKey, SymKey, TYPE_0, TYPE_1, TYPE_2, sha256_hex,
};
use wallet_connect::uri::PairingUri;

const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

const SYM_KEY: &str = "ea1d8a20f476d1e1ec952ca42708b8f7161ce7c81eadf97e520e2b40333decd5";
const TOPIC: &str = "1ca1d70db64cab0f93de5934e27f7114e8e9fd7dd3c7145d81ce7f2dd2cd05c8";
const MESSAGE: &str =
    r#"{"id":1700000000000123,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#;
const TYPE0: &str = "AAABAgMEBQYHCAkKC1NpmVwoe1LzFvoek58vLd24arS1IRoX7Xuy7Y9LTWmCaXYMYdSxZnpJPkmSlQmZJY11ozvc5V4BcxFXC1BwoXsl1jotdmaHy+/FURO43y9SSsSs96Cv5AUpWvll2g==";
const TYPE1: &str = "AYUg8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY6qm05qAAECAwQFBgcICQoLU2mZXCh7UvMW+h6Tny8t3bhqtLUhGhfte7Ltj0tNaYJpdgxh1LFmekk+SZKVCZkljXWjO9zlXgFzEVcLUHCheyXWOi12ZofL78VRE7jfL1JKxKz3oK/kBSla+WXa";
const TYPE2: &str = "AnsiaWQiOjE3MDAwMDAwMDAwMDAxMjMsImpzb25ycGMiOiIyLjAiLCJtZXRob2QiOiJ3Y19zZXNzaW9uUGluZyIsInBhcmFtcyI6e319";

const ISS: &str = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
const JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtlaFJnZjd5SmJnYUdmWXNkb0FzS2RCUEUzZGoyQ1lob3dRZGNqcVNKZ3ZWZCIsInN1YiI6ImM0NzlmZTVkYzQ2NGU3NzFlNzhiMTkzZDIzOWE2NWI1OGQyNzhjYWQxYzM0YmZiMGI1NzE2ZTViYjUxNDkyOGUiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0Lm9yZyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.mj-KbasSAjEbWHn-M0ooKXCr6PUE88T5rbawSJ3fr_ntVHqCC7dOQRlWIqgGeKk-J4Nb_PqgwW1PK6PR574VCA";
const URI: &str = "wc:1ca1d70db64cab0f93de5934e27f7114e8e9fd7dd3c7145d81ce7f2dd2cd05c8@2?expiryTimestamp=1700000300&relay-protocol=irn&symKey=ea1d8a20f476d1e1ec952ca42708b8f7161ce7c81eadf97e520e2b40333decd5";
const SUBSCRIPTION_ID: &str = "f91029aa5dd08dea5d1765c67d03dbbd0508a09d94b5b4a34b9706f9231c8a57";

fn alice() -> KeyPair {
    let secret: [u8; 32] = hex::decode(ALICE_PRIVATE).unwrap().try_into().unwrap();
    KeyPair::from_secret(secret)
}

#[test]
fn key_derivation_matches_reference() {
    let alice = alice();
    assert_eq!(alice.public_key().to_hex(), ALICE_PUBLIC);
    let sym = alice
        .derive_sym_key(&PublicKey::from_hex(BOB_PUBLIC).unwrap())
        .unwrap();
    assert_eq!(sym.to_hex(), SYM_KEY);
    assert_eq!(sym.topic().as_str(), TOPIC);
}

#[test]
fn reference_envelopes_decrypt_and_reencode_identically() {
    let key = SymKey::from_hex(SYM_KEY).unwrap();

    let e0 = Envelope::decode(TYPE0).unwrap();
    assert_eq!(e0.kind, TYPE_0);
    assert_eq!(e0.iv, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert_eq!(e0.open(&key).unwrap(), MESSAGE.as_bytes());
    assert_eq!(e0.encode(), TYPE0);

    let e1 = Envelope::decode(TYPE1).unwrap();
    assert_eq!(e1.kind, TYPE_1);
    assert_eq!(e1.sender_public_key.unwrap().to_hex(), ALICE_PUBLIC);
    assert_eq!(e1.open(&key).unwrap(), MESSAGE.as_bytes());
    assert_eq!(e1.encode(), TYPE1);

    let e2 = Envelope::decode(TYPE2).unwrap();
    assert_eq!(e2.kind, TYPE_2);
    assert_eq!(e2.sealed, MESSAGE.as_bytes());
    assert_eq!(
        wallet_connect::crypto::encode_type2(MESSAGE.as_bytes()),
        TYPE2
    );
}

#[test]
fn relay_jwt_matches_reference() {
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let identity = IdentityKey::from_seed(seed);
    assert_eq!(identity.client_id(), ISS);

    let claims = JwtClaims {
        iss: ISS.into(),
        sub: "c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e".into(),
        aud: "wss://relay.walletconnect.org".into(),
        iat: 1_700_000_000,
        exp: 1_700_086_400,
        act: None,
    };
    // Ed25519 is deterministic, so the whole token must match.
    assert_eq!(encode_jwt(&identity, &claims), JWT);
    assert_eq!(decode_jwt(JWT).unwrap(), claims);
}

#[test]
fn pairing_uri_matches_reference() {
    let uri = PairingUri::new(SymKey::from_hex(SYM_KEY).unwrap(), 1_700_000_300);
    assert_eq!(uri.to_string(), URI);
    assert_eq!(URI.parse::<PairingUri>().unwrap(), uri);
}

#[test]
fn subscription_id_is_hash_of_topic_and_client_id() {
    assert_eq!(
        sha256_hex(format!("{TOPIC}{ISS}").as_bytes()),
        SUBSCRIPTION_ID
    );
}
