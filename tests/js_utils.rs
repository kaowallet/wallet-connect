//! Port of the `@walletconnect/utils` 2.26.0 test suite
//! (`packages/utils/test/{crypto,uri,validators,misc}.spec.ts` in
//! WalletConnect/walletconnect-monorepo).
//!
//! Fixtures are copied verbatim from the JS tests. Tests for features this
//! crate does not implement (Verify P-256 JWTs, CACAO/SIWE, deep links,
//! `isSessionCompatible`/`find`) are not ported; see `docs/js-test-port.md`.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde_json::{Value, json};
use wallet_connect::crypto::{
    Envelope, KeyPair, PublicKey, SymKey, TYPE_0, TYPE_1, TYPE_2, Topic, encode_type2, sha256_hex,
};
use wallet_connect::rpc::ErrorObject;
use wallet_connect::sign::namespaces::{ensure_conforming, merge_required_and_optional};
use wallet_connect::sign::{
    InternalError, ProposalNamespaces, SdkError, SessionNamespaces, SupportedNamespace,
    build_approved_namespaces,
};
use wallet_connect::time::{SEVEN_DAYS, expiry_in, is_expired, now_secs};
use wallet_connect::uri::PairingUri;

fn from_json<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).expect("fixture matches the type")
}

// ---------------------------------------------------------------------------
// crypto.spec.ts
// ---------------------------------------------------------------------------

mod crypto {
    use super::*;

    // test/shared/values.ts
    const KEY_PAIR_A_PRIVATE: &str =
        "1fb63fca5c6ac731246f2f069d3bc2454345d5208254aa8ea7bffc6d110c8862";
    const KEY_PAIR_A_PUBLIC: &str =
        "ff7a7d5767c362b0a17ad92299ebdb7831dcbd9a56959c01368c7404543b3342";
    const KEY_PAIR_B_PRIVATE: &str =
        "36bf507903537de91f5e573666eaa69b1fa313974f23b2b59645f20fea505854";
    const KEY_PAIR_B_PUBLIC: &str =
        "590c2c627be7af08597091ff80dd41f7fa28acd10ef7191d7e830e116d3a186a";
    const TEST_SHARED_KEY: &str =
        "9c87e48e69b33a613907515bcd5b1b4cc10bbaf15167b19804b00f0a9217e607";
    const TEST_HASHED_KEY: &str =
        "a492906ccc809a411bb53a84572b57329375378c6ad7566f3e1c688200123e77";
    const TEST_SYM_KEY: &str = "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c";

    // test/crypto.spec.ts
    const TEST_MESSAGE: &str = r#"{"id":1,"jsonrpc":"2.0","method":"test_method","params":{}}"#;
    const TEST_IV: &str = "717765636661617364616473";
    const TEST_SEALED: &str = "7a5a1e843debf98b01d6a75718b5ee27115eafa3caba9703ca1c5601a6af2419045320faec2073cc8b6b8dc439e63e21612ff3883c867e0bdcd72c833eb7f7bb2034a9ec35c2fb03d93732";
    const TEST_ENCODED_TYPE_0: &str = "AHF3ZWNmYWFzZGFkc3paHoQ96/mLAdanVxi17icRXq+jyrqXA8ocVgGmryQZBFMg+uwgc8yLa43EOeY+IWEv84g8hn4L3Ncsgz6397sgNKnsNcL7A9k3Mg==";
    const TEST_ENCODED_TYPE_0_BASE64URL: &str = "AHF3ZWNmYWFzZGFkc3paHoQ96_mLAdanVxi17icRXq-jyrqXA8ocVgGmryQZBFMg-uwgc8yLa43EOeY-IWEv84g8hn4L3Ncsgz6397sgNKnsNcL7A9k3Mg";
    const TEST_ENCODED_TYPE_1: &str = "Af96fVdnw2KwoXrZIpnr23gx3L2aVpWcATaMdARUOzNCcXdlY2ZhYXNkYWRzeloehD3r+YsB1qdXGLXuJxFer6PKupcDyhxWAaavJBkEUyD67CBzzItrjcQ55j4hYS/ziDyGfgvc1yyDPrf3uyA0qew1wvsD2Tcy";
    const TEST_ENCODED_TYPE_1_BASE64URL: &str = "Af96fVdnw2KwoXrZIpnr23gx3L2aVpWcATaMdARUOzNCcXdlY2ZhYXNkYWRzeloehD3r-YsB1qdXGLXuJxFer6PKupcDyhxWAaavJBkEUyD67CBzzItrjcQ55j4hYS_ziDyGfgvc1yyDPrf3uyA0qew1wvsD2Tcy";
    const TEST_ENCODED_TYPE_2: &str =
        "AnsiaWQiOjEsImpzb25ycGMiOiIyLjAiLCJtZXRob2QiOiJ0ZXN0X21ldGhvZCIsInBhcmFtcyI6e319";
    const TEST_HASHED_MESSAGE: &str =
        "15112289b5b794e68d1ea3cd91330db55582a37d0596f7b99ea8becdf9d10496";

    fn key_pair(private: &str) -> KeyPair {
        KeyPair::from_secret(hex::decode(private).unwrap().try_into().unwrap())
    }

    fn sym_key() -> SymKey {
        SymKey::from_hex(TEST_SYM_KEY).unwrap()
    }

    #[test]
    fn generate_random_bytes32() {
        assert_eq!(Topic::generate().as_str().len(), 64); // hex
        assert_eq!(SymKey::generate().to_hex().len(), 64);
        assert_ne!(Topic::generate(), Topic::generate());
    }

    #[test]
    fn generate_key_pair() {
        let kp = KeyPair::generate();
        assert_eq!(hex::encode(kp.secret_bytes()).len(), 64);
        assert_eq!(kp.public_key().to_hex().len(), 64);
        assert_eq!(
            KeyPair::from_secret(kp.secret_bytes()).public_key(),
            kp.public_key()
        );
    }

    #[test]
    fn generate_key_pair_cross_test() {
        // Key pairs from independent generations agree on the shared key.
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_eq!(
            a.derive_sym_key(&b.public_key()).unwrap(),
            b.derive_sym_key(&a.public_key()).unwrap()
        );
    }

    #[test]
    fn generate_key_pair_same_random() {
        // The JS test stubs `crypto.getRandomValues` to return 32 bytes of 0x01
        // and compares against @stablelib/x25519; the expected public key was
        // computed with @noble/curves (the SDK's X25519 implementation).
        let kp = KeyPair::from_secret([1; 32]);
        assert_eq!(
            kp.public_key().to_hex(),
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
        );
    }

    #[test]
    fn key_pairs_match_fixtures() {
        assert_eq!(
            key_pair(KEY_PAIR_A_PRIVATE).public_key().to_hex(),
            KEY_PAIR_A_PUBLIC
        );
        assert_eq!(
            key_pair(KEY_PAIR_B_PRIVATE).public_key().to_hex(),
            KEY_PAIR_B_PUBLIC
        );
    }

    #[test]
    fn derive_sym_key() {
        let a = key_pair(KEY_PAIR_A_PRIVATE);
        let b = key_pair(KEY_PAIR_B_PRIVATE);
        let sym_a = a
            .derive_sym_key(&PublicKey::from_hex(KEY_PAIR_B_PUBLIC).unwrap())
            .unwrap();
        assert_eq!(sym_a.to_hex(), TEST_SYM_KEY);
        let sym_b = b
            .derive_sym_key(&PublicKey::from_hex(KEY_PAIR_A_PUBLIC).unwrap())
            .unwrap();
        assert_eq!(sym_b.to_hex(), TEST_SYM_KEY);
    }

    #[test]
    fn hash_key() {
        let shared = hex::decode(TEST_SHARED_KEY).unwrap();
        assert_eq!(Topic::from_key(&shared).as_str(), TEST_HASHED_KEY);
        assert_eq!(
            SymKey::from_hex(TEST_SHARED_KEY).unwrap().topic().as_str(),
            TEST_HASHED_KEY
        );
    }

    #[test]
    fn hash_message() {
        assert_eq!(sha256_hex(TEST_MESSAGE.as_bytes()), TEST_HASHED_MESSAGE);
    }

    /// The JS `encrypt (type 0)` test seals with a fixed IV and compares the
    /// envelope; ChaCha20-Poly1305 is deterministic, so decoding the reference
    /// envelope into the same IV and sealed bytes (and re-encoding it
    /// identically) pins the same layout.
    #[test]
    fn encrypt_type_0() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_0).unwrap();
        assert_eq!(envelope.kind, TYPE_0);
        assert_eq!(hex::encode(envelope.iv), TEST_IV);
        assert_eq!(hex::encode(&envelope.sealed), TEST_SEALED);
        assert_eq!(envelope.encode(), TEST_ENCODED_TYPE_0);
    }

    #[test]
    fn decrypt_type_0() {
        assert_eq!(
            sym_key().decrypt(TEST_ENCODED_TYPE_0).unwrap(),
            TEST_MESSAGE.as_bytes()
        );
        // And our own type 0 envelopes decrypt to the same message.
        let ours = sym_key().encrypt(TEST_MESSAGE.as_bytes());
        assert_eq!(sym_key().decrypt(&ours).unwrap(), TEST_MESSAGE.as_bytes());
    }

    #[test]
    fn encrypt_type_0_for_link_mode() {
        // Link mode uses base64url without padding; the layout is the same.
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_0_BASE64URL).unwrap();
        assert_eq!(hex::encode(envelope.iv), TEST_IV);
        assert_eq!(hex::encode(&envelope.sealed), TEST_SEALED);
        assert_eq!(envelope, Envelope::decode(TEST_ENCODED_TYPE_0).unwrap());
    }

    #[test]
    fn decrypt_type_0_for_link_mode() {
        assert_eq!(
            sym_key().decrypt(TEST_ENCODED_TYPE_0_BASE64URL).unwrap(),
            TEST_MESSAGE.as_bytes()
        );
    }

    #[test]
    fn encrypt_type_1() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_1).unwrap();
        assert_eq!(envelope.kind, TYPE_1);
        assert_eq!(
            envelope.sender_public_key.unwrap().to_hex(),
            KEY_PAIR_A_PUBLIC
        );
        assert_eq!(hex::encode(envelope.iv), TEST_IV);
        assert_eq!(hex::encode(&envelope.sealed), TEST_SEALED);
        assert_eq!(envelope.encode(), TEST_ENCODED_TYPE_1);
    }

    #[test]
    fn decrypt_type_1() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_1).unwrap();
        let sender = envelope.sender_public_key.unwrap();
        assert_eq!(sender.to_hex(), KEY_PAIR_A_PUBLIC);
        // The receiver derives the key from the embedded sender key.
        let sym = key_pair(KEY_PAIR_B_PRIVATE)
            .derive_sym_key(&sender)
            .unwrap();
        assert_eq!(sym.to_hex(), TEST_SYM_KEY);
        assert_eq!(
            sym.decrypt(TEST_ENCODED_TYPE_1).unwrap(),
            TEST_MESSAGE.as_bytes()
        );
    }

    #[test]
    fn encrypt_type_1_for_link_mode() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_1_BASE64URL).unwrap();
        assert_eq!(envelope, Envelope::decode(TEST_ENCODED_TYPE_1).unwrap());
        assert_eq!(hex::encode(&envelope.sealed), TEST_SEALED);
    }

    #[test]
    fn decrypt_type_1_for_link_mode() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_1_BASE64URL).unwrap();
        let sym = key_pair(KEY_PAIR_B_PRIVATE)
            .derive_sym_key(&envelope.sender_public_key.unwrap())
            .unwrap();
        assert_eq!(envelope.open(&sym).unwrap(), TEST_MESSAGE.as_bytes());
    }

    #[test]
    fn encode_type_2_for_link_mode() {
        assert_eq!(encode_type2(TEST_MESSAGE.as_bytes()), TEST_ENCODED_TYPE_2);
    }

    #[test]
    fn decode_type_2_for_link_mode() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_2).unwrap();
        assert_eq!(envelope.kind, TYPE_2);
        assert_eq!(envelope.sealed, TEST_MESSAGE.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// uri.spec.ts (+ toBase64/fromBase64 from misc.spec.ts)
// ---------------------------------------------------------------------------

mod uri {
    use super::*;

    const TEST_PAIRING_TOPIC: &str =
        "c9e6d30fb34afe70a15c14e9337ba8e4d5a35dd695c39b94884b0ee60c69d168";
    const TEST_SYM_KEY: &str = "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c";

    fn uri_params(topic: &str) -> PairingUri {
        PairingUri {
            topic: Topic::new(topic),
            version: 2,
            sym_key: SymKey::from_hex(TEST_SYM_KEY).unwrap(),
            relay_protocol: "irn".into(),
            relay_data: None,
            expiry_timestamp: None,
            methods: None,
        }
    }

    fn uri_string() -> String {
        format!("wc:{TEST_PAIRING_TOPIC}@2?relay-protocol=irn&symKey={TEST_SYM_KEY}")
    }

    #[test]
    fn format_uri() {
        assert_eq!(uri_params(TEST_PAIRING_TOPIC).to_string(), uri_string());
    }

    #[test]
    fn parse_uri() {
        let parsed: PairingUri = uri_string().parse().unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.topic.as_str(), TEST_PAIRING_TOPIC);
        assert_eq!(parsed.sym_key.to_hex(), TEST_SYM_KEY);
        assert_eq!(parsed.relay_data, None);
        assert_eq!(parsed.relay_protocol, "irn");
        assert_eq!(parsed, uri_params(TEST_PAIRING_TOPIC));
    }

    #[test]
    fn parse_topic() {
        // An Android-style `//topic` is formatted as `wc://topic@2...` and the
        // slashes must not end up in the parsed topic.
        let topic = Topic::generate();
        let android = format!("//{topic}");
        let parsed: PairingUri = uri_params(&android).to_string().parse().unwrap();
        assert_ne!(parsed.topic.as_str(), android);
        assert_eq!(parsed.topic, topic);
        assert!(!parsed.topic.as_str().starts_with("//"));
    }

    #[test]
    fn should_parse_base64_uri() {
        let encoded = STANDARD.encode(uri_string());
        let plain: PairingUri = uri_string().parse().unwrap();
        let from_b64: PairingUri = encoded.parse().unwrap();
        assert_eq!(plain, from_b64);
    }

    /// misc.spec.ts: `fromBase64` decodes unpadded input (length mod 4 of 2 and
    /// 3), which `toBase64(input, true)` produces, e.g. for Telegram deep links.
    #[test]
    fn should_parse_unpadded_base64_uri() {
        let plain: PairingUri = uri_string().parse().unwrap();
        // Vary the URI length so that every padding length is exercised.
        for extra in ["", "&x=1", "&x=12", "&x=123"] {
            let s = format!("{}{extra}", uri_string());
            let unpadded = STANDARD_NO_PAD.encode(&s);
            assert!(!unpadded.contains('='));
            let parsed: PairingUri = unpadded
                .parse()
                .unwrap_or_else(|e| panic!("{unpadded}: {e}"));
            assert_eq!(parsed, plain, "{s}");
        }
    }
}

// ---------------------------------------------------------------------------
// validators.spec.ts
// ---------------------------------------------------------------------------

mod validators {
    use super::*;

    const ADDRESS: &str = "0x57f48fAFeC1d76B27e3f29b8d277b6218CDE6092";

    fn required(v: Value) -> ProposalNamespaces {
        from_json(v)
    }

    fn approved(v: Value) -> SessionNamespaces {
        from_json(v)
    }

    fn conforming(req: Value, appr: Value) -> Result<(), ErrorObject> {
        ensure_conforming(&required(req), &approved(appr), "validators")
    }

    fn assert_non_conforming(req: Value, appr: Value) {
        let err = conforming(req, appr).unwrap_err();
        assert_eq!(err.code, InternalError::NonConformingNamespaces.code());
    }

    #[test]
    fn should_validate_namespaces_configuration_1() {
        let req = json!({
            "eip155": {"chains": ["eip155:1", "eip155:2", "eip155:3"], "events": [], "methods": ["eth_accounts", "personal_sign"]},
            "eip155:4": {"events": [], "methods": ["eth_accounts"]},
            "solana": {"chains": ["solana:1", "solana:2", "solana:3"], "events": [], "methods": ["eth_accounts", "personal_sign"]},
        });
        let appr = json!({
            "eip155": {
                "accounts": [format!("eip155:1:{ADDRESS}"), format!("eip155:2:{ADDRESS}"), format!("eip155:3:{ADDRESS}")],
                "events": [], "methods": ["eth_accounts", "personal_sign"],
            },
            "eip155:4": {"events": [], "methods": ["eth_accounts"], "accounts": [format!("eip155:4:{ADDRESS}")]},
            "eip155:5": {"events": [], "methods": ["eth_sendTransaction"], "accounts": [format!("eip155:5:{ADDRESS}")]},
            "solana": {
                "accounts": [format!("solana:1:{ADDRESS}"), format!("solana:2:{ADDRESS}"), format!("solana:3:{ADDRESS}")],
                "events": [], "methods": ["eth_accounts", "personal_sign"],
            },
        });
        assert_eq!(conforming(req, appr), Ok(()));
    }

    #[test]
    fn should_validate_namespaces_configuration_2() {
        let req = json!({
            "eip155:1": {"events": [], "methods": ["eth_accounts", "personal_sign"]},
            "eip155:2": {"events": [], "methods": ["eth_accounts"]},
            "solana:1": {"events": [], "methods": ["eth_accounts", "personal_sign"]},
        });
        let appr = json!({
            "eip155": {
                "accounts": [format!("eip155:1:{ADDRESS}"), format!("eip155:2:{ADDRESS}"), format!("eip155:3:{ADDRESS}")],
                "events": [], "methods": ["eth_accounts", "personal_sign"],
            },
            "solana": {"accounts": [format!("solana:1:{ADDRESS}")], "events": [], "methods": ["eth_accounts", "personal_sign"]},
        });
        assert_eq!(conforming(req, appr), Ok(()));
    }

    #[test]
    fn should_validate_namespaces_configuration_3() {
        let req =
            json!({"eip155": {"chains": ["eip155:1"], "events": [], "methods": ["eth_accounts"]}});
        let appr = json!({
            "eip155": {
                "accounts": [format!("eip155:1:{ADDRESS}"), format!("eip155:2:{ADDRESS}")],
                "events": ["chainChanged"], "methods": ["eth_accounts", "personal_sign"],
            },
        });
        assert_eq!(conforming(req, appr), Ok(()));
    }

    #[test]
    fn should_validate_namespaces_configuration_4() {
        let req = json!({"eip155": {"chains": ["eip155:1", "eip155:2"], "events": [], "methods": ["eth_accounts"]}});
        let appr = json!({
            "eip155:1": {"accounts": [format!("eip155:1:{ADDRESS}")], "events": ["chainChanged"], "methods": ["eth_accounts"]},
            "eip155:2": {"accounts": [format!("eip155:2:{ADDRESS}")], "events": ["chainChanged"], "methods": ["eth_accounts"]},
        });
        assert_eq!(conforming(req, appr), Ok(()));
    }

    #[test]
    fn should_throw_on_invalid_accounts() {
        assert_non_conforming(
            json!({"eip155": {"chains": ["eip155:1"], "events": [], "methods": ["eth_accounts"]}}),
            json!({"eip155": {"accounts": [format!("eip155:2:{ADDRESS}")], "events": ["chainChanged"], "methods": ["eth_accounts", "personal_sign"]}}),
        );
    }

    #[test]
    fn should_throw_on_invalid_namespace() {
        assert_non_conforming(
            json!({"eip155": {"chains": ["eip155:1"], "events": [], "methods": ["eth_accounts"]}}),
            json!({"solana": {"accounts": [format!("solana:1:{ADDRESS}")], "events": ["chainChanged"], "methods": ["eth_accounts", "personal_sign"]}}),
        );
    }

    #[test]
    fn should_throw_on_invalid_methods() {
        assert_non_conforming(
            json!({"eip155": {"chains": ["eip155:1"], "events": [], "methods": ["eth_accounts"]}}),
            json!({"eip155": {"accounts": [format!("eip155:1:{ADDRESS}")], "events": ["chainChanged"], "methods": ["personal_sign"]}}),
        );
    }

    #[test]
    fn should_throw_on_caip2_namespace_not_including_that_caip2_in_accounts() {
        assert_non_conforming(
            json!({"eip155": {"chains": ["eip155:1", "eip155:2"], "events": [], "methods": ["eth_accounts"]}}),
            json!({
                "eip155:1": {"accounts": [format!("eip155:1:{ADDRESS}")], "events": ["chainChanged"], "methods": ["eth_accounts"]},
                "eip155:2": {"accounts": [format!("eip155:1:{ADDRESS}")], "events": ["chainChanged"], "methods": ["eth_accounts"]},
            }),
        );
    }
}

// ---------------------------------------------------------------------------
// validators.spec.ts: buildApprovedNamespaces
// ---------------------------------------------------------------------------

mod build_approved_namespaces {
    use super::*;

    const ADDRESS: &str = "0x57f48fAFeC1d76B27e3f29b8d277b6218CDE6092";

    fn accounts(chains: &[&str]) -> Vec<String> {
        chains.iter().map(|c| format!("{c}:{ADDRESS}")).collect()
    }

    fn supported(v: Value) -> BTreeMap<String, SupportedNamespace> {
        from_json(v)
    }

    /// `buildApprovedNamespaces({ proposal: { requiredNamespaces, optionalNamespaces }, supportedNamespaces })`
    fn build(required: Value, optional: Value, supported_: Value) -> Result<Value, ErrorObject> {
        let required: ProposalNamespaces = from_json(required);
        let optional: ProposalNamespaces = from_json(optional);
        build_approved_namespaces(&required, &optional, &supported(supported_))
            .map(|ns| serde_json::to_value(ns).unwrap())
    }

    #[test]
    fn config_1_optional_method() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:3"]);
        let result = build(
            json!({"eip155": {"chains": ["eip155:1"], "events": ["chainChanged"], "methods": ["personal_sign"]}}),
            json!({"eip155": {"chains": ["eip155:1"], "events": [""], "methods": ["eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:3"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": [accts[0]],
            }})
        );
    }

    #[test]
    fn config_2_optional_chain() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:3"]);
        let result = build(
            json!({"eip155": {"chains": ["eip155:1"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {"chains": ["eip155:2"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:3"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": [accts[0], accts[1]],
            }})
        );
    }

    #[test]
    fn config_3_inline_chain() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:3"]);
        let result = build(
            json!({"eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {"chains": ["eip155:2"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:3"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": [accts[0], accts[1]],
            }})
        );
    }

    #[test]
    fn config_4_multiple_inline_chains() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:3"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {"chains": ["eip155:3"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:3"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:3"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }})
        );
    }

    #[test]
    fn config_5_multiple_inline_chains() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:4", "eip155:3"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({
                "eip155": {"chains": ["eip155:3"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:4": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:3", "eip155:4"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:4", "eip155:3"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }})
        );
    }

    #[test]
    fn config_6_unsupported_optional_chains() {
        let accts = accounts(&["eip155:1", "eip155:2"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({
                "eip155": {"chains": ["eip155:3"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:4": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }})
        );
    }

    #[test]
    fn config_7_partially_supported_optional_chains() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:4"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({
                "eip155": {"chains": ["eip155:3"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:4": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:4"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:4"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }})
        );
    }

    #[test]
    fn config_8_partially_supported_optional_methods() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:4"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "events": ["chainChanged"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction", "eth_signTypedData"],
            }}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:4"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": [accts[0], accts[1]],
            }})
        );
    }

    #[test]
    fn config_9_partially_supported_optional_events() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:4"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "events": ["chainChanged", "accountsChanged"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction", "eth_signTypedData"],
            }}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:4"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": [accts[0], accts[1]],
            }})
        );
    }

    #[test]
    fn config_10_extra_supported_chains() {
        let accts = accounts(&["eip155:1", "eip155:2", "eip155:11"]);
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "events": ["chainChanged", "accountsChanged"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction", "eth_signTypedData"],
            }}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2", "eip155:11"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": [accts[0], accts[1]],
            }})
        );
    }

    #[test]
    fn config_11_multiple_namespaces_required() {
        let accts_eip = accounts(&["eip155:1", "eip155:2", "eip155:4"]);
        let accts_cosmos =
            vec!["cosmos:cosmoshub-4:cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02".to_owned()];
        let result = build(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "cosmos": {"chains": ["cosmos:cosmoshub-4"], "events": ["cosmos_event"], "methods": ["cosmos_method"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "events": ["chainChanged", "accountsChanged"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction", "eth_signTypedData"],
            }}),
            json!({
                "eip155": {
                    "chains": ["eip155:1", "eip155:2", "eip155:4"],
                    "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                    "events": ["chainChanged", "accountsChanged"],
                    "accounts": accts_eip,
                },
                "cosmos": {
                    "chains": ["cosmos:cosmoshub-4"],
                    "methods": ["cosmos_method"],
                    "events": ["cosmos_event"],
                    "accounts": accts_cosmos,
                },
            }),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({
                "eip155": {
                    "chains": ["eip155:1", "eip155:2"],
                    "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                    "events": ["chainChanged", "accountsChanged"],
                    "accounts": [accts_eip[0], accts_eip[1]],
                },
                "cosmos": {
                    "chains": ["cosmos:cosmoshub-4"],
                    "methods": ["cosmos_method"],
                    "events": ["cosmos_event"],
                    "accounts": accts_cosmos,
                },
            })
        );
    }

    #[test]
    fn config_12_chains_fuzzing() {
        // eip155:1 must not match the accounts of eip155:11 or eip155:111.
        let accts = accounts(&["eip155:1", "eip155:11", "eip155:111"]);
        let result = build(
            json!({"eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({}),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:11", "eip155:111"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged"],
                "accounts": accts,
            }}),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": [accts[0]],
            }})
        );
    }

    #[test]
    fn config_13_required_and_optional_empty() {
        let supported_ = json!({"eip155": {
            "chains": ["eip155:1", "eip155:2", "eip155:3"],
            "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
            "events": ["chainChanged"],
            "accounts": accounts(&["eip155:1", "eip155:2", "eip155:3"]),
        }});
        let result = build(json!({}), json!({}), supported_.clone()).unwrap();
        assert_eq!(result, supported_);
    }

    fn assert_build_fails(required: Value, supported_: Value) {
        let optional = json!({"eip155": {
            "chains": ["eip155:1", "eip155:2"],
            "events": ["chainChanged", "accountsChanged"],
            "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction", "eth_signTypedData"],
        }});
        let result = build(required, optional, supported_);
        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn should_throw_config_1_no_supported_required_chains() {
        assert_build_fails(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "cosmos": {"chains": ["cosmos:cosmoshub-4"], "events": ["cosmos_event"], "methods": ["cosmos_method"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:5"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": accounts(&["eip155:5"]),
            }}),
        );
    }

    #[test]
    fn should_throw_config_2_partially_supported_required_chains() {
        assert_build_fails(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "cosmos": {"chains": ["cosmos:cosmoshub-4"], "events": ["cosmos_event"], "methods": ["cosmos_method"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:5"],
                "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": accounts(&["eip155:1", "eip155:5"]),
            }}),
        );
    }

    #[test]
    fn should_throw_config_3_no_supported_required_methods() {
        assert_build_fails(
            json!({"eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1"],
                "methods": ["personal_sign"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": accounts(&["eip155:1"]),
            }}),
        );
    }

    #[test]
    fn should_throw_config_4_no_supported_required_events() {
        assert_build_fails(
            json!({"eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": [],
                "accounts": accounts(&["eip155:1"]),
            }}),
        );
    }

    #[test]
    fn should_throw_config_5_no_accounts_for_required_chain() {
        assert_build_fails(
            json!({"eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
            json!({"eip155": {
                "chains": ["eip155:1"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": accounts(&["eip155:2"]),
            }}),
        );
    }

    #[test]
    fn should_throw_config_6_partial_accounts_for_required_chain() {
        assert_build_fails(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": accounts(&["eip155:2"]),
            }}),
        );
    }

    #[test]
    fn should_throw_config_7_misconfigured_supported_accounts_caip10() {
        assert_build_fails(
            json!({
                "eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "eip155:2": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
            }),
            json!({"eip155": {
                "chains": ["eip155:1", "eip155:2"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "events": ["chainChanged"],
                "accounts": [ADDRESS, ADDRESS],
            }}),
        );
    }

    #[test]
    fn matching_namespace_but_no_supported_chains() {
        // bip122 is requested and supported, but on a different chain, so it
        // is left out of the result.
        let result = build(
            json!({}),
            json!({
                "eip155": {
                    "chains": ["eip155:1", "eip155:2"],
                    "events": ["chainChanged", "accountsChanged"],
                    "methods": ["personal_sign", "eth_sendTransaction", "eth_signTransaction", "eth_signTypedData"],
                },
                "bip122": {
                    "chains": ["bip122:000000000019d6689c085ae165831e93"],
                    "events": ["chainChanged"],
                    "methods": ["bip122_signTransaction"],
                },
            }),
            json!({
                "eip155": {
                    "chains": ["eip155:1"],
                    "methods": ["personal_sign", "eth_sendTransaction"],
                    "events": ["chainChanged"],
                    "accounts": accounts(&["eip155:1"]),
                },
                "bip122": {
                    "chains": ["bip122:000000000019d6689c085ae165831e92"],
                    "events": ["chainChanged"],
                    "methods": ["bip122_signTransaction"],
                    "accounts": accounts(&["bip122:000000000019d6689c085ae165831e92"]),
                },
            }),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"eip155": {
                "chains": ["eip155:1"],
                "events": ["chainChanged"],
                "methods": ["personal_sign", "eth_sendTransaction"],
                "accounts": accounts(&["eip155:1"]),
            }})
        );
    }
}

// ---------------------------------------------------------------------------
// validators.spec.ts: merge namespaces
// ---------------------------------------------------------------------------

mod merge_namespaces {
    use super::*;

    fn merge(required: Value, optional: Value) -> Value {
        let required: ProposalNamespaces = from_json(required);
        let optional: ProposalNamespaces = from_json(optional);
        serde_json::to_value(merge_required_and_optional(&required, &optional)).unwrap()
    }

    #[test]
    fn case_1() {
        assert_eq!(
            merge(
                json!({"eip155:1": {"events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
                json!({"eip155:1": {"events": ["accountsChanged"], "methods": ["eth_sendTransaction"]}}),
            ),
            json!({"eip155": {
                "chains": ["eip155:1"],
                "events": ["chainChanged", "accountsChanged"],
                "methods": ["personal_sign", "eth_sendTransaction"],
            }})
        );
    }

    #[test]
    fn case_2() {
        assert_eq!(
            merge(
                json!({"eip155": {"chains": ["eip155:1"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
                json!({"eip155": {"chains": ["eip155:1"], "events": ["accountsChanged"], "methods": ["eth_sendTransaction"]}}),
            ),
            json!({"eip155": {
                "chains": ["eip155:1"],
                "events": ["chainChanged", "accountsChanged"],
                "methods": ["personal_sign", "eth_sendTransaction"],
            }})
        );
    }

    #[test]
    fn case_3() {
        assert_eq!(
            merge(
                json!({"eip155": {"chains": ["eip155:1"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]}}),
                json!({"solana": {"chains": ["solana:1"], "events": ["accountsChanged"], "methods": ["solana_signTransaction"]}}),
            ),
            json!({
                "eip155": {"chains": ["eip155:1"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                "solana": {"chains": ["solana:1"], "events": ["accountsChanged"], "methods": ["solana_signTransaction"]},
            })
        );
    }

    #[test]
    fn case_4() {
        assert_eq!(
            merge(
                json!({
                    "eip155": {"chains": ["eip155:2"], "events": ["chainChanged"], "methods": ["personal_sign", "eth_sendTransaction"]},
                    "solana": {"chains": ["solana:1"], "events": ["accountsChanged"], "methods": ["solana_signTransaction"]},
                }),
                json!({"eip155": {"chains": ["eip155:1"], "events": ["accountsChanged"], "methods": ["eth_signTypedData"]}}),
            ),
            json!({
                "eip155": {
                    "chains": ["eip155:2", "eip155:1"],
                    "events": ["chainChanged", "accountsChanged"],
                    "methods": ["personal_sign", "eth_sendTransaction", "eth_signTypedData"],
                },
                "solana": {"chains": ["solana:1"], "events": ["accountsChanged"], "methods": ["solana_signTransaction"]},
            })
        );
    }
}

// ---------------------------------------------------------------------------
// misc.spec.ts (expiry utils) and errors.ts
// ---------------------------------------------------------------------------

mod misc {
    use super::*;

    /// `formatRelayRpcUrl`: `auth`, `projectId` and `ua` query parameters;
    /// the JWT's audience is the bare relay URL.
    #[cfg(feature = "ws")]
    #[test]
    fn format_relay_rpc_url() {
        use wallet_connect::auth::{IdentityKey, verify_jwt};
        use wallet_connect::relay::WsConnector;

        const RELAY_URL: &str = "wss://relay.walletconnect.org";
        const PROJECT_ID: &str = "27e484dcd9e3efcfd25a83a78777cdf1";
        let identity = IdentityKey::generate();
        let query = |connector: WsConnector| -> BTreeMap<String, String> {
            let url = connector.connection_url().unwrap();
            assert_eq!(url.scheme(), "wss");
            assert_eq!(url.host_str(), Some("relay.walletconnect.org"));
            url.query_pairs().into_owned().collect()
        };

        let params = query(WsConnector::new(RELAY_URL, identity.clone()));
        assert_eq!(params.keys().collect::<Vec<_>>(), ["auth", "ua"]);
        assert!(params["ua"].starts_with("wc-2/rust-"), "{}", params["ua"]);
        let claims = verify_jwt(&params["auth"]).unwrap();
        assert_eq!(claims.aud, RELAY_URL);
        assert_eq!(claims.iss, identity.client_id());

        let params = query(
            WsConnector::new(RELAY_URL, identity)
                .project_id(PROJECT_ID)
                .user_agent("wc-2/js-2.0.0-rc.1/linux/node"),
        );
        assert_eq!(
            params.keys().collect::<Vec<_>>(),
            ["auth", "projectId", "ua"]
        );
        assert_eq!(params["projectId"], PROJECT_ID);
        assert_eq!(params["ua"], "wc-2/js-2.0.0-rc.1/linux/node");
    }

    #[test]
    fn calc_expiry_is_relative_to_now() {
        let before = now_secs();
        let expiry = expiry_in(SEVEN_DAYS);
        let after = now_secs();
        assert_eq!(SEVEN_DAYS, 604_800);
        assert!((before + SEVEN_DAYS..=after + SEVEN_DAYS).contains(&expiry));
    }

    #[test]
    fn is_expired_is_false_before_the_expiry() {
        // Two minutes pre-expiry.
        assert!(!is_expired(now_secs() + 120));
    }

    #[test]
    fn is_expired_is_true_at_and_after_the_expiry() {
        // Exactly at the expiry counts as expired, as in the reference SDK.
        assert!(is_expired(now_secs()));
        assert!(is_expired(1_675_702_595));
    }

    /// `SDK_ERRORS` and `INTERNAL_ERRORS` of `packages/utils/src/errors.ts`.
    #[test]
    fn error_codes_and_messages_match_the_reference() {
        let sdk = [
            (SdkError::InvalidMethod, 1001, "Invalid method."),
            (SdkError::InvalidEvent, 1002, "Invalid event."),
            (
                SdkError::InvalidUpdateRequest,
                1003,
                "Invalid update request.",
            ),
            (
                SdkError::InvalidExtendRequest,
                1004,
                "Invalid extend request.",
            ),
            (
                SdkError::InvalidSessionSettleRequest,
                1005,
                "Invalid session settle request.",
            ),
            (SdkError::UnauthorizedMethod, 3001, "Unauthorized method."),
            (SdkError::UnauthorizedEvent, 3002, "Unauthorized event."),
            (
                SdkError::UnauthorizedUpdateRequest,
                3003,
                "Unauthorized update request.",
            ),
            (
                SdkError::UnauthorizedExtendRequest,
                3004,
                "Unauthorized extend request.",
            ),
            (SdkError::UserRejected, 5000, "User rejected."),
            (SdkError::UserRejectedChains, 5001, "User rejected chains."),
            (
                SdkError::UserRejectedMethods,
                5002,
                "User rejected methods.",
            ),
            (SdkError::UserRejectedEvents, 5003, "User rejected events."),
            (SdkError::UnsupportedChains, 5100, "Unsupported chains."),
            (SdkError::UnsupportedMethods, 5101, "Unsupported methods."),
            (SdkError::UnsupportedEvents, 5102, "Unsupported events."),
            (SdkError::UnsupportedAccounts, 5103, "Unsupported accounts."),
            (
                SdkError::UnsupportedNamespaceKey,
                5104,
                "Unsupported namespace key.",
            ),
            (SdkError::UserDisconnected, 6000, "User disconnected."),
            (
                SdkError::SessionSettlementFailed,
                7000,
                "Session settlement failed.",
            ),
            (
                SdkError::WcMethodUnsupported,
                10001,
                "Unsupported wc_ method.",
            ),
        ];
        assert_eq!(sdk.len(), SdkError::ALL.len());
        for (error, code, message) in sdk {
            assert_eq!(error.error(), ErrorObject::new(code, message), "{error:?}");
        }

        let internal = [
            (InternalError::NoMatchingKey, 2, "No matching key."),
            (InternalError::MissingOrInvalid, 5, "Missing or invalid."),
            (InternalError::Expired, 6, "Expired."),
            (InternalError::MismatchedTopic, 8, "Mismatched topic."),
            (
                InternalError::NonConformingNamespaces,
                9,
                "Non conforming namespaces.",
            ),
        ];
        for (error, code, message) in internal {
            assert_eq!((error.code(), error.message()), (code, message));
            // `getInternalError(key, context)` appends the context after a space.
            assert_eq!(
                error.with_context("ctx"),
                ErrorObject::new(code, format!("{message} ctx"))
            );
        }
    }
}
