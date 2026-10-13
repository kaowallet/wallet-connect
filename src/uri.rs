//! Pairing URIs.
//!
//! ```text
//! wc:{topic}@2?expiryTimestamp={secs}&relay-protocol=irn&symKey={hex}
//! ```
//!
//! The dapp shows this URI (usually as a QR code), the wallet scans it and
//! from then on both can talk on `topic` using `symKey`.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use url::form_urlencoded;

use crate::crypto::{SymKey, Topic};
use crate::error::{Error, Result};

pub const PROTOCOL: &str = "wc";
pub const VERSION: u32 = 2;
pub const DEFAULT_RELAY_PROTOCOL: &str = "irn";

/// A parsed `wc:` pairing URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingUri {
    pub topic: Topic,
    pub version: u32,
    pub sym_key: SymKey,
    pub relay_protocol: String,
    pub relay_data: Option<String>,
    /// Unix seconds after which the pairing is no longer valid.
    pub expiry_timestamp: Option<u64>,
    /// Methods the pairing is meant for (old SDKs only; omitted nowadays).
    pub methods: Option<Vec<String>>,
}

impl PairingUri {
    /// A URI for a fresh pairing whose topic is derived from `sym_key`.
    pub fn new(sym_key: SymKey, expiry_timestamp: u64) -> Self {
        Self {
            topic: sym_key.topic(),
            version: VERSION,
            sym_key,
            relay_protocol: DEFAULT_RELAY_PROTOCOL.into(),
            relay_data: None,
            expiry_timestamp: Some(expiry_timestamp),
            methods: None,
        }
    }
}

impl FromStr for PairingUri {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let invalid = |m: String| Error::InvalidUri(m);
        let mut s = input.trim().to_owned();

        // The reference SDK also accepts a base64-encoded URI.
        if !s.contains("wc:")
            && let Ok(decoded) = STANDARD.decode(&s)
            && let Ok(decoded) = String::from_utf8(decoded)
            && decoded.contains("wc:")
        {
            s = decoded;
        }

        let rest = s
            .strip_prefix("wc:")
            .ok_or_else(|| invalid(format!("missing `wc:` scheme in `{input}`")))?;
        // `wc://topic@2?...` is used by some Android deep links.
        let rest = rest.strip_prefix("//").unwrap_or(rest);
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (topic, version) = path
            .split_once('@')
            .ok_or_else(|| invalid("missing `@version`".into()))?;
        if topic.is_empty() {
            return Err(invalid("empty topic".into()));
        }
        let version: u32 = version
            .parse()
            .map_err(|_| invalid(format!("bad version `{version}`")))?;
        if version != VERSION {
            return Err(invalid(format!("unsupported version {version}")));
        }

        let mut sym_key = None;
        let mut relay_protocol = None;
        let mut relay_data = None;
        let mut expiry_timestamp = None;
        let mut methods = None;
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "symKey" => sym_key = Some(SymKey::from_hex(&value)?),
                "relay-protocol" => relay_protocol = Some(value.into_owned()),
                "relay-data" => relay_data = Some(value.into_owned()),
                "expiryTimestamp" => {
                    expiry_timestamp = Some(
                        value
                            .parse()
                            .map_err(|_| invalid(format!("bad expiryTimestamp `{value}`")))?,
                    )
                }
                "methods" => {
                    methods = Some(
                        value
                            .split(',')
                            .filter(|m| !m.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    )
                }
                _ => {}
            }
        }

        Ok(PairingUri {
            topic: Topic::new(topic),
            version,
            sym_key: sym_key.ok_or_else(|| invalid("missing symKey".into()))?,
            relay_protocol: relay_protocol
                .ok_or_else(|| invalid("missing relay-protocol".into()))?,
            relay_data,
            expiry_timestamp,
            methods,
        })
    }
}

impl fmt::Display for PairingUri {
    /// Parameters are emitted in the same (sorted) order as the reference
    /// SDK, so URIs are byte-for-byte identical.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut q = form_urlencoded::Serializer::new(String::new());
        if let Some(exp) = self.expiry_timestamp {
            q.append_pair("expiryTimestamp", &exp.to_string());
        }
        if let Some(methods) = &self.methods {
            q.append_pair("methods", &methods.join(","));
        }
        if let Some(data) = &self.relay_data {
            q.append_pair("relay-data", data);
        }
        q.append_pair("relay-protocol", &self.relay_protocol);
        q.append_pair("symKey", &self.sym_key.to_hex());
        write!(
            f,
            "{PROTOCOL}:{}@{}?{}",
            self.topic,
            self.version,
            q.finish()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303";
    const TOPIC: &str = "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9";

    #[test]
    fn parse_reference_uri() {
        let uri: PairingUri =
            format!("wc:{TOPIC}@2?expiryTimestamp=1705312345&relay-protocol=irn&symKey={KEY}")
                .parse()
                .unwrap();
        assert_eq!(uri.topic.as_str(), TOPIC);
        assert_eq!(uri.sym_key.to_hex(), KEY);
        assert_eq!(uri.relay_protocol, "irn");
        assert_eq!(uri.expiry_timestamp, Some(1705312345));
        assert_eq!(uri.methods, None);
    }

    #[test]
    fn roundtrip_matches_reference_formatting() {
        let s = format!(
            "wc:{TOPIC}@2?expiryTimestamp=1705312345&methods=wc_sessionPropose%2Cwc_authRequest&relay-protocol=irn&symKey={KEY}"
        );
        let uri: PairingUri = s.parse().unwrap();
        assert_eq!(
            uri.methods.as_deref(),
            Some(&["wc_sessionPropose".to_owned(), "wc_authRequest".to_owned()][..])
        );
        assert_eq!(uri.to_string(), s);
    }

    #[test]
    fn accepts_deep_link_and_base64_forms() {
        let plain = format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={KEY}");
        let deep = format!("wc://{TOPIC}@2?relay-protocol=irn&symKey={KEY}");
        let b64 = STANDARD.encode(&plain);
        for s in [&plain, &deep, &b64] {
            let uri: PairingUri = s.parse().unwrap();
            assert_eq!(uri.topic.as_str(), TOPIC);
        }
    }

    #[test]
    fn rejects_bad_uris() {
        for s in [
            "http://example.com".to_owned(),
            format!("wc:{TOPIC}@1?relay-protocol=irn&symKey={KEY}"),
            format!("wc:{TOPIC}@2?relay-protocol=irn"),
            format!("wc:{TOPIC}@2?symKey={KEY}"),
            format!("wc:{TOPIC}@2?relay-protocol=irn&symKey=abcd"),
            format!("wc:@2?relay-protocol=irn&symKey={KEY}"),
        ] {
            assert!(s.parse::<PairingUri>().is_err(), "{s}");
        }
    }

    #[test]
    fn new_derives_topic_from_key() {
        let key = SymKey::generate();
        let uri = PairingUri::new(key.clone(), 42);
        assert_eq!(uri.topic, key.topic());
        let back: PairingUri = uri.to_string().parse().unwrap();
        assert_eq!(back, uri);
    }
}
