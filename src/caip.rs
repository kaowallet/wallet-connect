//! CAIP-2 chain ids (`eip155:1`) and CAIP-10 account ids
//! (`eip155:1:0xab…`).
//!
//! Parsing is deliberately as lenient as the reference SDK: a chain id is two
//! non-empty `:`-separated parts, an account id three.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::error::{Error, Result};

/// A CAIP-2 chain id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId {
    pub namespace: String,
    pub reference: String,
}

impl ChainId {
    pub fn new(namespace: impl Into<String>, reference: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            reference: reference.into(),
        }
    }
}

impl FromStr for ChainId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split(':');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(ns), Some(reference), None) if !ns.is_empty() && !reference.is_empty() => {
                Ok(ChainId::new(ns, reference))
            }
            _ => Err(Error::InvalidCaip(format!(
                "chain id `{s}` is not of the form namespace:reference"
            ))),
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

/// A CAIP-10 account id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId {
    pub chain_id: ChainId,
    pub address: String,
}

impl AccountId {
    pub fn new(chain_id: ChainId, address: impl Into<String>) -> Self {
        Self {
            chain_id,
            address: address.into(),
        }
    }
}

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split(':');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(ns), Some(reference), Some(address), None)
                if !ns.is_empty() && !reference.is_empty() && !address.is_empty() =>
            {
                Ok(AccountId::new(ChainId::new(ns, reference), address))
            }
            _ => Err(Error::InvalidCaip(format!(
                "account id `{s}` is not of the form namespace:reference:address"
            ))),
        }
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.chain_id, self.address)
    }
}

macro_rules! string_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                String::deserialize(d)?.parse().map_err(D::Error::custom)
            }
        }
    };
}

string_serde!(ChainId);
string_serde!(AccountId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        let c: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(c, ChainId::new("eip155", "1"));
        assert_eq!(c.to_string(), "eip155:1");

        let a: AccountId = "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
            .parse()
            .unwrap();
        assert_eq!(a.chain_id, c);
        assert_eq!(a.address, "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");

        let sol: AccountId =
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyRWXArAaKv"
                .parse()
                .unwrap();
        assert_eq!(sol.chain_id.namespace, "solana");

        for bad in ["", "eip155", "eip155:", ":1", "a:b:c"] {
            assert!(bad.parse::<ChainId>().is_err(), "{bad}");
        }
        for bad in ["eip155:1", "eip155:1:", "a:b:c:d"] {
            assert!(bad.parse::<AccountId>().is_err(), "{bad}");
        }
    }
}
