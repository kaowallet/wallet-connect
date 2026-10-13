//! Sign API data model: metadata, namespaces, wire params and the records a
//! client keeps (pairings, proposals, sessions, pending requests).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{PublicKey, Topic};
use crate::relay::rpc::RELAY_PROTOCOL;

/// Free-form key/value properties attached to proposals and sessions.
pub type Properties = serde_json::Map<String, Value>;

/// Describes a dapp or wallet to its peer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub icons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirect>,
}

impl Metadata {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            url: url.into(),
            ..Self::default()
        }
    }

    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icons.push(icon.into());
        self
    }
}

/// Deep links back to the app.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Redirect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_mode: Option<bool>,
}

/// Relay protocol options (`{"protocol": "irn"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            protocol: RELAY_PROTOCOL.into(),
            data: None,
        }
    }
}

/// One side of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    pub public_key: PublicKey,
    pub metadata: Metadata,
}

/// What a dapp asks for in one namespace (`eip155`) or one chain
/// (`eip155:1`, in which case `chains` is omitted).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProposalNamespace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
}

impl ProposalNamespace {
    pub fn new<S: Into<String>>(
        chains: impl IntoIterator<Item = S>,
        methods: impl IntoIterator<Item = S>,
        events: impl IntoIterator<Item = S>,
    ) -> Self {
        Self {
            chains: Some(chains.into_iter().map(Into::into).collect()),
            methods: methods.into_iter().map(Into::into).collect(),
            events: events.into_iter().map(Into::into).collect(),
        }
    }
}

pub type ProposalNamespaces = BTreeMap<String, ProposalNamespace>;

/// What a wallet grants in one namespace.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionNamespace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
}

pub type SessionNamespaces = BTreeMap<String, SessionNamespace>;

// ---------------------------------------------------------------------------
// Wire params
// ---------------------------------------------------------------------------

/// `wc_sessionPropose` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProposeParams {
    pub relays: Vec<Relay>,
    pub proposer: Participant,
    #[serde(default)]
    pub required_namespaces: ProposalNamespaces,
    #[serde(default)]
    pub optional_namespaces: ProposalNamespaces,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_properties: Option<Properties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped_properties: Option<Properties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_timestamp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_topic: Option<Topic>,
}

/// Result of `wc_sessionPropose`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProposeResponse {
    pub relay: Relay,
    pub responder_public_key: PublicKey,
}

/// `wc_sessionSettle` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettleParams {
    pub relay: Relay,
    pub namespaces: SessionNamespaces,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_properties: Option<Properties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped_properties: Option<Properties>,
    pub expiry: u64,
    pub controller: Participant,
}

/// `wc_sessionUpdate` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionUpdateParams {
    pub namespaces: SessionNamespaces,
}

/// `wc_sessionExtend` params. Older peers send the new expiry; newer ones
/// send nothing and both sides extend to seven days from now.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionExtendParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

/// A JSON-RPC call a dapp asks the wallet to perform, e.g.
/// `personal_sign`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    /// Unix seconds after which the dapp no longer waits for an answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_timestamp: Option<u64>,
}

impl SessionRequest {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            method: method.into(),
            params,
            expiry_timestamp: None,
        }
    }
}

/// `wc_sessionRequest` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequestParams {
    pub request: SessionRequest,
    pub chain_id: String,
}

/// An event a wallet emits to the dapp, e.g. `accountsChanged`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionEvent {
    pub name: String,
    #[serde(default)]
    pub data: Value,
}

impl SessionEvent {
    pub fn new(name: impl Into<String>, data: Value) -> Self {
        Self {
            name: name.into(),
            data,
        }
    }
}

/// `wc_sessionEvent` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEventParams {
    pub event: SessionEvent,
    pub chain_id: String,
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// A pairing: the channel a dapp and a wallet use to negotiate sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    pub topic: Topic,
    /// Unix seconds.
    pub expiry: u64,
    pub relay: Relay,
    /// Becomes true once a session was negotiated over this pairing.
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_metadata: Option<Metadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
}

/// A session proposal, as received by a wallet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proposal {
    /// JSON-RPC id of the `wc_sessionPropose` request; pass it to
    /// `approve`/`reject`.
    pub id: u64,
    pub pairing_topic: Topic,
    /// Unix seconds.
    pub expiry_timestamp: u64,
    pub relays: Vec<Relay>,
    pub proposer: Participant,
    pub required_namespaces: ProposalNamespaces,
    pub optional_namespaces: ProposalNamespaces,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_properties: Option<Properties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped_properties: Option<Properties>,
}

/// An established session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub topic: Topic,
    pub pairing_topic: Topic,
    pub relay: Relay,
    /// Unix seconds.
    pub expiry: u64,
    /// For the wallet: whether the dapp confirmed the settlement.
    pub acknowledged: bool,
    /// Public key of the controller (always the wallet).
    pub controller: PublicKey,
    pub namespaces: SessionNamespaces,
    pub required_namespaces: ProposalNamespaces,
    pub optional_namespaces: ProposalNamespaces,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_properties: Option<Properties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped_properties: Option<Properties>,
    /// This client.
    #[serde(rename = "self")]
    pub local: Participant,
    pub peer: Participant,
}

impl Session {
    /// Whether this client controls the session (i.e. is the wallet).
    pub fn is_controller(&self) -> bool {
        self.local.public_key == self.controller
    }

    /// All CAIP-10 accounts granted in the session.
    pub fn accounts(&self) -> Vec<String> {
        let mut accounts: Vec<String> = Vec::new();
        for ns in self.namespaces.values() {
            for a in &ns.accounts {
                if !accounts.contains(a) {
                    accounts.push(a.clone());
                }
            }
        }
        accounts
    }

    /// All CAIP-2 chains granted in the session.
    pub fn chains(&self) -> Vec<String> {
        super::namespaces::session_chains(&self.namespaces)
    }
}

/// A `wc_sessionRequest` waiting for the wallet's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingRequest {
    /// JSON-RPC id to answer with `respond`.
    pub id: u64,
    pub topic: Topic,
    pub chain_id: String,
    pub request: SessionRequest,
}
