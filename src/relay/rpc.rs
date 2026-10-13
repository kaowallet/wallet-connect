//! Wire types of the relay ("irn") JSON-RPC API.

use serde::{Deserialize, Serialize};

use crate::crypto::Topic;

/// Method names.
pub mod methods {
    pub const PUBLISH: &str = "irn_publish";
    pub const BATCH_PUBLISH: &str = "irn_batchPublish";
    pub const SUBSCRIBE: &str = "irn_subscribe";
    pub const BATCH_SUBSCRIBE: &str = "irn_batchSubscribe";
    pub const UNSUBSCRIBE: &str = "irn_unsubscribe";
    pub const BATCH_UNSUBSCRIBE: &str = "irn_batchUnsubscribe";
    pub const FETCH_MESSAGES: &str = "irn_fetchMessages";
    pub const BATCH_FETCH_MESSAGES: &str = "irn_batchFetchMessages";
    /// Server → client push of a message on a subscribed topic.
    pub const SUBSCRIPTION: &str = "irn_subscription";
    /// Publish a session proposal and subscribe the proposer to the pairing
    /// topic in one round trip (used by recent JS SDKs).
    pub const PROPOSE_SESSION: &str = "wc_proposeSession";
    /// Publish the proposal response and the settle request and subscribe
    /// the wallet to the session topic in one round trip.
    pub const APPROVE_SESSION: &str = "wc_approveSession";
}

/// The relay protocol name used in URIs and `relay` objects.
pub const RELAY_PROTOCOL: &str = "irn";

/// Default relay endpoint.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.org";

/// Shortest and longest message lifetimes the relay accepts, in seconds.
pub const MIN_TTL: u64 = 10;
pub const MAX_TTL: u64 = crate::time::THIRTY_DAYS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishParams {
    pub topic: Topic,
    pub message: String,
    pub ttl: u64,
    #[serde(default)]
    pub tag: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPublishParams {
    pub messages: Vec<PublishParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeParams {
    pub topic: Topic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSubscribeParams {
    pub topics: Vec<Topic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeParams {
    pub topic: Topic,
    /// Subscription id returned by `irn_subscribe`.
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchUnsubscribeParams {
    pub subscriptions: Vec<UnsubscribeParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessagesParams {
    pub topic: Topic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFetchMessagesParams {
    pub topics: Vec<Topic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchMessagesResult {
    pub messages: Vec<SubscriptionData>,
    #[serde(default)]
    pub has_more: bool,
}

/// Params of an `irn_subscription` push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionParams {
    /// Subscription id.
    pub id: String,
    pub data: SubscriptionData,
}

/// A message delivered on a subscribed topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionData {
    pub topic: Topic,
    /// The (encrypted, base64) envelope.
    pub message: String,
    /// Unix milliseconds.
    #[serde(default)]
    pub published_at: u64,
    #[serde(default)]
    pub tag: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposeSessionParams {
    pub pairing_topic: Topic,
    /// Encrypted `wc_sessionPropose` request.
    pub session_proposal: String,
    #[serde(default = "default_ttl")]
    pub ttl: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveSessionParams {
    pub session_topic: Topic,
    pub pairing_topic: Topic,
    /// Encrypted response to `wc_sessionPropose` (pairing topic).
    pub session_proposal_response: String,
    /// Encrypted `wc_sessionSettle` request (session topic).
    pub session_settlement_request: String,
    #[serde(default = "default_ttl")]
    pub ttl: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<bool>,
}

fn default_ttl() -> u64 {
    crate::time::FIVE_MINUTES
}
