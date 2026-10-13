//! The Sign API client: one type for both roles.
//!
//! * A **dapp** calls [`SignClient::connect`], shows the returned URI, awaits
//!   the approval and then sends [`SignClient::request`]s.
//! * A **wallet** calls [`SignClient::pair`] with that URI, receives a
//!   [`SignEvent::SessionProposal`], answers it with
//!   [`SignClient::approve`]/[`SignClient::reject`] and then answers
//!   [`SignEvent::SessionRequest`]s with [`SignClient::respond`].
//!
//! Incoming messages are processed one at a time, in order, by a background
//! task; everything the peer does surfaces as a [`SignEvent`].

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot, watch};

use super::errors::{InternalError, SdkError};
use super::namespaces::{
    ensure_conforming, namespace_key, session_events_for_chain, session_has_chain,
    session_methods_for_chain, validate_proposal_namespaces, validate_session_namespaces,
};
use super::rpc::{self, methods};
use super::types::*;
use crate::crypto::{Envelope, KeyPair, PublicKey, SymKey, TYPE_0, Topic, sha256_hex};
use crate::error::{Error, Result};
use crate::relay::rpc::SubscriptionData;
use crate::relay::{Connector, PublishOptions, RelayClient, RelayClientOptions, RelayEvent};
use crate::rpc::{ErrorObject, Payload, Request, Response, payload_id};
use crate::time::{
    FIFTEEN_MINUTES, FIVE_MINUTES, SEVEN_DAYS, THIRTY_DAYS, expiry_in, is_expired, now_secs,
};
use crate::uri::PairingUri;

/// How many message hashes are remembered to drop duplicates and echoes.
const SEEN_CAPACITY: usize = 2048;

/// Everything the peer (or time) does to this client.
// Events are rare; boxing the large variants would only make matching on
// them clumsier.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SignEvent {
    /// Wallet: a dapp proposes a session. Answer with `approve`/`reject`.
    SessionProposal(Proposal),
    /// Dapp: the wallet settled a session (also resolves `connect`'s
    /// approval).
    SessionConnect(Session),
    /// Wallet: the dapp asks for something. Answer with `respond`.
    SessionRequest(PendingRequest),
    /// Dapp: the wallet emitted an event such as `accountsChanged`.
    SessionEvent {
        id: u64,
        topic: Topic,
        chain_id: String,
        event: SessionEvent,
    },
    /// Dapp: the wallet changed the session namespaces.
    SessionUpdate {
        id: u64,
        topic: Topic,
        namespaces: SessionNamespaces,
    },
    /// The peer extended the session.
    SessionExtend {
        id: u64,
        topic: Topic,
        expiry: u64,
    },
    SessionPing {
        id: u64,
        topic: Topic,
    },
    /// The peer ended the session.
    SessionDelete {
        id: u64,
        topic: Topic,
        reason: ErrorObject,
    },
    SessionExpire {
        topic: Topic,
    },
    /// Wallet: a pending request expired before it was answered.
    SessionRequestExpire {
        id: u64,
        topic: Topic,
    },
    ProposalExpire {
        id: u64,
    },
    PairingPing {
        id: u64,
        topic: Topic,
    },
    PairingDelete {
        id: u64,
        topic: Topic,
    },
    PairingExpire {
        topic: Topic,
    },
    RelayConnected,
    RelayDisconnected,
}

/// Receiver of [`SignEvent`]s.
pub type SignEvents = mpsc::UnboundedReceiver<SignEvent>;

/// A result that arrives later; `.await` it.
#[must_use = "await it to learn the outcome"]
pub struct Pending<T> {
    future: Pin<Box<dyn Future<Output = Result<T>> + Send>>,
}

impl<T: Send + 'static> Pending<T> {
    fn new<U: Send + 'static>(
        rx: oneshot::Receiver<Result<U>>,
        timeout: Duration,
        map: impl FnOnce(U) -> Result<T> + Send + 'static,
    ) -> Self {
        Pending {
            future: Box::pin(async move {
                match tokio::time::timeout(timeout, rx).await {
                    Ok(Ok(result)) => result.and_then(map),
                    Ok(Err(_)) => Err(Error::Closed),
                    Err(_) => Err(Error::Timeout),
                }
            }),
        }
    }
}

impl<T> IntoFuture for Pending<T> {
    type Output = Result<T>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<T>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        self.future
    }
}

impl<T> fmt::Debug for Pending<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pending")
    }
}

/// Returned by [`SignClient::connect`].
#[derive(Debug)]
pub struct ConnectResponse {
    /// The URI to show the wallet; `None` when an existing pairing was reused.
    pub uri: Option<PairingUri>,
    pub pairing_topic: Topic,
    /// Resolves with the session once the wallet approved and settled it, or
    /// with [`Error::Peer`] when it rejected the proposal.
    pub approval: Pending<Session>,
}

/// Returned by [`SignClient::approve`].
#[derive(Debug)]
pub struct Approved {
    pub session: Session,
    /// Resolves once the dapp acknowledged the settlement.
    pub acknowledged: Pending<()>,
}

/// What a dapp asks for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectParams {
    pub required_namespaces: ProposalNamespaces,
    pub optional_namespaces: ProposalNamespaces,
    pub session_properties: Option<Properties>,
    pub scoped_properties: Option<Properties>,
    /// Propose over an existing pairing instead of creating a new one.
    pub pairing_topic: Option<Topic>,
}

/// What a wallet grants.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApproveParams {
    pub id: u64,
    pub namespaces: SessionNamespaces,
    pub session_properties: Option<Properties>,
    pub scoped_properties: Option<Properties>,
}

/// Tunables for [`SignClient`].
#[derive(Debug, Clone)]
pub struct SignClientOptions {
    /// How often expired pairings, proposals, sessions and requests are
    /// cleaned up.
    pub expiry_check_interval: Duration,
    /// How long `ping` waits for the peer.
    pub ping_timeout: Duration,
    /// How long `update`/`extend` acknowledgements are awaited.
    pub ack_timeout: Duration,
}

impl Default for SignClientOptions {
    fn default() -> Self {
        Self {
            expiry_check_interval: Duration::from_secs(5),
            ping_timeout: Duration::from_secs(FIVE_MINUTES),
            ack_timeout: Duration::from_secs(FIVE_MINUTES),
        }
    }
}

// ---------------------------------------------------------------------------
// Persistent state
// ---------------------------------------------------------------------------

/// An X25519 secret, hex encoded when persisted.
#[derive(Clone)]
struct Secret([u8; 32]);

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let bytes = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        Ok(Secret(bytes.try_into().map_err(|_| {
            serde::de::Error::custom("expected 32 bytes")
        })?))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingSession {
    session_topic: Topic,
    pairing_topic: Topic,
    public_key: PublicKey,
}

/// An outgoing request awaiting its response.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    topic: Topic,
    method: String,
    expiry: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct State {
    sym_keys: BTreeMap<Topic, SymKey>,
    /// Dapp: X25519 secrets of proposals awaiting a response.
    key_pairs: BTreeMap<PublicKey, Secret>,
    pairings: BTreeMap<Topic, Pairing>,
    /// Wallet: proposals received.
    proposals: BTreeMap<u64, Proposal>,
    /// Dapp: proposals sent.
    sent_proposals: BTreeMap<u64, Proposal>,
    /// Dapp: proposal id → session awaiting `wc_sessionSettle`.
    pending_sessions: BTreeMap<u64, PendingSession>,
    sessions: BTreeMap<Topic, Session>,
    /// Wallet: session requests awaiting `respond`.
    pending_requests: BTreeMap<u64, PendingRequest>,
    history: BTreeMap<u64, Record>,
    /// Ids of the latest update/event per topic, to drop stale ones.
    last_ids: BTreeMap<String, u64>,
    seen: VecDeque<String>,
}

impl State {
    fn remember(&mut self, hash: String) -> bool {
        if self.seen.contains(&hash) {
            return false;
        }
        self.seen.push_back(hash);
        while self.seen.len() > SEEN_CAPACITY {
            self.seen.pop_front();
        }
        true
    }

    fn session(&self, topic: &Topic) -> Result<&Session> {
        self.sessions
            .get(topic)
            .ok_or_else(|| Error::NoSession(topic.to_string()))
    }
}

/// Serializable client state (keys, pairings, sessions, pending work).
///
/// Restore it with [`SignClientBuilder::snapshot`]. It contains private key
/// material: store it encrypted.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Snapshot(State);

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("pairings", &self.0.pairings.len())
            .field("sessions", &self.0.sessions.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Configures and connects a [`SignClient`].
pub struct SignClientBuilder {
    metadata: Metadata,
    connector: Option<Arc<dyn Connector>>,
    relay_url: String,
    project_id: Option<String>,
    identity: Option<crate::auth::IdentityKey>,
    snapshot: Option<Snapshot>,
    options: SignClientOptions,
    relay_options: RelayClientOptions,
}

impl SignClientBuilder {
    /// Relay to connect to (default `wss://relay.walletconnect.org`).
    pub fn relay_url(mut self, url: impl Into<String>) -> Self {
        self.relay_url = url.into();
        self
    }

    /// WalletConnect Cloud project id (required by the public relay).
    pub fn project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    /// Relay identity; generated when not set. Persist its seed to keep the
    /// same client id across restarts.
    pub fn identity(mut self, identity: crate::auth::IdentityKey) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Use a custom transport instead of WebSocket (`relay_url`,
    /// `project_id` and `identity` are then ignored).
    pub fn connector(mut self, connector: impl Connector) -> Self {
        self.connector = Some(Arc::new(connector));
        self
    }

    /// Restore state saved with [`SignClient::snapshot`].
    pub fn snapshot(mut self, snapshot: Snapshot) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    pub fn options(mut self, options: SignClientOptions) -> Self {
        self.options = options;
        self
    }

    pub fn relay_options(mut self, options: RelayClientOptions) -> Self {
        self.relay_options = options;
        self
    }

    /// Connect to the relay and start the client.
    pub async fn build(self) -> Result<(SignClient, SignEvents)> {
        let connector = match self.connector {
            Some(connector) => connector,
            None => default_connector(self.relay_url, self.project_id, self.identity)?,
        };
        let (relay, relay_events) =
            RelayClient::connect_shared(connector, self.relay_options).await?;
        SignClient::with_relay(
            relay,
            relay_events,
            self.metadata,
            self.options,
            self.snapshot,
        )
        .await
    }
}

#[cfg(feature = "ws")]
fn default_connector(
    relay_url: String,
    project_id: Option<String>,
    identity: Option<crate::auth::IdentityKey>,
) -> Result<Arc<dyn Connector>> {
    let identity = identity.unwrap_or_else(crate::auth::IdentityKey::generate);
    let mut connector = crate::relay::WsConnector::new(relay_url, identity);
    if let Some(project_id) = project_id {
        connector = connector.project_id(project_id);
    }
    Ok(Arc::new(connector))
}

#[cfg(not(feature = "ws"))]
fn default_connector(
    _relay_url: String,
    _project_id: Option<String>,
    _identity: Option<crate::auth::IdentityKey>,
) -> Result<Arc<dyn Connector>> {
    Err(Error::Transport(
        "no connector configured and the `ws` feature is disabled".into(),
    ))
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Inner {
    relay: RelayClient,
    metadata: Metadata,
    options: SignClientOptions,
    state: Mutex<State>,
    /// Outgoing request id → whoever awaits the response.
    waiters: Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    /// Proposal id → `connect`'s approval.
    approvals: Mutex<HashMap<u64, oneshot::Sender<Result<Session>>>>,
    events: mpsc::UnboundedSender<SignEvent>,
    shutdown: watch::Sender<bool>,
}

/// A WalletConnect Sign API client. Cheap to clone.
#[derive(Clone)]
pub struct SignClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for SignClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignClient")
            .field("metadata", &self.inner.metadata.name)
            .finish_non_exhaustive()
    }
}

fn protocol(kind: InternalError, context: impl fmt::Display) -> Error {
    Error::Protocol(kind.with_context(context))
}

fn parse_params<T: DeserializeOwned>(req: &Request) -> Result<T> {
    serde_json::from_value(req.params.clone()).map_err(|e| {
        protocol(
            InternalError::MissingOrInvalid,
            format!("{} params: {e}", req.method),
        )
    })
}

/// Client ids are `unix_ms * 1000 + random`; compare their timestamps.
fn is_out_of_sync(last: Option<u64>, id: u64) -> bool {
    last.is_some_and(|last| id / 1000 < last / 1000)
}

/// Every property needs a value, as in the reference SDK.
fn validate_properties(properties: Option<&Properties>, what: &str) -> Result<()> {
    match properties.into_iter().flatten().find(|(_, v)| v.is_null()) {
        Some((key, _)) => Err(protocol(
            InternalError::MissingOrInvalid,
            format!(
                "{what} must contain an existing value for each key. Received: null for key {key}"
            ),
        )),
        None => Ok(()),
    }
}

/// Scoped properties may only be keyed by namespaces (or chains of
/// namespaces) among `namespaces`.
fn validate_scoped_properties<'a>(
    scoped: Option<&Properties>,
    namespaces: impl IntoIterator<Item = &'a String>,
    what: &str,
) -> Result<()> {
    let Some(scoped) = scoped else {
        return Ok(());
    };
    validate_properties(Some(scoped), "scopedProperties")?;
    let mut allowed: Vec<&str> = namespaces.into_iter().map(|k| namespace_key(k)).collect();
    allowed.sort_unstable();
    allowed.dedup();
    if scoped.keys().all(|k| allowed.contains(&namespace_key(k))) {
        return Ok(());
    }
    Err(protocol(
        InternalError::MissingOrInvalid,
        format!(
            "Scoped properties must be a subset of {what}, received: {}, {what}: {}",
            Value::Object(scoped.clone()),
            allowed.join(", ")
        ),
    ))
}

impl SignClient {
    /// Start configuring a client that presents itself with `metadata`.
    pub fn builder(metadata: Metadata) -> SignClientBuilder {
        SignClientBuilder {
            metadata,
            connector: None,
            relay_url: crate::relay::rpc::DEFAULT_RELAY_URL.into(),
            project_id: None,
            identity: None,
            snapshot: None,
            options: SignClientOptions::default(),
            relay_options: RelayClientOptions::default(),
        }
    }

    /// Build a client on top of an existing relay connection.
    pub async fn with_relay(
        relay: RelayClient,
        relay_events: mpsc::UnboundedReceiver<RelayEvent>,
        metadata: Metadata,
        options: SignClientOptions,
        snapshot: Option<Snapshot>,
    ) -> Result<(Self, SignEvents)> {
        let state = snapshot.map(|s| s.0).unwrap_or_default();
        let topics: Vec<Topic> = state.sym_keys.keys().cloned().collect();
        let (events, events_rx) = mpsc::unbounded_channel();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let interval = options.expiry_check_interval;
        let inner = Arc::new(Inner {
            relay,
            metadata,
            options,
            state: Mutex::new(state),
            waiters: Mutex::default(),
            approvals: Mutex::default(),
            events,
            shutdown,
        });
        tokio::spawn(run(
            Arc::downgrade(&inner),
            relay_events,
            shutdown_rx,
            interval,
        ));
        if !topics.is_empty() {
            inner.relay.batch_subscribe(&topics).await?;
        }
        Ok((SignClient { inner }, events_rx))
    }

    pub fn metadata(&self) -> &Metadata {
        &self.inner.metadata
    }

    /// The underlying relay connection.
    pub fn relay(&self) -> &RelayClient {
        &self.inner.relay
    }

    // ----- dapp ----------------------------------------------------------

    /// Propose a session. Show `uri` to the wallet, then await `approval`.
    pub async fn connect(&self, params: ConnectParams) -> Result<ConnectResponse> {
        let inner = &self.inner;
        validate_proposal_namespaces(&params.required_namespaces, "connect() requiredNamespaces")
            .map_err(Error::Protocol)?;
        validate_proposal_namespaces(&params.optional_namespaces, "connect() optionalNamespaces")
            .map_err(Error::Protocol)?;
        validate_properties(params.session_properties.as_ref(), "sessionProperties")?;
        validate_scoped_properties(
            params.scoped_properties.as_ref(),
            params
                .required_namespaces
                .keys()
                .chain(params.optional_namespaces.keys()),
            "required/optional namespaces",
        )?;

        let (pairing_topic, uri) = match params.pairing_topic {
            Some(topic) => {
                let st = inner.state();
                let pairing = st
                    .pairings
                    .get(&topic)
                    .ok_or_else(|| Error::NoPairing(topic.to_string()))?;
                if is_expired(pairing.expiry) {
                    return Err(Error::Expired("pairing"));
                }
                (topic, None)
            }
            None => {
                let sym_key = SymKey::generate();
                let uri = PairingUri::new(sym_key.clone(), expiry_in(FIVE_MINUTES));
                let topic = uri.topic.clone();
                {
                    let mut st = inner.state();
                    st.sym_keys.insert(topic.clone(), sym_key);
                    st.pairings.insert(
                        topic.clone(),
                        Pairing {
                            topic: topic.clone(),
                            expiry: uri.expiry_timestamp.unwrap_or_default(),
                            relay: Relay::default(),
                            active: false,
                            peer_metadata: None,
                            methods: None,
                        },
                    );
                }
                if let Err(e) = inner.relay.subscribe(&topic).await {
                    let mut st = inner.state();
                    st.sym_keys.remove(&topic);
                    st.pairings.remove(&topic);
                    return Err(e);
                }
                (topic, Some(uri))
            }
        };

        let key_pair = KeyPair::generate();
        let id = payload_id();
        let expiry_timestamp = expiry_in(FIVE_MINUTES);
        let propose = SessionProposeParams {
            relays: vec![Relay::default()],
            proposer: Participant {
                public_key: key_pair.public_key(),
                metadata: inner.metadata.clone(),
            },
            required_namespaces: params.required_namespaces,
            optional_namespaces: params.optional_namespaces,
            session_properties: params.session_properties,
            scoped_properties: params.scoped_properties,
            expiry_timestamp: Some(expiry_timestamp),
            pairing_topic: Some(pairing_topic.clone()),
        };
        let proposal = Proposal {
            id,
            pairing_topic: pairing_topic.clone(),
            expiry_timestamp,
            relays: propose.relays.clone(),
            proposer: propose.proposer.clone(),
            required_namespaces: propose.required_namespaces.clone(),
            optional_namespaces: propose.optional_namespaces.clone(),
            session_properties: propose.session_properties.clone(),
            scoped_properties: propose.scoped_properties.clone(),
        };

        let (tx, rx) = oneshot::channel();
        inner.approvals.lock().unwrap().insert(id, tx);
        {
            let mut st = inner.state();
            st.key_pairs
                .insert(key_pair.public_key(), Secret(key_pair.secret_bytes()));
            st.sent_proposals.insert(id, proposal);
        }
        // The response is handled by the engine (on_session_propose_response),
        // which resolves the approval; the raw response receiver is not needed.
        let sent = inner
            .send_request_with_id(
                id,
                &pairing_topic,
                methods::SESSION_PROPOSE,
                serde_json::to_value(&propose)?,
                None,
            )
            .await;
        if let Err(e) = sent {
            inner.approvals.lock().unwrap().remove(&id);
            let mut st = inner.state();
            st.sent_proposals.remove(&id);
            st.key_pairs.remove(&key_pair.public_key());
            return Err(e);
        }

        Ok(ConnectResponse {
            uri,
            pairing_topic,
            approval: Pending::new(rx, Duration::from_secs(FIVE_MINUTES + 30), Ok),
        })
    }

    /// Ask the wallet to perform `request` on `chain_id` and wait for the
    /// answer. A rejection surfaces as [`Error::Peer`].
    pub async fn request(
        &self,
        topic: &Topic,
        chain_id: &str,
        mut request: SessionRequest,
    ) -> Result<Value> {
        let inner = &self.inner;
        {
            let st = inner.state();
            let session = st.session(topic)?;
            if is_expired(session.expiry) {
                return Err(Error::Expired("session"));
            }
            if !session_has_chain(&session.namespaces, chain_id) {
                return Err(Error::Protocol(
                    SdkError::UnsupportedChains.with_context(chain_id),
                ));
            }
            if !session_methods_for_chain(&session.namespaces, chain_id).contains(&request.method) {
                return Err(Error::Protocol(
                    SdkError::UnauthorizedMethod.with_context(&request.method),
                ));
            }
        }
        let ttl = match request.expiry_timestamp {
            Some(ts) => ts.saturating_sub(now_secs()),
            None => FIFTEEN_MINUTES,
        };
        if !(FIVE_MINUTES..=SEVEN_DAYS).contains(&ttl) {
            return Err(protocol(
                InternalError::MissingOrInvalid,
                format!(
                    "request() expiry must be between {FIVE_MINUTES} and {SEVEN_DAYS} seconds from now"
                ),
            ));
        }
        request.expiry_timestamp = Some(expiry_in(ttl));
        let params = SessionRequestParams {
            request,
            chain_id: chain_id.to_owned(),
        };
        let (_, rx) = inner
            .send_request(
                topic,
                methods::SESSION_REQUEST,
                serde_json::to_value(params)?,
                Some(ttl),
            )
            .await?;
        Pending::new(rx, Duration::from_secs(ttl), Ok).await
    }

    // ----- wallet --------------------------------------------------------

    /// Pair with a dapp using the URI it displayed. The proposal follows as
    /// a [`SignEvent::SessionProposal`]; pairing the same URI again while
    /// that proposal is unanswered emits it again.
    pub async fn pair(&self, uri: &str) -> Result<Pairing> {
        self.pair_uri(uri.parse()?).await
    }

    pub async fn pair_uri(&self, uri: PairingUri) -> Result<Pairing> {
        let inner = &self.inner;
        if uri.expiry_timestamp.is_some_and(is_expired) {
            return Err(Error::Expired("pairing uri"));
        }
        let pairing = Pairing {
            topic: uri.topic.clone(),
            expiry: uri
                .expiry_timestamp
                .unwrap_or_else(|| expiry_in(FIVE_MINUTES)),
            relay: Relay {
                protocol: uri.relay_protocol,
                data: uri.relay_data,
            },
            active: false,
            peer_metadata: None,
            methods: uri.methods,
        };
        let pending = {
            let mut st = inner.state();
            if st.pairings.get(&uri.topic).is_some_and(|p| p.active) {
                return Err(protocol(
                    InternalError::MissingOrInvalid,
                    format!(
                        "pairing already exists: {}; use a new connection URI",
                        uri.topic
                    ),
                ));
            }
            st.pairings.insert(uri.topic.clone(), pairing.clone());
            st.sym_keys.entry(uri.topic.clone()).or_insert(uri.sym_key);
            // Proposals already received over this pairing (and not yet
            // answered) when the same URI is scanned again, e.g. after the
            // app was closed before the user decided.
            st.proposals
                .values()
                .filter(|p| p.pairing_topic == uri.topic && !is_expired(p.expiry_timestamp))
                .cloned()
                .collect::<Vec<_>>()
        };
        if let Err(e) = inner.relay.subscribe(&uri.topic).await {
            let mut st = inner.state();
            st.pairings.remove(&uri.topic);
            st.sym_keys.remove(&uri.topic);
            return Err(e);
        }
        // Like the reference SDK, show them again.
        for proposal in pending {
            inner.emit(SignEvent::SessionProposal(proposal));
        }
        Ok(pairing)
    }

    /// Approve proposal `id` granting `namespaces`.
    pub async fn approve(&self, id: u64, namespaces: SessionNamespaces) -> Result<Approved> {
        self.approve_with(ApproveParams {
            id,
            namespaces,
            ..Default::default()
        })
        .await
    }

    pub async fn approve_with(&self, params: ApproveParams) -> Result<Approved> {
        let inner = &self.inner;
        let proposal = {
            let mut st = inner.state();
            let proposal = st
                .proposals
                .get(&params.id)
                .cloned()
                .ok_or(Error::NoProposal(params.id))?;
            if is_expired(proposal.expiry_timestamp) {
                st.proposals.remove(&params.id);
                return Err(Error::Expired("proposal"));
            }
            proposal
        };
        validate_session_namespaces(&params.namespaces, "approve()").map_err(Error::Protocol)?;
        ensure_conforming(
            &proposal.required_namespaces,
            &params.namespaces,
            "approve()",
        )
        .map_err(Error::Protocol)?;
        validate_properties(params.session_properties.as_ref(), "sessionProperties")?;
        validate_scoped_properties(
            params.scoped_properties.as_ref(),
            params.namespaces.keys(),
            "approved namespaces",
        )?;

        let relay = proposal.relays.first().cloned().unwrap_or_default();
        let key_pair = KeyPair::generate();
        let sym_key = key_pair.derive_sym_key(&proposal.proposer.public_key)?;
        let session_topic = sym_key.topic();
        let local = Participant {
            public_key: key_pair.public_key(),
            metadata: inner.metadata.clone(),
        };
        let settle = SessionSettleParams {
            relay: relay.clone(),
            namespaces: params.namespaces.clone(),
            session_properties: params.session_properties.clone(),
            scoped_properties: params.scoped_properties.clone(),
            expiry: expiry_in(SEVEN_DAYS),
            controller: local.clone(),
        };
        let session = Session {
            topic: session_topic.clone(),
            pairing_topic: proposal.pairing_topic.clone(),
            relay: relay.clone(),
            expiry: settle.expiry,
            acknowledged: false,
            controller: key_pair.public_key(),
            namespaces: params.namespaces,
            required_namespaces: proposal.required_namespaces.clone(),
            optional_namespaces: proposal.optional_namespaces.clone(),
            session_properties: params.session_properties,
            scoped_properties: params.scoped_properties,
            local,
            peer: proposal.proposer.clone(),
        };

        inner
            .state()
            .sym_keys
            .insert(session_topic.clone(), sym_key);
        let established = async {
            inner.relay.subscribe(&session_topic).await?;
            inner
                .state()
                .sessions
                .insert(session_topic.clone(), session.clone());
            let response = SessionProposeResponse {
                relay: relay.clone(),
                responder_public_key: key_pair.public_key(),
            };
            inner
                .send_result(
                    &proposal.pairing_topic,
                    params.id,
                    methods::SESSION_PROPOSE,
                    serde_json::to_value(response)?,
                )
                .await?;
            inner
                .send_request(
                    &session_topic,
                    methods::SESSION_SETTLE,
                    serde_json::to_value(&settle)?,
                    None,
                )
                .await
        }
        .await;
        let (_, ack) = match established {
            Ok(sent) => sent,
            Err(e) => {
                {
                    let mut st = inner.state();
                    st.sessions.remove(&session_topic);
                    st.sym_keys.remove(&session_topic);
                }
                let _ = inner.relay.unsubscribe(&session_topic).await;
                return Err(e);
            }
        };

        {
            let mut st = inner.state();
            st.proposals.remove(&params.id);
            if let Some(pairing) = st.pairings.get_mut(&proposal.pairing_topic) {
                pairing.active = true;
                pairing.expiry = expiry_in(THIRTY_DAYS);
                pairing.peer_metadata = Some(proposal.proposer.metadata.clone());
            }
        }
        Ok(Approved {
            session,
            acknowledged: Pending::new(ack, Duration::from_secs(FIVE_MINUTES), |_| Ok(())),
        })
    }

    /// Reject proposal `id`, e.g. with [`SdkError::UserRejected`]. The reason
    /// needs a non-zero code and a message.
    pub async fn reject(&self, id: u64, reason: impl Into<ErrorObject>) -> Result<()> {
        let inner = &self.inner;
        let proposal = inner
            .state()
            .proposals
            .get(&id)
            .cloned()
            .ok_or(Error::NoProposal(id))?;
        let reason = reason.into();
        if reason.code == 0 || reason.message.trim().is_empty() {
            return Err(protocol(
                InternalError::MissingOrInvalid,
                format!("reject() reason: {}", json!(reason)),
            ));
        }
        let opts = rpc::options(methods::SESSION_PROPOSE).and_then(|o| o.reject);
        inner
            .send_error(
                &proposal.pairing_topic,
                id,
                methods::SESSION_PROPOSE,
                reason,
                opts,
            )
            .await?;
        inner.state().proposals.remove(&id);
        Ok(())
    }

    /// Answer session request `id` with a result or an error.
    pub async fn respond(
        &self,
        topic: &Topic,
        id: u64,
        response: std::result::Result<Value, ErrorObject>,
    ) -> Result<()> {
        let inner = &self.inner;
        {
            let st = inner.state();
            let pending = st.pending_requests.get(&id).ok_or(Error::NoRequest(id))?;
            if pending.topic != *topic {
                return Err(protocol(
                    InternalError::MismatchedTopic,
                    format!("request {id} belongs to topic {}", pending.topic),
                ));
            }
        }
        let sent = match response {
            Ok(result) => {
                inner
                    .send_result(topic, id, methods::SESSION_REQUEST, result)
                    .await
            }
            Err(error) => {
                inner
                    .send_error(topic, id, methods::SESSION_REQUEST, error, None)
                    .await
            }
        };
        if sent.is_ok() || !inner.state().sessions.contains_key(topic) {
            inner.state().pending_requests.remove(&id);
        }
        sent
    }

    /// Change the namespaces of a session this client controls. The new
    /// namespaces apply locally right away; the returned value resolves when
    /// the dapp acknowledged them.
    pub async fn update(
        &self,
        topic: &Topic,
        namespaces: SessionNamespaces,
    ) -> Result<Pending<()>> {
        let inner = &self.inner;
        let previous = {
            let mut st = inner.state();
            let session = st.session(topic)?;
            if !session.is_controller() {
                return Err(Error::Protocol(SdkError::UnauthorizedUpdateRequest.error()));
            }
            validate_session_namespaces(&namespaces, "update()").map_err(Error::Protocol)?;
            ensure_conforming(&session.required_namespaces, &namespaces, "update()")
                .map_err(Error::Protocol)?;
            let session = st.sessions.get_mut(topic).expect("checked above");
            std::mem::replace(&mut session.namespaces, namespaces.clone())
        };
        match inner
            .send_request(
                topic,
                methods::SESSION_UPDATE,
                serde_json::to_value(SessionUpdateParams { namespaces })?,
                None,
            )
            .await
        {
            Ok((_, rx)) => Ok(Pending::new(rx, inner.options.ack_timeout, |_| Ok(()))),
            Err(e) => {
                if let Some(session) = inner.state().sessions.get_mut(topic) {
                    session.namespaces = previous;
                }
                Err(e)
            }
        }
    }

    /// Extend a session to seven days from now. Either peer may extend, as
    /// with the reference SDK; the returned value resolves when the peer
    /// acknowledged the extension.
    pub async fn extend(&self, topic: &Topic) -> Result<Pending<()>> {
        let inner = &self.inner;
        let expiry = expiry_in(SEVEN_DAYS);
        {
            let mut st = inner.state();
            st.session(topic)?;
            st.sessions.get_mut(topic).expect("checked above").expiry = expiry;
        }
        let params = SessionExtendParams {
            expiry: Some(expiry),
        };
        let (_, rx) = inner
            .send_request(
                topic,
                methods::SESSION_EXTEND,
                serde_json::to_value(params)?,
                None,
            )
            .await?;
        Ok(Pending::new(rx, inner.options.ack_timeout, |_| Ok(())))
    }

    /// Emit an event (e.g. `accountsChanged`) to the dapp.
    pub async fn emit(&self, topic: &Topic, chain_id: &str, event: SessionEvent) -> Result<()> {
        let inner = &self.inner;
        {
            let st = inner.state();
            let session = st.session(topic)?;
            if !session_has_chain(&session.namespaces, chain_id) {
                return Err(Error::Protocol(
                    SdkError::UnsupportedChains.with_context(chain_id),
                ));
            }
            if !session_events_for_chain(&session.namespaces, chain_id).contains(&event.name) {
                return Err(Error::Protocol(
                    SdkError::UnauthorizedEvent.with_context(&event.name),
                ));
            }
        }
        let params = SessionEventParams {
            event,
            chain_id: chain_id.to_owned(),
        };
        inner
            .send_notification(topic, methods::SESSION_EVENT, serde_json::to_value(params)?)
            .await
    }

    // ----- both ----------------------------------------------------------

    /// Ping the peer of a session or pairing and wait for the pong.
    pub async fn ping(&self, topic: &Topic) -> Result<()> {
        let inner = &self.inner;
        let method = {
            let st = inner.state();
            if st.sessions.contains_key(topic) {
                methods::SESSION_PING
            } else if st.pairings.contains_key(topic) {
                methods::PAIRING_PING
            } else {
                return Err(Error::NoSession(topic.to_string()));
            }
        };
        let (_, rx) = inner.send_request(topic, method, json!({}), None).await?;
        Pending::new(rx, inner.options.ping_timeout, |_| Ok(())).await
    }

    /// End a session (or delete a pairing) and tell the peer.
    pub async fn disconnect(&self, topic: &Topic) -> Result<()> {
        let inner = &self.inner;
        let reason = SdkError::UserDisconnected.error();
        let (is_session, is_pairing) = {
            let st = inner.state();
            (
                st.sessions.contains_key(topic),
                st.pairings.contains_key(topic),
            )
        };
        if is_session {
            inner
                .send_notification(
                    topic,
                    methods::SESSION_DELETE,
                    serde_json::to_value(&reason)?,
                )
                .await?;
            inner.delete_session(topic, reason).await;
        } else if is_pairing {
            inner
                .send_notification(
                    topic,
                    methods::PAIRING_DELETE,
                    serde_json::to_value(&reason)?,
                )
                .await?;
            inner.delete_pairing(topic).await;
        } else {
            return Err(Error::NoSession(topic.to_string()));
        }
        Ok(())
    }

    pub fn sessions(&self) -> Vec<Session> {
        self.inner.state().sessions.values().cloned().collect()
    }

    pub fn session(&self, topic: &Topic) -> Option<Session> {
        self.inner.state().sessions.get(topic).cloned()
    }

    pub fn pairings(&self) -> Vec<Pairing> {
        self.inner.state().pairings.values().cloned().collect()
    }

    /// Proposals received and not yet answered (wallet).
    pub fn proposals(&self) -> Vec<Proposal> {
        self.inner.state().proposals.values().cloned().collect()
    }

    /// Session requests received and not yet answered (wallet).
    pub fn pending_requests(&self) -> Vec<PendingRequest> {
        self.inner
            .state()
            .pending_requests
            .values()
            .cloned()
            .collect()
    }

    /// Everything needed to resume after a restart.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot(self.inner.state().clone())
    }

    /// Close the relay connection and stop processing. Everything still
    /// awaiting a peer fails with [`Error::Closed`].
    pub fn shutdown(&self) {
        self.inner.relay.close();
        let _ = self.inner.shutdown.send(true);
        for (_, waiter) in self.inner.waiters.lock().unwrap().drain() {
            let _ = waiter.send(Err(Error::Closed));
        }
        for (_, approval) in self.inner.approvals.lock().unwrap().drain() {
            let _ = approval.send(Err(Error::Closed));
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

async fn run(
    inner: Weak<Inner>,
    mut relay_events: mpsc::UnboundedReceiver<RelayEvent>,
    mut shutdown: watch::Receiver<bool>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            event = relay_events.recv() => {
                let Some(event) = event else { break };
                let Some(inner) = inner.upgrade() else { break };
                match event {
                    RelayEvent::Message(data) => inner.on_message(data).await,
                    RelayEvent::Connected => inner.emit(SignEvent::RelayConnected),
                    RelayEvent::Disconnected => inner.emit(SignEvent::RelayDisconnected),
                }
            }
            _ = ticker.tick() => {
                let Some(inner) = inner.upgrade() else { break };
                inner.expire().await;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn emit(&self, event: SignEvent) {
        let _ = self.events.send(event);
    }

    fn resolve_approval(&self, proposal_id: u64, outcome: Result<Session>) {
        if let Some(tx) = self.approvals.lock().unwrap().remove(&proposal_id) {
            let _ = tx.send(outcome);
        }
    }

    // ----- sending -------------------------------------------------------

    async fn publish_payload(
        &self,
        topic: &Topic,
        payload: &impl Serialize,
        opts: PublishOptions,
    ) -> Result<()> {
        let message = {
            let mut st = self.state();
            let key =
                st.sym_keys.get(topic).cloned().ok_or_else(|| {
                    protocol(InternalError::NoMatchingKey, format!("topic {topic}"))
                })?;
            let message = key.encrypt(&serde_json::to_vec(payload)?);
            // Remember our own message so that an echo from the relay is
            // ignored.
            st.remember(sha256_hex(message.as_bytes()));
            message
        };
        self.relay.publish(topic, &message, opts).await
    }

    async fn send_request(
        &self,
        topic: &Topic,
        method: &str,
        params: Value,
        ttl: Option<u64>,
    ) -> Result<(u64, oneshot::Receiver<Result<Value>>)> {
        self.send_request_with_id(payload_id(), topic, method, params, ttl)
            .await
    }

    async fn send_request_with_id(
        &self,
        id: u64,
        topic: &Topic,
        method: &str,
        params: Value,
        ttl: Option<u64>,
    ) -> Result<(u64, oneshot::Receiver<Result<Value>>)> {
        let mut opts = rpc::options(method).unwrap_or(rpc::UNREGISTERED).request;
        if let Some(ttl) = ttl {
            opts.ttl = ttl;
        }
        let (tx, rx) = oneshot::channel();
        self.state().history.insert(
            id,
            Record {
                topic: topic.clone(),
                method: method.to_owned(),
                expiry: expiry_in(opts.ttl + FIVE_MINUTES),
            },
        );
        self.waiters.lock().unwrap().insert(id, tx);
        let request = Request::with_id(id, method, params);
        if let Err(e) = self.publish_payload(topic, &request, opts).await {
            self.state().history.remove(&id);
            self.waiters.lock().unwrap().remove(&id);
            return Err(e);
        }
        Ok((id, rx))
    }

    /// A request whose response nobody waits for.
    async fn send_notification(&self, topic: &Topic, method: &str, params: Value) -> Result<()> {
        let opts = rpc::options(method).unwrap_or(rpc::UNREGISTERED).request;
        self.publish_payload(topic, &Request::new(method, params), opts)
            .await
    }

    async fn send_result(&self, topic: &Topic, id: u64, method: &str, result: Value) -> Result<()> {
        let opts = rpc::options(method).unwrap_or(rpc::UNREGISTERED).response;
        self.publish_payload(topic, &Response::result(id, result), opts)
            .await
    }

    async fn send_error(
        &self,
        topic: &Topic,
        id: u64,
        method: &str,
        error: ErrorObject,
        opts: Option<PublishOptions>,
    ) -> Result<()> {
        let opts =
            opts.unwrap_or_else(|| rpc::options(method).unwrap_or(rpc::UNREGISTERED).response);
        self.publish_payload(topic, &Response::error(id, error), opts)
            .await
    }

    /// Answer `req` with `true`, or with the error if `outcome` failed.
    async fn answer(&self, topic: &Topic, req: &Request, outcome: &Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => {
                self.send_result(topic, req.id, &req.method, Value::Bool(true))
                    .await
            }
            Err(e) => {
                self.send_error(topic, req.id, &req.method, e.to_error_object(), None)
                    .await
            }
        }
    }

    // ----- local bookkeeping ---------------------------------------------

    async fn delete_session(&self, topic: &Topic, reason: ErrorObject) {
        let orphaned: Vec<u64> = {
            let mut st = self.state();
            st.sessions.remove(topic);
            st.sym_keys.remove(topic);
            st.pending_requests.retain(|_, r| r.topic != *topic);
            let prefix = format!("{topic}/");
            st.last_ids.retain(|k, _| !k.starts_with(&prefix));
            let ids: Vec<u64> = st
                .history
                .iter()
                .filter(|(_, r)| r.topic == *topic)
                .map(|(id, _)| *id)
                .collect();
            for id in &ids {
                st.history.remove(id);
            }
            ids
        };
        {
            let mut waiters = self.waiters.lock().unwrap();
            for id in orphaned {
                if let Some(w) = waiters.remove(&id) {
                    let _ = w.send(Err(Error::Peer(reason.clone())));
                }
            }
        }
        if let Err(e) = self.relay.unsubscribe(topic).await {
            tracing::debug!(%topic, "unsubscribe failed: {e}");
        }
    }

    async fn delete_pairing(&self, topic: &Topic) {
        {
            let mut st = self.state();
            st.pairings.remove(topic);
            st.sym_keys.remove(topic);
        }
        if let Err(e) = self.relay.unsubscribe(topic).await {
            tracing::debug!(%topic, "unsubscribe failed: {e}");
        }
    }

    /// Dapp: delete older pairings with the wallet a session was just settled
    /// with (same metadata URL), like the reference SDK. Every `connect`
    /// creates a pairing, and active pairings otherwise live for 30 days.
    async fn cleanup_duplicate_pairings(&self, session: &Session) {
        let url = &session.peer.metadata.url;
        if url.is_empty() {
            return;
        }
        let duplicates: Vec<Topic> = self
            .state()
            .pairings
            .values()
            .filter(|p| {
                p.topic != session.pairing_topic
                    && p.peer_metadata.as_ref().is_some_and(|m| &m.url == url)
            })
            .map(|p| p.topic.clone())
            .collect();
        for topic in duplicates {
            let reason = json!(SdkError::UserDisconnected.error());
            if let Err(e) = self
                .send_notification(&topic, methods::PAIRING_DELETE, reason)
                .await
            {
                tracing::debug!(%topic, "telling the peer about a duplicate pairing failed: {e}");
            }
            self.delete_pairing(&topic).await;
        }
    }

    /// Dapp: forget a proposal we sent (and its pending session, if any).
    async fn drop_sent_proposal(&self, id: u64) {
        let pending_topic = {
            let mut st = self.state();
            if let Some(p) = st.sent_proposals.remove(&id) {
                st.key_pairs.remove(&p.proposer.public_key);
            }
            let pending = st.pending_sessions.remove(&id);
            if let Some(pending) = &pending {
                st.sym_keys.remove(&pending.session_topic);
            }
            pending.map(|p| p.session_topic)
        };
        if let Some(topic) = pending_topic {
            let _ = self.relay.unsubscribe(&topic).await;
        }
    }

    async fn expire(&self) {
        let now = now_secs();
        let (sessions, pairings, proposals, sent, requests, history) = {
            let st = self.state();
            (
                st.sessions
                    .values()
                    .filter(|s| s.expiry <= now)
                    .map(|s| s.topic.clone())
                    .collect::<Vec<_>>(),
                st.pairings
                    .values()
                    .filter(|p| p.expiry <= now)
                    .map(|p| p.topic.clone())
                    .collect::<Vec<_>>(),
                st.proposals
                    .values()
                    .filter(|p| p.expiry_timestamp <= now)
                    .map(|p| p.id)
                    .collect::<Vec<_>>(),
                st.sent_proposals
                    .values()
                    .filter(|p| p.expiry_timestamp <= now)
                    .map(|p| p.id)
                    .collect::<Vec<_>>(),
                st.pending_requests
                    .values()
                    .filter(|r| r.request.expiry_timestamp.is_some_and(|e| e <= now))
                    .map(|r| (r.id, r.topic.clone()))
                    .collect::<Vec<_>>(),
                st.history
                    .iter()
                    .filter(|(_, r)| r.expiry <= now)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>(),
            )
        };
        for topic in sessions {
            self.delete_session(&topic, InternalError::Expired.with_context("session"))
                .await;
            self.emit(SignEvent::SessionExpire { topic });
        }
        for topic in pairings {
            self.delete_pairing(&topic).await;
            self.emit(SignEvent::PairingExpire { topic });
        }
        for id in proposals {
            self.state().proposals.remove(&id);
            self.emit(SignEvent::ProposalExpire { id });
        }
        for id in sent {
            self.drop_sent_proposal(id).await;
            self.resolve_approval(id, Err(Error::Expired("proposal")));
            self.emit(SignEvent::ProposalExpire { id });
        }
        for (id, topic) in requests {
            self.state().pending_requests.remove(&id);
            self.emit(SignEvent::SessionRequestExpire { id, topic });
        }
        if !history.is_empty() {
            {
                let mut st = self.state();
                for id in &history {
                    st.history.remove(id);
                }
            }
            let mut waiters = self.waiters.lock().unwrap();
            for id in history {
                if let Some(w) = waiters.remove(&id) {
                    let _ = w.send(Err(Error::Timeout));
                }
            }
        }
    }

    // ----- receiving -----------------------------------------------------

    async fn on_message(&self, data: SubscriptionData) {
        let key = {
            let mut st = self.state();
            if !st.remember(sha256_hex(data.message.as_bytes())) {
                tracing::trace!(topic = %data.topic, "dropping duplicate message");
                return;
            }
            st.sym_keys.get(&data.topic).cloned()
        };
        let Some(key) = key else {
            tracing::debug!(topic = %data.topic, "message on a topic without a key");
            return;
        };
        let payload = match decode(&key, &data.message) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(topic = %data.topic, "undecodable message: {e}");
                return;
            }
        };
        let topic = data.topic;
        let handled = match payload {
            Payload::Request(req) => {
                tracing::debug!(%topic, method = %req.method, id = req.id, "incoming request");
                self.on_request(&topic, req).await
            }
            Payload::Response(res) => {
                tracing::debug!(%topic, id = res.id, ok = res.outcome.is_ok(), "incoming response");
                self.on_response(&topic, res).await
            }
        };
        if let Err(e) = handled {
            tracing::warn!(%topic, "handling message failed: {e}");
        }
    }

    async fn on_request(&self, topic: &Topic, req: Request) -> Result<()> {
        match req.method.as_str() {
            methods::SESSION_PROPOSE => self.on_session_propose(topic, req).await,
            methods::SESSION_SETTLE => self.on_session_settle(topic, req).await,
            methods::SESSION_UPDATE => self.on_session_update(topic, req).await,
            methods::SESSION_EXTEND => self.on_session_extend(topic, req).await,
            methods::SESSION_REQUEST => self.on_session_request(topic, req).await,
            methods::SESSION_EVENT => self.on_session_event(topic, req).await,
            methods::SESSION_PING => self.on_session_ping(topic, req).await,
            methods::SESSION_DELETE => self.on_session_delete(topic, req).await,
            methods::PAIRING_PING => self.on_pairing_ping(topic, req).await,
            methods::PAIRING_DELETE => self.on_pairing_delete(topic, req).await,
            other => {
                // Silently ignored, like the reference SDK: answering e.g.
                // wc_sessionAuthenticate with an error would abort the
                // dapp's fallback to a regular session proposal.
                tracing::debug!(method = other, "ignoring unsupported request");
                Ok(())
            }
        }
    }

    async fn on_response(&self, topic: &Topic, res: Response) -> Result<()> {
        let record = self.state().history.get(&res.id).cloned();
        let Some(record) = record else {
            tracing::debug!(id = res.id, "response to an unknown request");
            return Ok(());
        };
        if record.topic != *topic {
            tracing::warn!(id = res.id, %topic, "response arrived on the wrong topic; ignored");
            return Ok(());
        }
        self.state().history.remove(&res.id);
        match record.method.as_str() {
            methods::SESSION_PROPOSE => self.on_session_propose_response(topic, &res).await,
            methods::SESSION_SETTLE => self.on_session_settle_response(topic, &res).await,
            _ => {}
        }
        if let Some(waiter) = self.waiters.lock().unwrap().remove(&res.id) {
            let _ = waiter.send(res.outcome.map_err(Error::Peer));
        }
        Ok(())
    }

    /// Wallet: a dapp proposes a session on a pairing topic.
    async fn on_session_propose(&self, topic: &Topic, req: Request) -> Result<()> {
        if !self.state().pairings.contains_key(topic) {
            tracing::debug!(%topic, "proposal on a topic that is not a pairing; ignored");
            return Ok(());
        }
        let parsed = (|| -> Result<Proposal> {
            let params: SessionProposeParams = parse_params(&req)?;
            if params.relays.is_empty() || params.relays.iter().any(|r| r.protocol.is_empty()) {
                return Err(protocol(
                    InternalError::MissingOrInvalid,
                    "wc_sessionPropose relays",
                ));
            }
            validate_proposal_namespaces(
                &params.required_namespaces,
                "wc_sessionPropose requiredNamespaces",
            )
            .map_err(Error::Protocol)?;
            validate_proposal_namespaces(
                &params.optional_namespaces,
                "wc_sessionPropose optionalNamespaces",
            )
            .map_err(Error::Protocol)?;
            Ok(Proposal {
                id: req.id,
                pairing_topic: topic.clone(),
                expiry_timestamp: params
                    .expiry_timestamp
                    .unwrap_or_else(|| expiry_in(FIVE_MINUTES)),
                relays: params.relays,
                proposer: params.proposer,
                required_namespaces: params.required_namespaces,
                optional_namespaces: params.optional_namespaces,
                session_properties: params.session_properties,
                scoped_properties: params.scoped_properties,
            })
        })();
        match parsed {
            Ok(proposal) => {
                if is_expired(proposal.expiry_timestamp) {
                    tracing::debug!(id = proposal.id, "dropping expired proposal");
                    return Ok(());
                }
                let is_new = self
                    .state()
                    .proposals
                    .insert(proposal.id, proposal.clone())
                    .is_none();
                if is_new {
                    self.emit(SignEvent::SessionProposal(proposal));
                }
                Ok(())
            }
            Err(e) => {
                let opts = rpc::options(methods::SESSION_PROPOSE).and_then(|o| o.auto_reject);
                self.send_error(topic, req.id, &req.method, e.to_error_object(), opts)
                    .await
            }
        }
    }

    /// Dapp: the wallet answered our proposal.
    async fn on_session_propose_response(&self, pairing_topic: &Topic, res: &Response) {
        let proposal = self.state().sent_proposals.get(&res.id).cloned();
        let Some(proposal) = proposal else { return };
        let result = match &res.outcome {
            Ok(result) => result,
            Err(error) => {
                self.drop_sent_proposal(res.id).await;
                self.resolve_approval(res.id, Err(Error::Peer(error.clone())));
                return;
            }
        };
        let derived = (|| -> Result<SymKey> {
            let response: SessionProposeResponse = serde_json::from_value(result.clone())?;
            let secret = self
                .state()
                .key_pairs
                .get(&proposal.proposer.public_key)
                .cloned()
                .ok_or_else(|| protocol(InternalError::NoMatchingKey, "proposer key pair"))?;
            KeyPair::from_secret(secret.0).derive_sym_key(&response.responder_public_key)
        })();
        let sym_key = match derived {
            Ok(key) => key,
            Err(e) => {
                self.drop_sent_proposal(res.id).await;
                self.resolve_approval(res.id, Err(e));
                return;
            }
        };
        let session_topic = sym_key.topic();
        {
            let mut st = self.state();
            st.sym_keys.insert(session_topic.clone(), sym_key);
            st.pending_sessions.insert(
                res.id,
                PendingSession {
                    session_topic: session_topic.clone(),
                    pairing_topic: pairing_topic.clone(),
                    public_key: proposal.proposer.public_key,
                },
            );
            if let Some(pairing) = st.pairings.get_mut(pairing_topic) {
                pairing.active = true;
                pairing.expiry = expiry_in(THIRTY_DAYS);
            }
        }
        if let Err(e) = self.relay.subscribe(&session_topic).await {
            self.drop_sent_proposal(res.id).await;
            self.resolve_approval(res.id, Err(e));
        }
    }

    /// Dapp: the wallet settles the session.
    async fn on_session_settle(&self, topic: &Topic, req: Request) -> Result<()> {
        let pending = {
            let st = self.state();
            st.pending_sessions
                .iter()
                .find(|(_, p)| p.session_topic == *topic)
                .map(|(id, p)| (*id, p.clone(), st.sent_proposals.get(id).cloned()))
        };
        let Some((proposal_id, pending, proposal)) = pending else {
            if self.state().sessions.contains_key(topic) {
                // A retransmission of a settlement we already accepted.
                return self.answer(topic, &req, &Ok(())).await;
            }
            tracing::debug!(%topic, "settlement without a pending session; ignored");
            return Ok(());
        };

        let settled = (|| -> Result<Session> {
            let params: SessionSettleParams = parse_params(&req)?;
            if params.relay.protocol.is_empty() {
                return Err(protocol(
                    InternalError::MissingOrInvalid,
                    "wc_sessionSettle relay",
                ));
            }
            validate_session_namespaces(&params.namespaces, "wc_sessionSettle")
                .map_err(Error::Protocol)?;
            let (required, optional) = proposal
                .map(|p| (p.required_namespaces, p.optional_namespaces))
                .unwrap_or_default();
            ensure_conforming(&required, &params.namespaces, "wc_sessionSettle")
                .map_err(Error::Protocol)?;
            if is_expired(params.expiry) {
                return Err(protocol(InternalError::Expired, "wc_sessionSettle"));
            }
            Ok(Session {
                topic: topic.clone(),
                pairing_topic: pending.pairing_topic.clone(),
                relay: params.relay,
                expiry: params.expiry,
                acknowledged: true,
                controller: params.controller.public_key,
                namespaces: params.namespaces,
                required_namespaces: required,
                optional_namespaces: optional,
                session_properties: params.session_properties,
                scoped_properties: params.scoped_properties,
                local: Participant {
                    public_key: pending.public_key,
                    metadata: self.metadata.clone(),
                },
                peer: params.controller,
            })
        })();

        match settled {
            Ok(session) => {
                {
                    let mut st = self.state();
                    st.sessions.insert(topic.clone(), session.clone());
                    st.pending_sessions.remove(&proposal_id);
                    st.sent_proposals.remove(&proposal_id);
                    st.key_pairs.remove(&pending.public_key);
                    if let Some(pairing) = st.pairings.get_mut(&pending.pairing_topic) {
                        pairing.peer_metadata = Some(session.peer.metadata.clone());
                    }
                }
                let answered = self.answer(topic, &req, &Ok(())).await;
                self.emit(SignEvent::SessionConnect(session.clone()));
                self.resolve_approval(proposal_id, Ok(session.clone()));
                self.cleanup_duplicate_pairings(&session).await;
                answered
            }
            Err(e) => {
                let answered = self
                    .send_error(topic, req.id, &req.method, e.to_error_object(), None)
                    .await;
                self.drop_sent_proposal(proposal_id).await;
                self.resolve_approval(proposal_id, Err(e));
                answered
            }
        }
    }

    /// Wallet: the dapp acknowledged (or refused) the settlement.
    async fn on_session_settle_response(&self, topic: &Topic, res: &Response) {
        match &res.outcome {
            Ok(_) => {
                if let Some(session) = self.state().sessions.get_mut(topic) {
                    session.acknowledged = true;
                }
            }
            Err(error) => {
                tracing::warn!(%topic, "dapp refused the settlement: {error}");
                self.delete_session(topic, error.clone()).await;
            }
        }
    }

    async fn on_session_update(&self, topic: &Topic, req: Request) -> Result<()> {
        let key = format!("{topic}/update");
        let outcome = (|| -> Result<SessionNamespaces> {
            let st = self.state();
            let session = st.session(topic)?;
            if session.peer.public_key != session.controller {
                return Err(Error::Protocol(SdkError::UnauthorizedUpdateRequest.error()));
            }
            if is_out_of_sync(st.last_ids.get(&key).copied(), req.id) {
                return Err(Error::Protocol(
                    SdkError::InvalidUpdateRequest.with_context("out of order"),
                ));
            }
            let params: SessionUpdateParams = parse_params(&req)?;
            validate_session_namespaces(&params.namespaces, "wc_sessionUpdate")
                .map_err(Error::Protocol)?;
            ensure_conforming(
                &session.required_namespaces,
                &params.namespaces,
                "wc_sessionUpdate",
            )
            .map_err(Error::Protocol)?;
            Ok(params.namespaces)
        })();
        match outcome {
            Ok(namespaces) => {
                {
                    let mut st = self.state();
                    st.last_ids.insert(key, req.id);
                    if let Some(session) = st.sessions.get_mut(topic) {
                        session.namespaces = namespaces.clone();
                    }
                }
                self.answer(topic, &req, &Ok(())).await?;
                self.emit(SignEvent::SessionUpdate {
                    id: req.id,
                    topic: topic.clone(),
                    namespaces,
                });
                Ok(())
            }
            Err(e) => self.answer(topic, &req, &Err(e)).await,
        }
    }

    /// Either peer may extend: the reference SDK lets dapps call `extend` too.
    async fn on_session_extend(&self, topic: &Topic, req: Request) -> Result<()> {
        let outcome = (|| -> Result<u64> {
            let mut st = self.state();
            st.session(topic)?;
            let expiry = expiry_in(SEVEN_DAYS);
            st.sessions.get_mut(topic).expect("checked above").expiry = expiry;
            Ok(expiry)
        })();
        match outcome {
            Ok(expiry) => {
                self.answer(topic, &req, &Ok(())).await?;
                self.emit(SignEvent::SessionExtend {
                    id: req.id,
                    topic: topic.clone(),
                    expiry,
                });
                Ok(())
            }
            Err(e) => self.answer(topic, &req, &Err(e)).await,
        }
    }

    /// Wallet: the dapp asks for something.
    async fn on_session_request(&self, topic: &Topic, req: Request) -> Result<()> {
        let outcome = (|| -> Result<PendingRequest> {
            let st = self.state();
            let session = st.session(topic)?;
            let params: SessionRequestParams = parse_params(&req)?;
            if !session_has_chain(&session.namespaces, &params.chain_id) {
                return Err(Error::Protocol(
                    SdkError::UnsupportedChains.with_context(&params.chain_id),
                ));
            }
            if !session_methods_for_chain(&session.namespaces, &params.chain_id)
                .contains(&params.request.method)
            {
                return Err(Error::Protocol(
                    SdkError::UnauthorizedMethod.with_context(&params.request.method),
                ));
            }
            if params.request.expiry_timestamp.is_some_and(is_expired) {
                return Err(protocol(InternalError::Expired, "request"));
            }
            Ok(PendingRequest {
                id: req.id,
                topic: topic.clone(),
                chain_id: params.chain_id,
                request: params.request,
            })
        })();
        match outcome {
            Ok(pending) => {
                let is_new = self
                    .state()
                    .pending_requests
                    .insert(pending.id, pending.clone())
                    .is_none();
                if is_new {
                    self.emit(SignEvent::SessionRequest(pending));
                }
                Ok(())
            }
            Err(e) => self.answer(topic, &req, &Err(e)).await,
        }
    }

    /// Dapp: the wallet emits an event.
    async fn on_session_event(&self, topic: &Topic, req: Request) -> Result<()> {
        let outcome = (|| -> Result<Option<SessionEventParams>> {
            let st = self.state();
            let session = st.session(topic)?;
            let params: SessionEventParams = parse_params(&req)?;
            if !session_has_chain(&session.namespaces, &params.chain_id) {
                return Err(Error::Protocol(
                    SdkError::UnsupportedChains.with_context(&params.chain_id),
                ));
            }
            if !session_events_for_chain(&session.namespaces, &params.chain_id)
                .contains(&params.event.name)
            {
                return Err(Error::Protocol(
                    SdkError::UnauthorizedEvent.with_context(&params.event.name),
                ));
            }
            let key = format!("{topic}/event/{}", params.event.name);
            if is_out_of_sync(st.last_ids.get(&key).copied(), req.id) {
                return Ok(None);
            }
            Ok(Some(params))
        })();
        match outcome {
            Ok(None) => {
                tracing::debug!(id = req.id, "dropping out-of-order event");
                Ok(())
            }
            Ok(Some(params)) => {
                self.state()
                    .last_ids
                    .insert(format!("{topic}/event/{}", params.event.name), req.id);
                self.answer(topic, &req, &Ok(())).await?;
                self.emit(SignEvent::SessionEvent {
                    id: req.id,
                    topic: topic.clone(),
                    chain_id: params.chain_id,
                    event: params.event,
                });
                Ok(())
            }
            Err(e) => self.answer(topic, &req, &Err(e)).await,
        }
    }

    async fn on_session_ping(&self, topic: &Topic, req: Request) -> Result<()> {
        let outcome = self.state().session(topic).map(|_| ());
        self.answer(topic, &req, &outcome).await?;
        if outcome.is_ok() {
            self.emit(SignEvent::SessionPing {
                id: req.id,
                topic: topic.clone(),
            });
        }
        Ok(())
    }

    async fn on_session_delete(&self, topic: &Topic, req: Request) -> Result<()> {
        if !self.state().sessions.contains_key(topic) {
            return Ok(());
        }
        let reason: ErrorObject = serde_json::from_value(req.params.clone())
            .unwrap_or_else(|_| SdkError::UserDisconnected.error());
        // Like the reference SDK, no response: the peer already forgot the
        // session and its key.
        self.delete_session(topic, reason.clone()).await;
        self.emit(SignEvent::SessionDelete {
            id: req.id,
            topic: topic.clone(),
            reason,
        });
        Ok(())
    }

    async fn on_pairing_ping(&self, topic: &Topic, req: Request) -> Result<()> {
        let known = self.state().pairings.contains_key(topic);
        let outcome = if known {
            Ok(())
        } else {
            Err(Error::NoPairing(topic.to_string()))
        };
        self.answer(topic, &req, &outcome).await?;
        if known {
            self.emit(SignEvent::PairingPing {
                id: req.id,
                topic: topic.clone(),
            });
        }
        Ok(())
    }

    async fn on_pairing_delete(&self, topic: &Topic, req: Request) -> Result<()> {
        if !self.state().pairings.contains_key(topic) {
            return Ok(());
        }
        self.delete_pairing(topic).await;
        self.emit(SignEvent::PairingDelete {
            id: req.id,
            topic: topic.clone(),
        });
        Ok(())
    }
}

fn decode(key: &SymKey, message: &str) -> Result<Payload> {
    let envelope = Envelope::decode(message)?;
    if envelope.kind != TYPE_0 {
        return Err(Error::InvalidEnvelope(format!(
            "type {} envelopes are not used by the Sign API",
            envelope.kind
        )));
    }
    let plaintext = envelope.open(key)?;
    let text =
        std::str::from_utf8(&plaintext).map_err(|_| Error::InvalidPayload("not utf-8".into()))?;
    Payload::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_sync_compares_timestamps() {
        assert!(!is_out_of_sync(None, 5));
        assert!(!is_out_of_sync(
            Some(1_700_000_000_000_123),
            1_700_000_000_000_999
        ));
        assert!(!is_out_of_sync(
            Some(1_700_000_000_000_123),
            1_700_000_000_001_000
        ));
        assert!(is_out_of_sync(
            Some(1_700_000_000_001_123),
            1_700_000_000_000_999
        ));
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        let mut state = State::default();
        let key = SymKey::generate();
        state.sym_keys.insert(key.topic(), key.clone());
        let kp = KeyPair::generate();
        state
            .key_pairs
            .insert(kp.public_key(), Secret(kp.secret_bytes()));
        let json = serde_json::to_string(&Snapshot(state)).unwrap();
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.0.sym_keys.get(&key.topic()), Some(&key));
        assert_eq!(
            KeyPair::from_secret(back.0.key_pairs[&kp.public_key()].0).public_key(),
            kp.public_key()
        );
    }
}
