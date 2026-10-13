//! Shared harness for the ports of the JavaScript SDK's test suites.
//!
//! * Fixtures mirror `packages/sign-client/test/shared/values.ts`.
//! * [`test_connect`] mirrors `testConnectMethod` (`shared/connect.ts`).
//! * [`RawPeer`] speaks the wire protocol by hand. The JS tests call private
//!   engine handlers directly (e.g. `engine.onSessionUpdateRequest`); here the
//!   equivalent crafted message is encrypted and published on the relay.
//! * [`Tap`] records every frame a client sends to the relay, in place of the
//!   JS tests' spies on `relayer.publish`/`provider.request`.

// Each test crate uses a different subset of the harness.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use wallet_connect::crypto::{SymKey, Topic};
use wallet_connect::relay::rpc::PublishParams;
use wallet_connect::relay::{
    BoxFuture, Connection, Connector, PublishOptions, RelayClient, RelayClientOptions, RelayEvent,
    RelayServer,
};
use wallet_connect::rpc::{Payload, Request, Response};
use wallet_connect::sign::{
    ApproveParams, ConnectParams, Metadata, Pairing, Properties, ProposalNamespaces, Relay,
    Session, SessionEvent, SessionNamespaces, SessionRequest, SignClient, SignClientOptions,
    SignEvent, SignEvents, Snapshot,
};

/// How long to wait for something that should happen.
pub const WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Fixtures (sign-client/test/shared/values.ts)
// ---------------------------------------------------------------------------

pub const TEST_ETHEREUM_CHAIN: &str = "eip155:1";
pub const TEST_ARBITRUM_CHAIN: &str = "eip155:42161";
pub const TEST_AVALANCHE_CHAIN: &str = "eip155:43114";
pub const TEST_POLKADOT_CHAIN: &str = "polkadot:91b171bb158e2d3848fa23a9f1c25182";
pub const TEST_CHAINS: [&str; 2] = [TEST_ETHEREUM_CHAIN, TEST_ARBITRUM_CHAIN];
pub const TEST_METHODS: [&str; 4] = [
    "eth_sendTransaction",
    "eth_signTransaction",
    "personal_sign",
    "eth_signTypedData",
];
pub const TEST_POLKADOT_METHODS: [&str; 2] = ["polkadot_signTransaction", "polkadot_signMessage"];
pub const TEST_EVENTS: [&str; 2] = ["chainChanged", "accountsChanged"];
pub const TEST_ETHEREUM_ADDRESS: &str = "0x3c582121909DE92Dc89A36898633C1aE4790382b";
pub const TEST_POLKADOT_ADDRESS: &str = "8cGfbK9Q4zbsNzhZsZUtpsQgX5LG2UCPEDuXYV33whktGt7";

pub fn from_json<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).expect("fixture matches the type")
}

pub fn account(chain: &str, address: &str) -> String {
    format!("{chain}:{address}")
}

pub fn test_app_metadata_a() -> Metadata {
    from_json(json!({
        "name": "App A (Proposer)",
        "description": "Description of Proposer App run by client A",
        "url": "https://app.a.walletconnect.com",
        "icons": ["https://avatars.githubusercontent.com/u/37784886"],
        "redirect": {"universal": "App A (Proposer)", "native": "App A Native (Proposer)"},
    }))
}

pub fn test_app_metadata_b() -> Metadata {
    from_json(json!({
        "name": "App B (Responder)",
        "description": "Description of Responder App run by client B",
        "url": "https://app.b.walletconnect.com",
        "icons": ["https://avatars.githubusercontent.com/u/37784886"],
        "redirect": {"universal": "App B (Responder)", "native": "App B Native (Responder)"},
    }))
}

pub fn test_wallet_metadata() -> Metadata {
    from_json(json!({
        "name": "Test Wallet",
        "description": "Test Wallet for WalletConnect",
        "url": "https://walletconnect.com/",
        "icons": ["https://avatars.githubusercontent.com/u/37784886"],
    }))
}

pub fn test_required_namespaces() -> ProposalNamespaces {
    from_json(json!({
        "eip155": {"methods": TEST_METHODS, "chains": TEST_CHAINS, "events": TEST_EVENTS},
    }))
}

pub fn test_required_namespaces_v2() -> ProposalNamespaces {
    from_json(json!({
        "eip155": {"methods": TEST_METHODS, "chains": TEST_CHAINS, "events": TEST_EVENTS},
        TEST_AVALANCHE_CHAIN: {"methods": TEST_METHODS, "events": TEST_EVENTS},
    }))
}

pub fn test_optional_namespaces() -> ProposalNamespaces {
    from_json(json!({
        "polkadot": {
            "methods": TEST_POLKADOT_METHODS,
            "chains": [TEST_POLKADOT_CHAIN],
            "events": TEST_EVENTS,
        },
    }))
}

pub fn test_namespaces() -> SessionNamespaces {
    from_json(json!({
        "eip155": {
            "chains": TEST_CHAINS,
            "methods": TEST_METHODS,
            "accounts": [
                account(TEST_ETHEREUM_CHAIN, TEST_ETHEREUM_ADDRESS),
                account(TEST_ARBITRUM_CHAIN, TEST_ETHEREUM_ADDRESS),
            ],
            "events": TEST_EVENTS,
        },
        "polkadot": {
            "chains": [TEST_POLKADOT_CHAIN],
            "methods": TEST_POLKADOT_METHODS,
            "accounts": [account(TEST_POLKADOT_CHAIN, TEST_POLKADOT_ADDRESS)],
            "events": TEST_EVENTS,
        },
    }))
}

pub fn test_namespaces_v2() -> SessionNamespaces {
    from_json(json!({
        "eip155": {
            "methods": TEST_METHODS,
            "accounts": [
                account(TEST_ETHEREUM_CHAIN, TEST_ETHEREUM_ADDRESS),
                account(TEST_AVALANCHE_CHAIN, TEST_ETHEREUM_ADDRESS),
                account(TEST_ARBITRUM_CHAIN, TEST_ETHEREUM_ADDRESS),
            ],
            "events": TEST_EVENTS,
        },
    }))
}

pub fn test_session_properties() -> Properties {
    from_json(json!({"expiry": "2022-12-24T17:07:31+00:00", "caip154-mandatory": "true"}))
}

pub fn test_session_properties_approve() -> Properties {
    from_json(json!({"expiry": "2022-12-24T17:07:31+00:00"}))
}

/// `TEST_REQUEST_PARAMS`: `(chainId, request)`.
pub fn test_request_params() -> (&'static str, SessionRequest) {
    (
        TEST_CHAINS[0],
        SessionRequest::new(TEST_METHODS[0], json!([])),
    )
}

/// `TEST_REQUEST_PARAMS_OPTIONAL_NAMESPACE`: `(chainId, request)`.
pub fn test_request_params_optional_namespace() -> (&'static str, SessionRequest) {
    (
        TEST_POLKADOT_CHAIN,
        SessionRequest::new(TEST_POLKADOT_METHODS[0], json!([])),
    )
}

/// `TEST_EMIT_PARAMS`: `(chainId, event)`.
pub fn test_emit_params() -> (&'static str, SessionEvent) {
    (TEST_CHAINS[0], SessionEvent::new(TEST_EVENTS[0], json!("")))
}

pub fn irn() -> Relay {
    Relay {
        protocol: "irn".into(),
        data: None,
    }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

pub fn options() -> SignClientOptions {
    SignClientOptions {
        expiry_check_interval: Duration::from_millis(100),
        ping_timeout: WAIT,
        ack_timeout: WAIT,
    }
}

/// A client on `server`, known to the relay as `client_id`.
pub async fn client(
    server: &RelayServer,
    client_id: &str,
    metadata: Metadata,
) -> (SignClient, SignEvents) {
    client_with(server, client_id, metadata, None).await
}

pub async fn client_with(
    server: &RelayServer,
    client_id: &str,
    metadata: Metadata,
    snapshot: Option<Snapshot>,
) -> (SignClient, SignEvents) {
    let mut builder = SignClient::builder(metadata)
        .connector(server.connector(client_id))
        .options(options());
    if let Some(snapshot) = snapshot {
        builder = builder.snapshot(snapshot);
    }
    builder.build().await.unwrap()
}

/// `initTwoClients`: A is the dapp (`client_a`), B the wallet (`client_b`).
pub struct Clients {
    pub a: SignClient,
    pub a_events: SignEvents,
    pub b: SignClient,
    pub b_events: SignEvents,
}

pub async fn init_two_clients(server: &RelayServer) -> Clients {
    let (a, a_events) = client(server, "client_a", test_app_metadata_a()).await;
    let (b, b_events) = client(server, "client_b", test_app_metadata_b()).await;
    Clients {
        a,
        a_events,
        b,
        b_events,
    }
}

/// Parameters of `testConnectMethod`.
pub struct TestConnectParams {
    pub required_namespaces: ProposalNamespaces,
    pub optional_namespaces: ProposalNamespaces,
    pub namespaces: SessionNamespaces,
    pub session_properties: Properties,
    pub pairing_topic: Option<Topic>,
}

impl Default for TestConnectParams {
    fn default() -> Self {
        Self {
            required_namespaces: BTreeMap::new(),
            optional_namespaces: test_optional_namespaces(),
            namespaces: test_namespaces(),
            session_properties: test_session_properties(),
            pairing_topic: None,
        }
    }
}

pub struct Connected {
    pub pairing_a: Pairing,
    pub pairing_b: Pairing,
    pub session_a: Session,
    pub session_b: Session,
}

/// Port of `testConnectMethod`: A connects, B pairs and approves, and both
/// sides end up with matching sessions and active pairings.
pub async fn test_connect(clients: &mut Clients, params: TestConnectParams) -> Connected {
    let Clients {
        a,
        a_events,
        b,
        b_events,
    } = clients;

    let connect = a
        .connect(ConnectParams {
            required_namespaces: params.required_namespaces.clone(),
            optional_namespaces: params.optional_namespaces.clone(),
            session_properties: Some(params.session_properties.clone()),
            pairing_topic: params.pairing_topic.clone(),
            ..Default::default()
        })
        .await
        .unwrap();

    match &params.pairing_topic {
        None => {
            let uri = connect.uri.clone().expect("a new pairing has a uri");
            let pairing_a = find_pairing(a, &uri.topic).expect("A stored the pairing");
            assert_eq!(pairing_a.topic, uri.topic);
            assert_eq!(pairing_a.relay.protocol, uri.relay_protocol);
            let pairing_b = b.pair(&uri.to_string()).await.unwrap();
            assert_eq!(pairing_b.topic, pairing_a.topic);
            assert_eq!(pairing_b.relay, pairing_a.relay);
        }
        Some(topic) => {
            assert!(connect.uri.is_none());
            assert_eq!(&connect.pairing_topic, topic);
        }
    }

    let proposal = wait_for(b_events, |e| match e {
        SignEvent::SessionProposal(p) => Some(p),
        _ => None,
    })
    .await;
    assert_eq!(proposal.required_namespaces, params.required_namespaces);
    assert_eq!(
        proposal.session_properties.as_ref(),
        Some(&params.session_properties)
    );

    let approved = b
        .approve_with(ApproveParams {
            id: proposal.id,
            namespaces: params.namespaces.clone(),
            session_properties: Some(test_session_properties_approve()),
            ..Default::default()
        })
        .await
        .unwrap();
    let session_a = connect.approval.await.unwrap();
    approved.acknowledged.await.unwrap();
    let session_b = b.session(&session_a.topic).expect("B has the session");
    wait_for(a_events, |e| match e {
        SignEvent::SessionConnect(s) if s.topic == session_a.topic => Some(()),
        _ => None,
    })
    .await;

    // topic
    assert_eq!(session_a.topic, session_b.topic);
    // relay
    assert_eq!(session_a.relay, irn());
    assert_eq!(session_a.relay, session_b.relay);
    // namespaces
    assert_eq!(session_a.namespaces, params.namespaces);
    assert_eq!(session_a.namespaces, session_b.namespaces);
    assert_eq!(
        session_a.session_properties,
        Some(test_session_properties_approve())
    );
    // participants
    assert_eq!(session_a.local, session_b.peer);
    assert_eq!(session_a.peer, session_b.local);
    // controller
    assert_eq!(session_a.controller, session_b.controller);
    assert_eq!(session_a.controller, session_a.peer.public_key);
    assert_eq!(session_b.controller, session_b.local.public_key);
    // metadata
    assert_eq!(&session_a.local.metadata, a.metadata());
    assert_eq!(&session_b.local.metadata, b.metadata());

    let pairing_a = find_pairing(a, &session_a.pairing_topic).expect("A keeps the pairing");
    let pairing_b = find_pairing(b, &session_b.pairing_topic).expect("B keeps the pairing");
    // topic
    assert_eq!(pairing_a.topic, pairing_b.topic);
    // relay
    assert_eq!(pairing_a.relay, irn());
    assert_eq!(pairing_a.relay, pairing_b.relay);
    // active
    assert!(pairing_a.active);
    assert!(pairing_b.active);
    // metadata
    assert_eq!(
        pairing_a.peer_metadata.as_ref(),
        Some(&session_a.peer.metadata)
    );
    assert_eq!(
        pairing_b.peer_metadata.as_ref(),
        Some(&session_b.peer.metadata)
    );

    Connected {
        pairing_a,
        pairing_b,
        session_a,
        session_b,
    }
}

/// `initTwoPairedClients`.
pub async fn init_two_paired_clients(server: &RelayServer) -> (Clients, Connected) {
    let mut clients = init_two_clients(server).await;
    let connected = test_connect(&mut clients, TestConnectParams::default()).await;
    (clients, connected)
}

pub fn find_pairing(client: &SignClient, topic: &Topic) -> Option<Pairing> {
    client.pairings().into_iter().find(|p| &p.topic == topic)
}

// ---------------------------------------------------------------------------
// Events and timing
// ---------------------------------------------------------------------------

fn is_connectivity(event: &SignEvent) -> bool {
    matches!(
        event,
        SignEvent::RelayConnected | SignEvent::RelayDisconnected
    )
}

/// The next event other than a relay connectivity change.
pub async fn next_event(events: &mut SignEvents) -> SignEvent {
    loop {
        let event = timeout(WAIT, events.recv())
            .await
            .expect("no event in time")
            .expect("event stream closed");
        if !is_connectivity(&event) {
            return event;
        }
    }
}

/// Skip events until `select` picks one.
pub async fn wait_for<T>(
    events: &mut SignEvents,
    mut select: impl FnMut(SignEvent) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("expected event did not arrive in time")
            .expect("event stream closed");
        if let Some(found) = select(event) {
            return found;
        }
    }
}

/// Fail if an event matching `unexpected` arrives within `within`.
pub async fn assert_no_event(
    events: &mut SignEvents,
    within: Duration,
    mut unexpected: impl FnMut(&SignEvent) -> bool,
) {
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.recv()).await {
        assert!(!unexpected(&event), "unexpected event {event:?}");
    }
}

/// Poll `condition` until it holds.
pub async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Introspection through snapshots (the JS tests read the keychain directly)
// ---------------------------------------------------------------------------

/// The client's persisted state as JSON.
pub fn state(client: &SignClient) -> Value {
    serde_json::to_value(client.snapshot()).unwrap()
}

/// The symmetric key the client holds for `topic`, if any.
pub fn sym_key(client: &SignClient, topic: &Topic) -> Option<SymKey> {
    state(client)["symKeys"][topic.as_str()]
        .as_str()
        .map(|hex| SymKey::from_hex(hex).unwrap())
}

/// Public keys of the X25519 key pairs the client holds.
pub fn key_pairs(client: &SignClient) -> Vec<String> {
    state(client)["keyPairs"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// RawPeer: a hand-driven protocol peer
// ---------------------------------------------------------------------------

pub const RAW_OPTS: PublishOptions = PublishOptions {
    ttl: 300,
    tag: 0,
    prompt: false,
};

/// A relay client that encrypts and decrypts Sign API payloads by hand.
pub struct RawPeer {
    pub relay: RelayClient,
    events: mpsc::UnboundedReceiver<RelayEvent>,
    keys: BTreeMap<Topic, SymKey>,
}

impl RawPeer {
    pub async fn connect(server: &RelayServer, client_id: &str) -> Self {
        let (relay, events) =
            RelayClient::connect(server.connector(client_id), RelayClientOptions::default())
                .await
                .unwrap();
        RawPeer {
            relay,
            events,
            keys: BTreeMap::new(),
        }
    }

    /// Remember `key` for `topic` (needed to publish and to decrypt).
    pub fn add_key(&mut self, topic: &Topic, key: SymKey) {
        self.keys.insert(topic.clone(), key);
    }

    pub async fn subscribe(&mut self, topic: &Topic, key: SymKey) {
        self.add_key(topic, key);
        self.relay.subscribe(topic).await.unwrap();
    }

    /// Encrypt `payload` with the key of `topic` and publish it.
    pub async fn publish(&self, topic: &Topic, payload: &impl Serialize) {
        let key = self.keys.get(topic).expect("key for topic");
        let message = key.encrypt(&serde_json::to_vec(payload).unwrap());
        self.relay.publish(topic, &message, RAW_OPTS).await.unwrap();
    }

    pub async fn request(&self, topic: &Topic, id: u64, method: &str, params: Value) {
        self.publish(topic, &Request::with_id(id, method, params))
            .await;
    }

    pub async fn respond(&self, topic: &Topic, response: Response) {
        self.publish(topic, &response).await;
    }

    /// The next decrypted payload on any topic this peer has a key for.
    pub async fn next(&mut self) -> (Topic, Payload) {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let event = tokio::time::timeout_at(deadline, self.events.recv())
                .await
                .expect("no message in time")
                .expect("relay events closed");
            let RelayEvent::Message(data) = event else {
                continue;
            };
            let Some(key) = self.keys.get(&data.topic) else {
                continue;
            };
            let plaintext = key.decrypt(&data.message).expect("decryptable message");
            let payload = Payload::parse(std::str::from_utf8(&plaintext).unwrap()).unwrap();
            return (data.topic, payload);
        }
    }

    /// The next decrypted payload on `topic`.
    pub async fn next_on(&mut self, topic: &Topic) -> Payload {
        loop {
            let (t, payload) = self.next().await;
            if &t == topic {
                return payload;
            }
        }
    }

    /// The next request on `topic` with `method`.
    pub async fn next_request(&mut self, topic: &Topic, method: &str) -> Request {
        loop {
            if let Payload::Request(req) = self.next_on(topic).await
                && req.method == method
            {
                return req;
            }
        }
    }

    /// The next response on `topic`.
    pub async fn next_response(&mut self, topic: &Topic) -> Response {
        loop {
            if let Payload::Response(res) = self.next_on(topic).await {
                return res;
            }
        }
    }

    /// Fail if a message arrives on `topic` within `within`.
    pub async fn assert_quiet(&mut self, topic: &Topic, within: Duration) {
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(Some(event)) = tokio::time::timeout_at(deadline, self.events.recv()).await {
            if let RelayEvent::Message(data) = event {
                assert_ne!(&data.topic, topic, "unexpected message on {topic}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tap: records what a client sends to the relay
// ---------------------------------------------------------------------------

struct TapInner {
    server: RelayServer,
    client_id: String,
    frames: Mutex<Vec<Value>>,
    kill: Mutex<Option<oneshot::Sender<()>>>,
}

/// A [`Connector`] to an in-process relay that records every frame the
/// client sends and can drop the connection on demand.
#[derive(Clone)]
pub struct Tap(Arc<TapInner>);

impl Tap {
    pub fn new(server: &RelayServer, client_id: &str) -> Self {
        Tap(Arc::new(TapInner {
            server: server.clone(),
            client_id: client_id.to_owned(),
            frames: Mutex::new(Vec::new()),
            kill: Mutex::new(None),
        }))
    }

    /// Every JSON frame sent so far.
    pub fn frames(&self) -> Vec<Value> {
        self.0.frames.lock().unwrap().clone()
    }

    /// Requests with `method` sent so far.
    pub fn requests(&self, method: &str) -> Vec<Value> {
        self.frames()
            .into_iter()
            .filter(|f| f["method"] == method)
            .collect()
    }

    /// `irn_publish` params sent so far.
    pub fn published(&self) -> Vec<PublishParams> {
        self.requests("irn_publish")
            .into_iter()
            .map(|f| serde_json::from_value(f["params"].clone()).unwrap())
            .collect()
    }

    pub fn clear(&self) {
        self.0.frames.lock().unwrap().clear();
    }

    /// Cut the current connection, as if the network dropped it.
    pub fn drop_connection(&self) {
        if let Some(kill) = self.0.kill.lock().unwrap().take() {
            let _ = kill.send(());
        }
    }
}

impl Connector for Tap {
    fn connect(&self) -> BoxFuture<wallet_connect::Result<Connection>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let Connection {
                sender: to_server,
                receiver: mut from_server,
            } = inner.server.accept(inner.client_id.clone());
            let (client_end, proxy_end) = Connection::pair();
            let Connection {
                sender: to_client,
                receiver: mut from_client,
            } = proxy_end;
            let (kill, mut killed) = oneshot::channel();
            *inner.kill.lock().unwrap() = Some(kill);
            let recorder = inner.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut killed => break,
                        frame = from_client.recv() => {
                            let Some(text) = frame else { break };
                            if let Ok(value) = serde_json::from_str(&text) {
                                recorder.frames.lock().unwrap().push(value);
                            }
                            if to_server.send(text).is_err() {
                                break;
                            }
                        }
                        frame = from_server.recv() => {
                            let Some(text) = frame else { break };
                            if to_client.send(text).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            Ok(client_end)
        })
    }
}

/// A client on `server` whose relay traffic is recorded by the returned tap.
pub async fn tapped_client(
    server: &RelayServer,
    client_id: &str,
    metadata: Metadata,
) -> (SignClient, SignEvents, Tap) {
    let tap = Tap::new(server, client_id);
    let (client, events) = SignClient::builder(metadata)
        .connector(tap.clone())
        .options(options())
        .build()
        .await
        .unwrap();
    (client, events, tap)
}

/// A connector whose connections the test drives by hand: every connect
/// hands the test the relay's end of a fresh in-memory connection.
pub fn manual_connector() -> (impl Connector, mpsc::UnboundedReceiver<Connection>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let connector = move || {
        let (client_end, relay_end) = Connection::pair();
        let _ = tx.send(relay_end);
        async move { Ok(client_end) }
    };
    (connector, rx)
}
