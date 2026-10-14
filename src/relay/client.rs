//! JSON-RPC client for the relay.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot, watch};

use super::rpc::{self, SubscriptionData, SubscriptionParams, methods};
use super::transport::{Connection, Connector};
use crate::crypto::Topic;
use crate::error::{Error, Result};
use crate::rpc::{ErrorObject, JSONRPC_VERSION, Payload, Request};

/// Largest batch the relay accepts in `irn_batchSubscribe`.
const BATCH_LIMIT: usize = 500;

/// Tunables for [`RelayClient`].
#[derive(Debug, Clone)]
pub struct RelayClientOptions {
    /// How long to wait for the relay to answer a request.
    pub request_timeout: Duration,
    /// Reconnect (and resubscribe) automatically when the connection drops.
    pub reconnect: bool,
    /// Cap of the exponential reconnect backoff.
    pub max_backoff: Duration,
}

impl Default for RelayClientOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            reconnect: true,
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// Options of a single publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishOptions {
    /// Seconds the relay keeps the message for offline subscribers.
    pub ttl: u64,
    /// Message tag, see [`crate::sign::rpc`] for the Sign API tags.
    pub tag: u32,
    /// Ask the relay to send a push notification to the receiver.
    pub prompt: bool,
}

/// Something that happened on the relay connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    /// A message arrived on a subscribed topic (already acknowledged).
    Message(SubscriptionData),
    /// The connection was (re)established. After a reconnect all known
    /// topics are resubscribed automatically.
    Connected,
    /// The connection dropped; in-flight requests failed with
    /// [`Error::Disconnected`].
    Disconnected,
}

/// Why a relay request failed, and whether the relay may have acted on it.
#[derive(Debug)]
pub(crate) enum RequestError {
    /// The request never reached the relay, or the relay refused it.
    Failed(Error),
    /// The request went out but no answer came back: it timed out, or the
    /// connection dropped or the client closed first. The relay may have
    /// processed it.
    Unconfirmed(Error),
}

impl From<RequestError> for Error {
    fn from(e: RequestError) -> Self {
        match e {
            RequestError::Failed(e) | RequestError::Unconfirmed(e) => e,
        }
    }
}

type Waiter = oneshot::Sender<Result<Value>>;

#[derive(Default)]
struct State {
    outbound: Option<mpsc::UnboundedSender<String>>,
    pending: HashMap<u64, Waiter>,
    /// topic → subscription id
    subscriptions: HashMap<Topic, String>,
    closed: bool,
}

struct Inner {
    connector: Arc<dyn Connector>,
    options: RelayClientOptions,
    state: Mutex<State>,
    events: mpsc::UnboundedSender<RelayEvent>,
    shutdown: watch::Sender<bool>,
}

/// A connection to a relay: publish to topics, subscribe to topics, receive
/// messages. Cheap to clone; all clones share the connection.
#[derive(Clone)]
pub struct RelayClient {
    inner: Arc<Inner>,
}

impl RelayClient {
    /// Connect using `connector` and start the background driver. Incoming
    /// messages and connection changes are delivered on the returned
    /// receiver.
    pub async fn connect(
        connector: impl Connector,
        options: RelayClientOptions,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayEvent>)> {
        Self::connect_shared(Arc::new(connector), options).await
    }

    /// [`RelayClient::connect`] with an already shared connector.
    pub async fn connect_shared(
        connector: Arc<dyn Connector>,
        options: RelayClientOptions,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayEvent>)> {
        let connection = connector.connect().await?;
        let (events, events_rx) = mpsc::unbounded_channel();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let inner = Arc::new(Inner {
            connector,
            options,
            state: Mutex::new(State::default()),
            events,
            shutdown,
        });
        inner.attach(connection.sender.clone());
        tokio::spawn(drive(Arc::downgrade(&inner), connection, shutdown_rx));
        Ok((RelayClient { inner }, events_rx))
    }

    pub fn is_connected(&self) -> bool {
        self.inner.state.lock().unwrap().outbound.is_some()
    }

    /// Topics this client is subscribed to.
    pub fn subscriptions(&self) -> Vec<Topic> {
        self.inner
            .state
            .lock()
            .unwrap()
            .subscriptions
            .keys()
            .cloned()
            .collect()
    }

    /// Send a raw JSON-RPC request and wait for its result.
    pub async fn request<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let result = self.call(method, serde_json::to_value(params)?).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// [`RelayClient::request`], telling apart the failures after which the
    /// relay may have processed the request anyway.
    async fn call(&self, method: &str, params: Value) -> Result<Value, RequestError> {
        let request = Request::new(method, params);
        let id = request.id;
        let text = serde_json::to_string(&request).map_err(|e| RequestError::Failed(e.into()))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.inner.state.lock().unwrap();
            if state.closed {
                return Err(RequestError::Failed(Error::Closed));
            }
            let outbound = state
                .outbound
                .clone()
                .ok_or(RequestError::Failed(Error::Disconnected))?;
            state.pending.insert(id, tx);
            if outbound.send(text).is_err() {
                state.pending.remove(&id);
                return Err(RequestError::Failed(Error::Disconnected));
            }
        }
        tracing::trace!(id, method, "relay request");
        match tokio::time::timeout(self.inner.options.request_timeout, rx).await {
            Ok(Ok(Ok(result))) => Ok(result),
            Ok(Ok(Err(e @ Error::Relay(_)))) => Err(RequestError::Failed(e)),
            // The connection dropped or the client closed.
            Ok(Ok(Err(e))) => Err(RequestError::Unconfirmed(e)),
            Ok(Err(_)) => Err(RequestError::Unconfirmed(Error::Disconnected)),
            Err(_) => {
                self.inner.state.lock().unwrap().pending.remove(&id);
                Err(RequestError::Unconfirmed(Error::Timeout))
            }
        }
    }

    /// Publish an (already encrypted) message to `topic`.
    pub async fn publish(&self, topic: &Topic, message: &str, opts: PublishOptions) -> Result<()> {
        Ok(self.try_publish(topic, message, opts).await?)
    }

    /// [`RelayClient::publish`], telling apart the failures after which the
    /// relay may have accepted the message anyway.
    pub(crate) async fn try_publish(
        &self,
        topic: &Topic,
        message: &str,
        opts: PublishOptions,
    ) -> Result<(), RequestError> {
        let params = rpc::PublishParams {
            topic: topic.clone(),
            message: message.to_owned(),
            ttl: opts.ttl,
            tag: opts.tag,
            prompt: opts.prompt.then_some(true),
            attestation: None,
        };
        let params = serde_json::to_value(params).map_err(|e| RequestError::Failed(e.into()))?;
        self.call(methods::PUBLISH, params).await.map(drop)
    }

    /// Subscribe to `topic`. Messages the relay holds for it are delivered
    /// right away.
    pub async fn subscribe(&self, topic: &Topic) -> Result<String> {
        let id: String = self
            .request(
                methods::SUBSCRIBE,
                rpc::SubscribeParams {
                    topic: topic.clone(),
                },
            )
            .await?;
        self.record_subscription(topic.clone(), id.clone());
        Ok(id)
    }

    /// Subscribe to many topics at once.
    pub async fn batch_subscribe(&self, topics: &[Topic]) -> Result<()> {
        for chunk in topics.chunks(BATCH_LIMIT) {
            let result: Value = self
                .request(
                    methods::BATCH_SUBSCRIBE,
                    rpc::BatchSubscribeParams {
                        topics: chunk.to_vec(),
                    },
                )
                .await?;
            let ids: Vec<String> = serde_json::from_value(result).unwrap_or_default();
            for (i, topic) in chunk.iter().enumerate() {
                self.record_subscription(topic.clone(), ids.get(i).cloned().unwrap_or_default());
            }
        }
        Ok(())
    }

    /// Unsubscribe from `topic`. Unknown topics are ignored.
    pub async fn unsubscribe(&self, topic: &Topic) -> Result<()> {
        let Some(id) = self.inner.state.lock().unwrap().subscriptions.remove(topic) else {
            return Ok(());
        };
        let _: Value = self
            .request(
                methods::UNSUBSCRIBE,
                rpc::UnsubscribeParams {
                    topic: topic.clone(),
                    id,
                },
            )
            .await?;
        Ok(())
    }

    /// Pull the messages the relay holds for `topic` instead of waiting for
    /// pushes.
    pub async fn fetch_messages(&self, topic: &Topic) -> Result<rpc::FetchMessagesResult> {
        self.request(
            methods::FETCH_MESSAGES,
            rpc::FetchMessagesParams {
                topic: topic.clone(),
            },
        )
        .await
    }

    pub async fn batch_fetch_messages(&self, topics: &[Topic]) -> Result<rpc::FetchMessagesResult> {
        self.request(
            methods::BATCH_FETCH_MESSAGES,
            rpc::BatchFetchMessagesParams {
                topics: topics.to_vec(),
            },
        )
        .await
    }

    /// `wc_proposeSession`: publish a proposal and subscribe to its pairing
    /// topic in one round trip.
    pub async fn propose_session(&self, params: rpc::ProposeSessionParams) -> Result<()> {
        let topic = params.pairing_topic.clone();
        let _: Value = self.request(methods::PROPOSE_SESSION, params).await?;
        self.record_subscription(topic, String::new());
        Ok(())
    }

    /// `wc_approveSession`: publish the proposal response and the settle
    /// request and subscribe to the session topic in one round trip.
    pub async fn approve_session(&self, params: rpc::ApproveSessionParams) -> Result<()> {
        let topic = params.session_topic.clone();
        let _: Value = self.request(methods::APPROVE_SESSION, params).await?;
        self.record_subscription(topic, String::new());
        Ok(())
    }

    /// Close the connection and stop reconnecting.
    pub fn close(&self) {
        let mut state = self.inner.state.lock().unwrap();
        state.closed = true;
        state.outbound = None;
        for (_, waiter) in state.pending.drain() {
            let _ = waiter.send(Err(Error::Closed));
        }
        drop(state);
        let _ = self.inner.shutdown.send(true);
    }

    fn record_subscription(&self, topic: Topic, id: String) {
        self.inner
            .state
            .lock()
            .unwrap()
            .subscriptions
            .insert(topic, id);
    }
}

impl Inner {
    fn attach(&self, outbound: mpsc::UnboundedSender<String>) {
        self.state.lock().unwrap().outbound = Some(outbound);
        let _ = self.events.send(RelayEvent::Connected);
    }

    fn detach(&self) {
        let mut state = self.state.lock().unwrap();
        state.outbound = None;
        for (_, waiter) in state.pending.drain() {
            let _ = waiter.send(Err(Error::Disconnected));
        }
        drop(state);
        let _ = self.events.send(RelayEvent::Disconnected);
    }

    fn handle_incoming(&self, text: &str, outbound: &mpsc::UnboundedSender<String>) {
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("relay sent invalid json: {e}");
                return;
            }
        };

        if let Some(method) = value.get("method").and_then(Value::as_str) {
            let id = value.get("id").cloned().unwrap_or(Value::Null);
            let reply = |outcome: std::result::Result<Value, ErrorObject>| {
                let mut msg = json!({ "id": id, "jsonrpc": JSONRPC_VERSION });
                match outcome {
                    Ok(result) => msg["result"] = result,
                    Err(error) => msg["error"] = serde_json::to_value(error).unwrap_or_default(),
                }
                let _ = outbound.send(msg.to_string());
            };
            if method != methods::SUBSCRIPTION && !method.ends_with("_subscription") {
                reply(Err(ErrorObject::new(
                    ErrorObject::METHOD_NOT_FOUND,
                    format!("unsupported method {method}"),
                )));
                return;
            }
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            match serde_json::from_value::<SubscriptionParams>(params) {
                Ok(params) => {
                    // Acknowledge first so the relay stops retrying, exactly
                    // like the reference SDK.
                    reply(Ok(Value::Bool(true)));
                    let _ = self.events.send(RelayEvent::Message(params.data));
                }
                Err(e) => reply(Err(ErrorObject::new(
                    ErrorObject::INVALID_PARAMS,
                    e.to_string(),
                ))),
            }
            return;
        }

        match Payload::from_value(value) {
            Ok(Payload::Response(response)) => {
                let waiter = self.state.lock().unwrap().pending.remove(&response.id);
                match waiter {
                    Some(waiter) => {
                        let _ = waiter.send(response.outcome.map_err(Error::Relay));
                    }
                    None => tracing::debug!(id = response.id, "response to unknown relay request"),
                }
            }
            Ok(Payload::Request(_)) => unreachable!("requests are handled above"),
            Err(e) => tracing::warn!("unrecognised relay payload: {e}"),
        }
    }
}

/// Background task: pumps the current connection, reconnects with backoff,
/// resubscribes. Holds only a weak reference so that dropping every
/// [`RelayClient`] stops it.
async fn drive(inner: Weak<Inner>, first: Connection, mut shutdown: watch::Receiver<bool>) {
    let mut connection = first;
    let mut reconnected = false;
    loop {
        let Connection {
            sender,
            mut receiver,
        } = connection;

        if reconnected {
            let Some(strong) = inner.upgrade() else {
                return;
            };
            strong.attach(sender.clone());
            let client = RelayClient { inner: strong };
            tokio::spawn(async move {
                let topics = client.subscriptions();
                if !topics.is_empty()
                    && let Err(e) = client.batch_subscribe(&topics).await
                {
                    tracing::warn!("resubscribing after reconnect failed: {e}");
                }
            });
        }

        loop {
            tokio::select! {
                frame = receiver.recv() => {
                    let Some(text) = frame else { break };
                    let Some(strong) = inner.upgrade() else { return };
                    strong.handle_incoming(&text, &sender);
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }

        let (connector, options) = {
            let Some(strong) = inner.upgrade() else {
                return;
            };
            strong.detach();
            if strong.state.lock().unwrap().closed || !strong.options.reconnect {
                return;
            }
            (strong.connector.clone(), strong.options.clone())
        };
        tracing::info!("relay connection lost, reconnecting");

        let mut delay = Duration::from_millis(250);
        connection = loop {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
            if inner.strong_count() == 0 {
                return;
            }
            match connector.connect().await {
                Ok(connection) => break connection,
                Err(e) => {
                    tracing::warn!("relay reconnect failed: {e}");
                    delay = (delay * 2).min(options.max_backoff);
                }
            }
        };
        reconnected = true;
    }
}
