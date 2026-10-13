//! A self-contained relay server.
//!
//! It implements the subset of the relay API that WalletConnect clients use,
//! with the relay's store-and-forward semantics: published messages are kept
//! for their TTL and pushed to every subscriber that has not acknowledged them
//! yet, including subscribers that only show up later. It's meant for tests,
//! local development and private deployments, not as a replacement for the
//! production relay network (no rate limiting, persistence or clustering).
//!
//! Connections are attached either in-process ([`RelayServer::accept`],
//! [`RelayServer::connector`]) or over WebSocket ([`RelayServer::listen`],
//! with the `ws` feature).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::rpc::{self, MAX_TTL, MIN_TTL, SubscriptionData, SubscriptionParams, methods};
use super::transport::{BoxFuture, Connection, Connector};
use crate::crypto::{Topic, sha256_hex};
use crate::error::Result;
use crate::rpc::{ErrorObject, JSONRPC_VERSION, parse_id, payload_id};
use crate::time::now_ms;

/// Tags the relay uses for messages it publishes on behalf of
/// `wc_proposeSession` / `wc_approveSession`.
const TAG_SESSION_PROPOSE: u32 = 1100;
const TAG_SESSION_PROPOSE_RESPONSE: u32 = 1101;
const TAG_SESSION_SETTLE: u32 = 1102;

/// A relay. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct RelayServer {
    state: Arc<Mutex<ServerState>>,
}

#[derive(Default)]
struct ServerState {
    next_conn: u64,
    conns: HashMap<u64, Conn>,
    topics: HashMap<Topic, TopicState>,
    /// client id → ids of the messages it acknowledged
    acked: HashMap<String, HashSet<String>>,
}

struct Conn {
    client_id: String,
    tx: mpsc::UnboundedSender<String>,
    /// topic → subscription id
    subscriptions: HashMap<Topic, String>,
    /// push request id → message id, until the client acknowledges it
    in_flight: HashMap<u64, String>,
    /// messages pushed on this connection (acknowledged or not)
    delivered: HashSet<String>,
}

#[derive(Default)]
struct TopicState {
    messages: Vec<Stored>,
    subscribers: HashSet<u64>,
}

struct Stored {
    /// sha256 of the message
    id: String,
    data: SubscriptionData,
    expires_at_ms: u64,
    publisher: String,
}

type RpcResult = std::result::Result<Value, ErrorObject>;

impl RelayServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a client known as `client_id` and return its end of the
    /// connection.
    pub fn accept(&self, client_id: impl Into<String>) -> Connection {
        let (client_end, server_end) = Connection::pair();
        let Connection {
            sender,
            mut receiver,
        } = server_end;
        let conn_id = {
            let mut state = self.state.lock().unwrap();
            state.next_conn += 1;
            let id = state.next_conn;
            state.conns.insert(
                id,
                Conn {
                    client_id: client_id.into(),
                    tx: sender,
                    subscriptions: HashMap::new(),
                    in_flight: HashMap::new(),
                    delivered: HashSet::new(),
                },
            );
            id
        };
        let server = self.clone();
        tokio::spawn(async move {
            while let Some(text) = receiver.recv().await {
                if !server.state.lock().unwrap().handle(conn_id, &text) {
                    break;
                }
            }
            server.state.lock().unwrap().remove_conn(conn_id);
        });
        client_end
    }

    /// A [`Connector`] that attaches in-process connections as `client_id`.
    pub fn connector(&self, client_id: impl Into<String>) -> ServerConnector {
        ServerConnector {
            server: self.clone(),
            client_id: client_id.into(),
        }
    }

    /// Drop every live connection, as if the relay restarted. Stored
    /// messages survive.
    pub fn disconnect_all(&self) {
        let mut state = self.state.lock().unwrap();
        let ids: Vec<u64> = state.conns.keys().copied().collect();
        for id in ids {
            state.remove_conn(id);
        }
    }

    /// Number of live connections.
    pub fn connection_count(&self) -> usize {
        self.state.lock().unwrap().conns.len()
    }

    /// Number of unexpired messages stored for `topic`.
    pub fn stored_message_count(&self, topic: &Topic) -> usize {
        let now = now_ms();
        self.state.lock().unwrap().topics.get(topic).map_or(0, |t| {
            t.messages.iter().filter(|m| m.expires_at_ms > now).count()
        })
    }
}

/// See [`RelayServer::connector`].
#[derive(Clone)]
pub struct ServerConnector {
    server: RelayServer,
    client_id: String,
}

impl Connector for ServerConnector {
    fn connect(&self) -> BoxFuture<Result<Connection>> {
        let connection = self.server.accept(self.client_id.clone());
        Box::pin(async move { Ok(connection) })
    }
}

fn params<T: DeserializeOwned>(value: Value) -> std::result::Result<T, ErrorObject> {
    serde_json::from_value(value)
        .map_err(|e| ErrorObject::new(ErrorObject::INVALID_PARAMS, format!("invalid params: {e}")))
}

impl ServerState {
    /// Handle one frame from `conn_id`. Returns false if the connection is
    /// gone.
    fn handle(&mut self, conn_id: u64, text: &str) -> bool {
        if !self.conns.contains_key(&conn_id) {
            return false;
        }
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                self.reply(
                    conn_id,
                    Value::Null,
                    Err(ErrorObject::new(ErrorObject::PARSE_ERROR, e.to_string())),
                );
                return true;
            }
        };
        let id = value.get("id").cloned().unwrap_or(Value::Null);

        let Some(method) = value.get("method").and_then(Value::as_str) else {
            // A response: the acknowledgement of a push.
            if let Some(push_id) = parse_id(&id) {
                self.on_ack(conn_id, push_id);
            }
            return true;
        };
        let params_value = value.get("params").cloned().unwrap_or(Value::Null);
        // Topics whose stored messages should be flushed to this connection
        // once the response has been sent.
        let mut flush = Vec::new();
        let result = self.dispatch(conn_id, method, params_value, &mut flush);
        match &result {
            Ok(_) => tracing::debug!(conn_id, method, "relay request served"),
            Err(e) => tracing::debug!(conn_id, method, "relay request failed: {e}"),
        }
        self.reply(conn_id, id, result);
        for topic in flush {
            self.deliver(conn_id, &topic);
        }
        true
    }

    fn dispatch(
        &mut self,
        conn_id: u64,
        method: &str,
        p: Value,
        flush: &mut Vec<Topic>,
    ) -> RpcResult {
        match method {
            methods::PUBLISH => {
                let p: rpc::PublishParams = params(p)?;
                self.publish(conn_id, p)
            }
            methods::BATCH_PUBLISH => {
                let p: rpc::BatchPublishParams = params(p)?;
                for message in p.messages {
                    self.publish(conn_id, message)?;
                }
                Ok(Value::Bool(true))
            }
            methods::SUBSCRIBE => {
                let p: rpc::SubscribeParams = params(p)?;
                let id = self.subscribe(conn_id, &p.topic);
                flush.push(p.topic);
                Ok(Value::String(id))
            }
            methods::BATCH_SUBSCRIBE => {
                let p: rpc::BatchSubscribeParams = params(p)?;
                let ids: Vec<Value> = p
                    .topics
                    .iter()
                    .map(|t| Value::String(self.subscribe(conn_id, t)))
                    .collect();
                flush.extend(p.topics);
                Ok(Value::Array(ids))
            }
            methods::UNSUBSCRIBE => {
                let p: rpc::UnsubscribeParams = params(p)?;
                self.unsubscribe(conn_id, &p.topic);
                Ok(Value::Bool(true))
            }
            methods::BATCH_UNSUBSCRIBE => {
                let p: rpc::BatchUnsubscribeParams = params(p)?;
                for s in p.subscriptions {
                    self.unsubscribe(conn_id, &s.topic);
                }
                Ok(Value::Bool(true))
            }
            methods::FETCH_MESSAGES => {
                let p: rpc::FetchMessagesParams = params(p)?;
                Ok(self.fetch(conn_id, &[p.topic]))
            }
            methods::BATCH_FETCH_MESSAGES => {
                let p: rpc::BatchFetchMessagesParams = params(p)?;
                Ok(self.fetch(conn_id, &p.topics))
            }
            methods::PROPOSE_SESSION => {
                let p: rpc::ProposeSessionParams = params(p)?;
                self.subscribe(conn_id, &p.pairing_topic);
                flush.push(p.pairing_topic.clone());
                self.publish(
                    conn_id,
                    rpc::PublishParams {
                        topic: p.pairing_topic,
                        message: p.session_proposal,
                        ttl: p.ttl,
                        tag: p.tag.unwrap_or(TAG_SESSION_PROPOSE),
                        prompt: p.prompt,
                        attestation: p.attestation,
                    },
                )
            }
            methods::APPROVE_SESSION => {
                let p: rpc::ApproveSessionParams = params(p)?;
                self.subscribe(conn_id, &p.session_topic);
                flush.push(p.session_topic.clone());
                self.publish(
                    conn_id,
                    rpc::PublishParams {
                        topic: p.pairing_topic,
                        message: p.session_proposal_response,
                        ttl: p.ttl,
                        tag: TAG_SESSION_PROPOSE_RESPONSE,
                        prompt: None,
                        attestation: None,
                    },
                )?;
                self.publish(
                    conn_id,
                    rpc::PublishParams {
                        topic: p.session_topic,
                        message: p.session_settlement_request,
                        ttl: p.ttl,
                        tag: TAG_SESSION_SETTLE,
                        prompt: None,
                        attestation: None,
                    },
                )
            }
            other => Err(ErrorObject::new(
                ErrorObject::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        }
    }

    fn reply(&self, conn_id: u64, id: Value, result: RpcResult) {
        let Some(conn) = self.conns.get(&conn_id) else {
            return;
        };
        let mut msg = json!({ "id": id, "jsonrpc": JSONRPC_VERSION });
        match result {
            Ok(result) => msg["result"] = result,
            Err(error) => msg["error"] = serde_json::to_value(error).unwrap_or_default(),
        }
        let _ = conn.tx.send(msg.to_string());
    }

    fn publish(&mut self, conn_id: u64, p: rpc::PublishParams) -> RpcResult {
        if p.message.is_empty() {
            return Err(ErrorObject::new(
                ErrorObject::INVALID_PARAMS,
                "empty message",
            ));
        }
        let publisher = self.conns[&conn_id].client_id.clone();
        let now = now_ms();
        let ttl = p.ttl.clamp(MIN_TTL, MAX_TTL);
        let id = sha256_hex(p.message.as_bytes());
        let topic = self.topics.entry(p.topic.clone()).or_default();
        topic.messages.retain(|m| m.expires_at_ms > now);
        // Publishing is idempotent: a retried publish is not a new message.
        if !topic.messages.iter().any(|m| m.id == id) {
            topic.messages.push(Stored {
                id,
                data: SubscriptionData {
                    topic: p.topic.clone(),
                    message: p.message,
                    published_at: now,
                    tag: p.tag,
                    attestation: p.attestation,
                },
                expires_at_ms: now + ttl * 1000,
                publisher,
            });
            let subscribers: Vec<u64> = topic.subscribers.iter().copied().collect();
            for subscriber in subscribers {
                self.deliver(subscriber, &p.topic);
            }
        }
        Ok(Value::Bool(true))
    }

    fn subscribe(&mut self, conn_id: u64, topic: &Topic) -> String {
        let conn = self.conns.get_mut(&conn_id).expect("live connection");
        let id = sha256_hex(format!("{topic}{}", conn.client_id).as_bytes());
        conn.subscriptions.insert(topic.clone(), id.clone());
        self.topics
            .entry(topic.clone())
            .or_default()
            .subscribers
            .insert(conn_id);
        id
    }

    fn unsubscribe(&mut self, conn_id: u64, topic: &Topic) {
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            conn.subscriptions.remove(topic);
        }
        if let Some(t) = self.topics.get_mut(topic) {
            t.subscribers.remove(&conn_id);
        }
    }

    /// Messages on `topics` that `conn_id`'s client has neither published
    /// nor acknowledged.
    fn pending_for<'a>(
        &'a self,
        client_id: &'a str,
        topic: &Topic,
    ) -> impl Iterator<Item = &'a Stored> + 'a {
        let now = now_ms();
        let acked = self.acked.get(client_id);
        self.topics
            .get(topic)
            .into_iter()
            .flat_map(|t| t.messages.iter())
            .filter(move |m| {
                m.expires_at_ms > now
                    && m.publisher != client_id
                    && !acked.is_some_and(|a| a.contains(&m.id))
            })
    }

    /// Push every pending message of `topic` to `conn_id` that hasn't been
    /// pushed on this connection yet.
    fn deliver(&mut self, conn_id: u64, topic: &Topic) {
        let Some(conn) = self.conns.get(&conn_id) else {
            return;
        };
        let Some(sub_id) = conn.subscriptions.get(topic).cloned() else {
            return;
        };
        let pushes: Vec<(String, SubscriptionData)> = self
            .pending_for(&conn.client_id, topic)
            .filter(|m| !conn.delivered.contains(&m.id))
            .map(|m| (m.id.clone(), m.data.clone()))
            .collect();
        let conn = self.conns.get_mut(&conn_id).expect("checked above");
        for (msg_id, data) in pushes {
            let push_id = payload_id();
            let push = json!({
                "id": push_id,
                "jsonrpc": JSONRPC_VERSION,
                "method": methods::SUBSCRIPTION,
                "params": SubscriptionParams { id: sub_id.clone(), data },
            });
            if conn.tx.send(push.to_string()).is_err() {
                return;
            }
            conn.delivered.insert(msg_id.clone());
            conn.in_flight.insert(push_id, msg_id);
        }
    }

    fn fetch(&mut self, conn_id: u64, topics: &[Topic]) -> Value {
        let client_id = self.conns[&conn_id].client_id.clone();
        let mut messages = Vec::new();
        let mut ids = Vec::new();
        for topic in topics {
            for m in self.pending_for(&client_id, topic) {
                ids.push(m.id.clone());
                messages.push(m.data.clone());
            }
        }
        // Fetched messages count as delivered and acknowledged.
        self.acked
            .entry(client_id)
            .or_default()
            .extend(ids.iter().cloned());
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            conn.delivered.extend(ids);
        }
        serde_json::to_value(rpc::FetchMessagesResult {
            messages,
            has_more: false,
        })
        .expect("serializable")
    }

    fn on_ack(&mut self, conn_id: u64, push_id: u64) {
        let Some(conn) = self.conns.get_mut(&conn_id) else {
            return;
        };
        if let Some(msg_id) = conn.in_flight.remove(&push_id) {
            let client_id = conn.client_id.clone();
            self.acked.entry(client_id).or_default().insert(msg_id);
        }
    }

    fn remove_conn(&mut self, conn_id: u64) {
        if let Some(conn) = self.conns.remove(&conn_id) {
            for topic in conn.subscriptions.keys() {
                if let Some(t) = self.topics.get_mut(topic) {
                    t.subscribers.remove(&conn_id);
                }
            }
        }
    }
}
