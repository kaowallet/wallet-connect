//! JSON-RPC 2.0 framing shared by the relay protocol and the peer-to-peer
//! Sign protocol.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::time::now_ms;

pub const JSONRPC_VERSION: &str = "2.0";

/// Request ids are `unix_ms * 1000 + 3 random digits`, exactly like the
/// reference SDK's `payloadId()`. They stay below 2^53 so JavaScript peers
/// can represent them losslessly, and they are made strictly increasing
/// within the process so two requests never collide.
pub fn payload_id() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let mut rnd = [0u8; 2];
    getrandom::fill(&mut rnd).expect("OS random number generator failed");
    let candidate = now_ms() * 1000 + u64::from(u16::from_le_bytes(rnd)) % 1000;
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let next = candidate.max(last + 1);
        match LAST.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => last = actual,
        }
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorObject {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
}

impl fmt::Display for ErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

/// A JSON-RPC request (or notification-style request; WalletConnect always
/// sets an id).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    /// A request with a fresh [`payload_id`].
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self::with_id(payload_id(), method, params)
    }

    pub fn with_id(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            id,
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC response: either a result or an error.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub id: u64,
    pub outcome: std::result::Result<Value, ErrorObject>,
}

impl Response {
    pub fn result(id: u64, result: Value) -> Self {
        Self {
            id,
            outcome: Ok(result),
        }
    }

    pub fn error(id: u64, error: ErrorObject) -> Self {
        Self {
            id,
            outcome: Err(error),
        }
    }
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(3))?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("jsonrpc", JSONRPC_VERSION)?;
        match &self.outcome {
            Ok(result) => map.serialize_entry("result", result)?,
            Err(error) => map.serialize_entry("error", error)?,
        }
        map.end()
    }
}

/// Any JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Request(Request),
    Response(Response),
}

impl Payload {
    pub fn parse(text: &str) -> Result<Self> {
        Self::from_value(serde_json::from_str(text)?)
    }

    pub fn from_value(value: Value) -> Result<Self> {
        let Value::Object(mut obj) = value else {
            return Err(Error::InvalidPayload("not a json object".into()));
        };
        let id = obj
            .get("id")
            .and_then(parse_id)
            .ok_or_else(|| Error::InvalidPayload("missing or invalid id".into()))?;

        if let Some(method) = obj.get("method").and_then(Value::as_str) {
            let method = method.to_owned();
            let params = obj.remove("params").unwrap_or(Value::Null);
            return Ok(Payload::Request(Request::with_id(id, method, params)));
        }
        if let Some(error) = obj.remove("error") {
            let error: ErrorObject = serde_json::from_value(error)?;
            return Ok(Payload::Response(Response::error(id, error)));
        }
        if let Some(result) = obj.remove("result") {
            return Ok(Payload::Response(Response::result(id, result)));
        }
        Err(Error::InvalidPayload(
            "neither a request nor a response".into(),
        ))
    }

    pub fn id(&self) -> u64 {
        match self {
            Payload::Request(r) => r.id,
            Payload::Response(r) => r.id,
        }
    }

    pub fn to_json(&self) -> String {
        match self {
            Payload::Request(r) => serde_json::to_string(r),
            Payload::Response(r) => serde_json::to_string(r),
        }
        .expect("payload serialization cannot fail")
    }
}

/// Ids are numbers on the wire, but some JavaScript code paths stringify
/// large ones; accept both.
pub(crate) fn parse_id(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn payload_ids_are_unique_and_js_safe() {
        let ids: Vec<u64> = (0..10_000).map(|_| payload_id()).collect();
        for w in ids.windows(2) {
            assert!(w[1] > w[0]);
        }
        assert!(ids.iter().all(|&id| id < (1u64 << 53)));
    }

    #[test]
    fn parse_request_and_responses() {
        let req =
            Payload::parse(r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#)
                .unwrap();
        assert_eq!(
            req,
            Payload::Request(Request::with_id(1, "wc_sessionPing", json!({})))
        );

        let ok = Payload::parse(r#"{"id":"2","jsonrpc":"2.0","result":null}"#).unwrap();
        assert_eq!(ok, Payload::Response(Response::result(2, Value::Null)));

        let err = Payload::parse(
            r#"{"id":3,"jsonrpc":"2.0","error":{"code":5000,"message":"User rejected."}}"#,
        )
        .unwrap();
        assert_eq!(
            err,
            Payload::Response(Response::error(3, ErrorObject::new(5000, "User rejected.")))
        );
        assert!(Payload::parse(r#"{"id":4,"jsonrpc":"2.0"}"#).is_err());
    }

    #[test]
    fn response_serialization() {
        let r = Response::result(7, json!(true));
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"id": 7, "jsonrpc": "2.0", "result": true})
        );
        let e = Response::error(8, ErrorObject::new(1, "x"));
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            json!({"id": 8, "jsonrpc": "2.0", "error": {"code": 1, "message": "x"}})
        );
    }
}
