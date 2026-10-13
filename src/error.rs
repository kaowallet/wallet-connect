//! Crate-wide error type.

use crate::rpc::ErrorObject;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while speaking WalletConnect.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed or unusable key material (bad hex, wrong length, low-order point, ...).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// An envelope could not be decoded (bad base64, unknown type byte, truncated).
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// The ChaCha20-Poly1305 tag did not verify.
    #[error("decryption failed")]
    Decryption,

    /// A pairing URI could not be parsed.
    #[error("invalid pairing uri: {0}")]
    InvalidUri(String),

    /// A relay auth JWT could not be decoded or verified.
    #[error("invalid jwt: {0}")]
    InvalidJwt(String),

    /// A CAIP-2 chain id or CAIP-10 account id is malformed.
    #[error("invalid CAIP identifier: {0}")]
    InvalidCaip(String),

    /// A JSON-RPC payload was not a valid request or response.
    #[error("invalid json-rpc payload: {0}")]
    InvalidPayload(String),

    /// The underlying transport failed (WebSocket handshake, I/O, ...).
    #[error("transport error: {0}")]
    Transport(String),

    /// The operation needed a live relay connection and there was none.
    #[error("not connected to the relay")]
    Disconnected,

    /// No answer arrived in time.
    #[error("timed out")]
    Timeout,

    /// The relay answered a request with a JSON-RPC error.
    #[error("relay error {}: {}", .0.code, .0.message)]
    Relay(ErrorObject),

    /// The peer answered a request with a JSON-RPC error.
    #[error("peer error {}: {}", .0.code, .0.message)]
    Peer(ErrorObject),

    /// A protocol rule was violated. The error object carries a WalletConnect
    /// error code (see [`crate::sign::SdkError`]) and is what gets sent to the
    /// peer when the violation is detected while handling its request.
    #[error("{} (code {})", .0.message, .0.code)]
    Protocol(ErrorObject),

    /// Unknown session topic.
    #[error("no session for topic {0}")]
    NoSession(String),

    /// Unknown pairing topic.
    #[error("no pairing for topic {0}")]
    NoPairing(String),

    /// Unknown session proposal id.
    #[error("no proposal with id {0}")]
    NoProposal(u64),

    /// Unknown pending session request id.
    #[error("no pending request with id {0}")]
    NoRequest(u64),

    /// Something has outlived its expiry.
    #[error("{0} expired")]
    Expired(&'static str),

    /// The client was shut down while the operation was in flight.
    #[error("client closed")]
    Closed,

    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    /// The JSON-RPC error object to send to a peer when handling its request
    /// failed with `self`.
    pub(crate) fn to_error_object(&self) -> ErrorObject {
        use crate::sign::InternalError;
        match self {
            Error::Protocol(e) | Error::Peer(e) => e.clone(),
            Error::NoSession(_)
            | Error::NoPairing(_)
            | Error::NoProposal(_)
            | Error::NoRequest(_) => InternalError::NoMatchingKey.with_context(self),
            Error::Expired(what) => InternalError::Expired.with_context(what),
            Error::Json(_) | Error::InvalidPayload(_) | Error::InvalidCaip(_) => {
                InternalError::MissingOrInvalid.with_context(self)
            }
            other => ErrorObject::new(ErrorObject::INTERNAL_ERROR, other.to_string()),
        }
    }
}
