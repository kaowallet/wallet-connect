//! The Sign API (v2): pairing, session proposal and settlement, requests,
//! events, updates, extensions, pings and deletion.

mod client;
pub mod errors;
pub mod namespaces;
pub mod rpc;
pub mod types;

pub use client::{
    ApproveParams, Approved, ConnectParams, ConnectResponse, Pending, SignClient,
    SignClientBuilder, SignClientOptions, SignEvent, SignEvents, Snapshot,
};
pub use errors::{InternalError, SdkError};
pub use namespaces::{SupportedNamespace, build_approved_namespaces};
pub use types::*;
