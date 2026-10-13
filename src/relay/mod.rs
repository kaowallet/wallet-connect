//! The relay layer: a JSON-RPC client for the WalletConnect relay network,
//! pluggable transports, and a self-contained relay server.

mod client;
pub mod rpc;
mod server;
mod transport;
#[cfg(feature = "ws")]
mod ws;

pub use client::{PublishOptions, RelayClient, RelayClientOptions, RelayEvent};
pub use server::{RelayServer, ServerConnector};
pub use transport::{BoxFuture, Connection, Connector};
#[cfg(feature = "ws")]
pub use ws::{WsConnector, connect_ws, default_user_agent};
