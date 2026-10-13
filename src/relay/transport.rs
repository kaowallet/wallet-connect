//! Transport abstraction.
//!
//! A relay connection is a bidirectional stream of JSON text frames. It is
//! modelled as a pair of unbounded channels so that the WebSocket transport,
//! the in-process transport used by tests and anything a user plugs in all
//! look the same to [`RelayClient`](super::RelayClient).

use std::future::Future;
use std::pin::Pin;

use tokio::sync::mpsc;

use crate::error::Result;

/// One end of a relay connection. Dropping `sender` closes the connection;
/// `receiver` yields `None` once the other side has gone away.
#[derive(Debug)]
pub struct Connection {
    pub sender: mpsc::UnboundedSender<String>,
    pub receiver: mpsc::UnboundedReceiver<String>,
}

impl Connection {
    /// Two in-memory endpoints wired to each other.
    pub fn pair() -> (Connection, Connection) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        (
            Connection {
                sender: a_tx,
                receiver: b_rx,
            },
            Connection {
                sender: b_tx,
                receiver: a_rx,
            },
        )
    }
}

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Opens relay connections. Called once up front and again on every
/// reconnect, so implementations should produce fresh credentials (the
/// WebSocket connector signs a new JWT each time).
pub trait Connector: Send + Sync + 'static {
    fn connect(&self) -> BoxFuture<Result<Connection>>;
}

impl<F, Fut> Connector for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Connection>> + Send + 'static,
{
    fn connect(&self) -> BoxFuture<Result<Connection>> {
        Box::pin(self())
    }
}
