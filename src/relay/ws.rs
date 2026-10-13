//! WebSocket transport (client) and the WebSocket front of the bundled relay
//! server.

use std::net::SocketAddr;
use std::sync::Once;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use url::Url;

use super::rpc::DEFAULT_RELAY_URL;
use super::server::RelayServer;
use super::transport::{BoxFuture, Connection, Connector};
use crate::auth::{DEFAULT_JWT_TTL, IdentityKey, verify_jwt};
use crate::crypto::random_bytes;
use crate::error::{Error, Result};

/// How often the server pings idle clients. The reference SDK restarts its
/// transport when it hears nothing from the relay for a while.
const SERVER_PING_INTERVAL: Duration = Duration::from_secs(20);

fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Fails only if the application installed a provider already, which
        // is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// `wc-2/rust-<version>/<os>-<arch>/wallet-connect`, in the shape of the
/// reference SDK's user agent.
pub fn default_user_agent() -> String {
    format!(
        "wc-2/rust-{}/{}-{}/wallet-connect",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Connects to a relay over WebSocket, authenticating with a fresh JWT on
/// every (re)connect.
#[derive(Debug, Clone)]
pub struct WsConnector {
    relay_url: String,
    project_id: Option<String>,
    identity: IdentityKey,
    user_agent: String,
}

impl WsConnector {
    pub fn new(relay_url: impl Into<String>, identity: IdentityKey) -> Self {
        Self {
            relay_url: relay_url.into(),
            project_id: None,
            identity,
            user_agent: default_user_agent(),
        }
    }

    /// Connector for the public WalletConnect relay.
    pub fn walletconnect(project_id: impl Into<String>, identity: IdentityKey) -> Self {
        Self::new(DEFAULT_RELAY_URL, identity).project_id(project_id)
    }

    pub fn project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn identity(&self) -> &IdentityKey {
        &self.identity
    }

    /// `relay_url?auth=<jwt>&ua=<ua>&projectId=<id>`. The JWT audience is
    /// the relay URL without its query, as in the reference SDK.
    pub fn connection_url(&self) -> Result<Url> {
        let mut url = Url::parse(&self.relay_url)
            .map_err(|e| Error::Transport(format!("bad relay url `{}`: {e}", self.relay_url)))?;
        let mut aud = url.clone();
        aud.set_query(None);
        let aud = aud.as_str().trim_end_matches('/').to_owned();
        let jwt = self.identity.sign_jwt(&aud, DEFAULT_JWT_TTL);
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("auth", &jwt);
            q.append_pair("ua", &self.user_agent);
            if let Some(project_id) = &self.project_id {
                q.append_pair("projectId", project_id);
            }
        }
        Ok(url)
    }
}

impl Connector for WsConnector {
    fn connect(&self) -> BoxFuture<Result<Connection>> {
        let url = self.connection_url();
        Box::pin(async move { connect_ws(url?.as_str()).await })
    }
}

/// Open a WebSocket to `url` and expose it as a [`Connection`].
pub async fn connect_ws(url: &str) -> Result<Connection> {
    install_crypto_provider();
    let (ws, _response) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| Error::Transport(format!("websocket connect: {e}")))?;
    let (app_end, io_end) = Connection::pair();
    tokio::spawn(pump(ws, io_end, None));
    Ok(app_end)
}

/// Shuttle frames between a WebSocket and a channel endpoint until either
/// side closes. Pongs are sent by tungstenite automatically.
async fn pump<S>(ws: WebSocketStream<S>, endpoint: Connection, ping_every: Option<Duration>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Connection {
        sender,
        mut receiver,
    } = endpoint;
    let (mut sink, mut stream) = ws.split();
    let mut ping = tokio::time::interval(ping_every.unwrap_or(Duration::from_secs(3600)));
    ping.tick().await;
    loop {
        tokio::select! {
            outgoing = receiver.recv() => match outgoing {
                Some(text) => {
                    if sink.send(Message::text(text)).await.is_err() {
                        break;
                    }
                }
                None => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
            },
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if sender.send(text.as_str().to_owned()).is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Binary(bytes))) => match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => {
                        if sender.send(text).is_err() {
                            break;
                        }
                    }
                    Err(_) => tracing::debug!("dropping non-utf8 binary frame"),
                },
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            },
            _ = ping.tick(), if ping_every.is_some() => {
                if sink.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
        }
    }
}

impl RelayServer {
    /// Serve this relay over WebSocket on `addr` (use port 0 for an
    /// ephemeral port). Returns the bound address and the accept loop task.
    ///
    /// Clients authenticate with the usual `auth` JWT query parameter; the
    /// token's `iss` becomes the client id. Connections without a token are
    /// accepted under a random id, invalid tokens are refused with 401.
    pub async fn listen(
        &self,
        addr: impl tokio::net::ToSocketAddrs,
    ) -> Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Transport(format!("bind: {e}")))?;
        let local = listener
            .local_addr()
            .map_err(|e| Error::Transport(format!("local_addr: {e}")))?;
        let server = self.clone();
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_socket(server, stream).await {
                                tracing::debug!(%peer, "relay connection ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        Ok((local, task))
    }
}

// The handshake callback's error type is dictated by tungstenite.
#[allow(clippy::result_large_err)]
async fn serve_socket(server: RelayServer, stream: TcpStream) -> Result<()> {
    let mut client_id = None;
    let authenticate = |req: &Request,
                        resp: Response|
     -> std::result::Result<Response, ErrorResponse> {
        let query = req.uri().query().unwrap_or("");
        let auth = url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == "auth")
            .map(|(_, v)| v.into_owned());
        match auth {
            Some(jwt) => match verify_jwt(&jwt) {
                Ok(claims) => client_id = Some(claims.iss),
                Err(e) => {
                    let mut err = ErrorResponse::new(Some(format!("unauthorized: {e}")));
                    *err.status_mut() = StatusCode::UNAUTHORIZED;
                    return Err(err);
                }
            },
            None => client_id = Some(format!("anonymous:{}", hex::encode(random_bytes::<16>()))),
        }
        Ok(resp)
    };
    let ws = tokio_tungstenite::accept_hdr_async(stream, authenticate)
        .await
        .map_err(|e| Error::Transport(format!("websocket handshake: {e}")))?;
    let client_id = client_id.expect("set by the handshake callback");
    tracing::debug!(%client_id, "relay client connected");
    let endpoint = server.accept(client_id);
    pump(ws, endpoint, Some(SERVER_PING_INTERVAL)).await;
    Ok(())
}
