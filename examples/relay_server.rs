//! A local WalletConnect relay.
//!
//! ```sh
//! cargo run --example relay_server -- 127.0.0.1:8080
//! ```
//!
//! Point dapps and wallets (this crate's or the JavaScript SDK's, via its
//! `relayUrl` option) at `ws://127.0.0.1:8080`.

use wallet_connect::relay::RelayServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".into());
    let server = RelayServer::new();
    let (local, accept_loop) = server.listen(addr).await?;
    println!("relay listening on ws://{local}");
    accept_loop.await?;
    Ok(())
}
