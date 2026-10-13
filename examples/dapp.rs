//! A minimal dapp: proposes a session, asks for a `personal_sign`, pings,
//! extends the session, disconnects.
//!
//! ```sh
//! # against a local relay (see the relay_server example)
//! cargo run --example dapp -- --relay ws://127.0.0.1:8080
//! # against the public relay
//! cargo run --example dapp -- --project-id <WalletConnect Cloud project id>
//! ```
//!
//! The pairing URI is printed on a line of its own; paste it into a wallet
//! (or into the wallet example).

use std::collections::BTreeMap;

use serde_json::json;
use wallet_connect::relay::rpc::DEFAULT_RELAY_URL;
use wallet_connect::sign::{
    ConnectParams, Metadata, ProposalNamespace, SessionRequest, SignClient, SignEvent,
};

struct Args {
    relay: String,
    project_id: Option<String>,
}

fn args() -> Args {
    let mut args = Args {
        relay: DEFAULT_RELAY_URL.into(),
        project_id: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--relay" => args.relay = it.next().expect("--relay needs a value"),
            "--project-id" => {
                args.project_id = Some(it.next().expect("--project-id needs a value"))
            }
            other => panic!("unknown argument {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let args = args();

    let metadata = Metadata::new(
        "Rust dapp",
        "wallet-connect example dapp",
        "https://example.com",
    )
    .icon("https://avatars.githubusercontent.com/u/37784886");
    let mut builder = SignClient::builder(metadata).relay_url(&args.relay);
    if let Some(project_id) = &args.project_id {
        builder = builder.project_id(project_id);
    }
    let (client, mut events) = builder.build().await?;

    let connect = client
        .connect(ConnectParams {
            // Must be granted, or the wallet has to reject the proposal...
            required_namespaces: BTreeMap::from([(
                "eip155".to_owned(),
                ProposalNamespace::new(["eip155:1"], ["personal_sign"], ["accountsChanged"]),
            )]),
            // ...nice to have.
            optional_namespaces: BTreeMap::from([(
                "eip155".to_owned(),
                ProposalNamespace::new(["eip155:10"], ["eth_sendTransaction"], ["chainChanged"]),
            )]),
            ..Default::default()
        })
        .await?;
    let uri = connect.uri.expect("a new pairing always has a uri");
    println!("Scan or paste this URI in your wallet:");
    println!("{uri}");

    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                SignEvent::SessionEvent {
                    event, chain_id, ..
                } => {
                    println!("event {} on {chain_id}: {}", event.name, event.data)
                }
                SignEvent::SessionUpdate { namespaces, .. } => {
                    println!(
                        "session updated: {}",
                        serde_json::to_string(&namespaces).unwrap()
                    )
                }
                SignEvent::SessionDelete { reason, .. } => {
                    println!("wallet ended the session: {reason}")
                }
                _ => {}
            }
        }
    });

    let session = connect.approval.await?;
    println!(
        "session {} with {}",
        session.topic, session.peer.metadata.name
    );
    println!("accounts: {}", session.accounts().join(", "));

    let account = session
        .accounts()
        .into_iter()
        .find(|a| a.starts_with("eip155:1:"))
        .or_else(|| session.accounts().into_iter().next())
        .ok_or("the wallet granted no accounts")?;
    let (chain, address) = account.rsplit_once(':').expect("CAIP-10 account");
    let message = format!("0x{}", hex::encode("Hello from Rust"));
    let signature = client
        .request(
            &session.topic,
            chain,
            SessionRequest::new("personal_sign", json!([message, address])),
        )
        .await?;
    println!("personal_sign result: {signature}");

    client.ping(&session.topic).await?;
    println!("ping ok");

    client.extend(&session.topic).await?.await?;
    println!("extend ok");

    client.disconnect(&session.topic).await?;
    println!("disconnected");
    client.shutdown();
    Ok(())
}
