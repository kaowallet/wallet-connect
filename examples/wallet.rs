//! A minimal wallet: pairs with a URI, approves the proposal for a demo
//! account, answers `personal_sign`, emits `accountsChanged`, and exits when
//! the dapp disconnects.
//!
//! ```sh
//! cargo run --example wallet -- --relay ws://127.0.0.1:8080 'wc:…'
//! ```
//!
//! It holds no real keys: the "signature" it returns is a placeholder, which
//! is enough to exercise the protocol.

use std::collections::BTreeMap;

use serde_json::json;
use wallet_connect::relay::rpc::DEFAULT_RELAY_URL;
use wallet_connect::sign::{
    Metadata, SdkError, SessionEvent, SignClient, SignEvent, SupportedNamespace,
    build_approved_namespaces,
};

const ADDRESS: &str = "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";

struct Args {
    relay: String,
    project_id: Option<String>,
    uri: String,
}

fn args() -> Args {
    let mut relay = DEFAULT_RELAY_URL.to_owned();
    let mut project_id = None;
    let mut uri = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--relay" => relay = it.next().expect("--relay needs a value"),
            "--project-id" => project_id = Some(it.next().expect("--project-id needs a value")),
            other => uri = Some(other.to_owned()),
        }
    }
    Args {
        relay,
        project_id,
        uri: uri.expect("usage: wallet [--relay URL] [--project-id ID] <wc: uri>"),
    }
}

fn supported() -> BTreeMap<String, SupportedNamespace> {
    let chains = ["eip155:1", "eip155:10", "eip155:137"];
    BTreeMap::from([(
        "eip155".to_owned(),
        SupportedNamespace {
            chains: chains.map(String::from).to_vec(),
            methods: [
                "personal_sign",
                "eth_sendTransaction",
                "eth_signTypedData_v4",
            ]
            .map(String::from)
            .to_vec(),
            events: ["accountsChanged", "chainChanged"]
                .map(String::from)
                .to_vec(),
            accounts: chains.iter().map(|c| format!("{c}:{ADDRESS}")).collect(),
        },
    )])
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
        "Rust wallet",
        "wallet-connect example wallet",
        "https://example.org",
    );
    let mut builder = SignClient::builder(metadata).relay_url(&args.relay);
    if let Some(project_id) = &args.project_id {
        builder = builder.project_id(project_id);
    }
    let (client, mut events) = builder.build().await?;
    client.pair(&args.uri).await?;
    println!("paired, waiting for a proposal");

    while let Some(event) = events.recv().await {
        match event {
            SignEvent::SessionProposal(proposal) => {
                println!(
                    "proposal from {} ({})",
                    proposal.proposer.metadata.name, proposal.proposer.metadata.url
                );
                match build_approved_namespaces(
                    &proposal.required_namespaces,
                    &proposal.optional_namespaces,
                    &supported(),
                ) {
                    Ok(namespaces) => {
                        let approved = client.approve(proposal.id, namespaces).await?;
                        approved.acknowledged.await?;
                        let session = approved.session;
                        println!("session {} approved", session.topic);
                        client
                            .emit(
                                &session.topic,
                                "eip155:1",
                                SessionEvent::new("accountsChanged", json!([ADDRESS])),
                            )
                            .await?;
                    }
                    Err(reason) => {
                        println!("cannot satisfy the proposal: {reason}");
                        client
                            .reject(proposal.id, SdkError::UnsupportedChains)
                            .await?;
                    }
                }
            }
            SignEvent::SessionRequest(request) => {
                println!(
                    "request {} on {}: {} {}",
                    request.id, request.chain_id, request.request.method, request.request.params
                );
                let response = match request.request.method.as_str() {
                    // Placeholder signature: this example holds no keys.
                    "personal_sign" => Ok(json!(format!("0x{}", "11".repeat(65)))),
                    _ => Err(SdkError::UserRejected.error()),
                };
                client.respond(&request.topic, request.id, response).await?;
            }
            SignEvent::SessionPing { topic, .. } => println!("ping on {topic}"),
            SignEvent::SessionDelete { reason, .. } => {
                println!("dapp ended the session: {reason}");
                break;
            }
            _ => {}
        }
    }
    client.shutdown();
    Ok(())
}
