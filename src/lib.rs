//! The [WalletConnect v2](https://specs.walletconnect.com/2.0) protocol in
//! Rust, for both dapps and wallets.
//!
//! The crate is wire-compatible with the reference JavaScript SDK
//! (`@walletconnect/sign-client`): key derivation, envelopes, relay auth and
//! URIs are pinned to its output by test vectors, and live sessions are
//! exercised against it in both directions (see `interop/`).
//!
//! # Layers
//!
//! | module     | what it does                                                             |
//! |------------|--------------------------------------------------------------------------|
//! | [`crypto`] | X25519 + HKDF key agreement, topics, ChaCha20-Poly1305 envelopes          |
//! | [`uri`]    | `wc:` pairing URIs                                                       |
//! | [`auth`]   | `did:key` client ids and the Ed25519 JWT presented to the relay          |
//! | [`relay`]  | relay JSON-RPC client, transports (WebSocket, in-process), relay server  |
//! | [`sign`]   | the Sign API: pairing, proposals, sessions, requests, events             |
//!
//! Most applications only need [`sign::SignClient`].
//!
//! # A dapp
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use serde_json::json;
//! use wallet_connect::sign::{ConnectParams, Metadata, ProposalNamespace, SessionRequest, SignClient};
//!
//! # async fn dapp() -> wallet_connect::Result<()> {
//! let metadata = Metadata::new("My dapp", "An example", "https://dapp.example");
//! let (client, _events) = SignClient::builder(metadata)
//!     .project_id("<WalletConnect Cloud project id>")
//!     .build()
//!     .await?;
//!
//! let connect = client
//!     .connect(ConnectParams {
//!         optional_namespaces: BTreeMap::from([(
//!             "eip155".to_owned(),
//!             ProposalNamespace::new(["eip155:1"], ["personal_sign"], ["accountsChanged"]),
//!         )]),
//!         ..Default::default()
//!     })
//!     .await?;
//! println!("show this to the wallet: {}", connect.uri.unwrap());
//!
//! let session = connect.approval.await?;
//! let signature = client
//!     .request(
//!         &session.topic,
//!         "eip155:1",
//!         SessionRequest::new("personal_sign", json!(["0x48656c6c6f", "0xab16…"])),
//!     )
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! # A wallet
//!
//! ```no_run
//! use wallet_connect::sign::{Metadata, SdkError, SignClient, SignEvent};
//! # use wallet_connect::sign::SessionNamespaces;
//! # fn namespaces_for(_: &wallet_connect::sign::Proposal) -> SessionNamespaces { unimplemented!() }
//! # fn sign(_: &wallet_connect::sign::PendingRequest) -> serde_json::Value { unimplemented!() }
//!
//! # async fn wallet(uri: &str) -> wallet_connect::Result<()> {
//! let metadata = Metadata::new("My wallet", "An example", "https://wallet.example");
//! let (client, mut events) = SignClient::builder(metadata)
//!     .project_id("<WalletConnect Cloud project id>")
//!     .build()
//!     .await?;
//! client.pair(uri).await?;
//!
//! while let Some(event) = events.recv().await {
//!     match event {
//!         SignEvent::SessionProposal(proposal) => {
//!             // e.g. with wallet_connect::sign::build_approved_namespaces
//!             client.approve(proposal.id, namespaces_for(&proposal)).await?;
//!         }
//!         SignEvent::SessionRequest(request) => {
//!             let answer = if request.request.method == "personal_sign" {
//!                 Ok(sign(&request))
//!             } else {
//!                 Err(SdkError::UserRejected.error())
//!             };
//!             client.respond(&request.topic, request.id, answer).await?;
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! # Without a network
//!
//! [`relay::RelayServer`] is a complete relay that can run in-process (or be
//! served over WebSocket), which makes end-to-end tests self-contained:
//!
//! ```
//! use std::collections::BTreeMap;
//! use serde_json::json;
//! use wallet_connect::relay::RelayServer;
//! use wallet_connect::sign::*;
//!
//! # #[tokio::main] async fn main() -> wallet_connect::Result<()> {
//! let relay = RelayServer::new();
//! let (dapp, _) = SignClient::builder(Metadata::new("dapp", "", ""))
//!     .connector(relay.connector("dapp"))
//!     .build()
//!     .await?;
//! let (wallet, mut wallet_events) = SignClient::builder(Metadata::new("wallet", "", ""))
//!     .connector(relay.connector("wallet"))
//!     .build()
//!     .await?;
//!
//! let required = BTreeMap::from([(
//!     "eip155".to_owned(),
//!     ProposalNamespace::new(["eip155:1"], ["personal_sign"], []),
//! )]);
//! let connect = dapp
//!     .connect(ConnectParams { required_namespaces: required, ..Default::default() })
//!     .await?;
//! wallet.pair(&connect.uri.unwrap().to_string()).await?;
//!
//! let proposal = loop {
//!     if let Some(SignEvent::SessionProposal(p)) = wallet_events.recv().await {
//!         break p;
//!     }
//! };
//! let supported = BTreeMap::from([(
//!     "eip155".to_owned(),
//!     SupportedNamespace {
//!         chains: vec!["eip155:1".into()],
//!         methods: vec!["personal_sign".into()],
//!         events: vec![],
//!         accounts: vec!["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".into()],
//!     },
//! )]);
//! let namespaces =
//!     build_approved_namespaces(&proposal.required_namespaces, &proposal.optional_namespaces, &supported)
//!         .map_err(wallet_connect::Error::Protocol)?;
//! wallet.approve(proposal.id, namespaces).await?;
//!
//! let session = connect.approval.await?;
//! assert_eq!(session.accounts(), ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]);
//! # Ok(()) }
//! ```
//!
//! # Not covered
//!
//! The one-click authentication extension (`wc_sessionAuthenticate`,
//! SIWE/CACAO), link mode, the Verify attestation API and the Notify API are
//! not implemented. Peers that ask for one-click auth fall back to a regular
//! session proposal, which is fully supported.

pub mod auth;
pub mod caip;
pub mod crypto;
pub mod error;
pub mod relay;
pub mod rpc;
pub mod sign;
pub mod time;
pub mod uri;

pub use error::{Error, Result};
