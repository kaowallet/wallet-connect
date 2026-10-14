//! End-to-end Sign API flows between a dapp client and a wallet client.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::timeout;
use wallet_connect::Error;
use wallet_connect::crypto::Topic;
use wallet_connect::relay::{BoxFuture, Connection, Connector, RelayClientOptions, RelayServer};
use wallet_connect::sign::{
    ConnectParams, Metadata, ProposalNamespace, ProposalNamespaces, SdkError, Session,
    SessionEvent, SessionNamespace, SessionNamespaces, SessionRequest, SignClient,
    SignClientOptions, SignEvent, SignEvents, SupportedNamespace, build_approved_namespaces,
};

const ACCOUNT: &str = "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";

fn options() -> SignClientOptions {
    SignClientOptions {
        expiry_check_interval: Duration::from_millis(100),
        ping_timeout: Duration::from_secs(5),
        ack_timeout: Duration::from_secs(5),
    }
}

async fn client(server: &RelayServer, name: &str) -> (SignClient, SignEvents) {
    SignClient::builder(Metadata::new(
        name,
        format!("{name} (test)"),
        format!("https://{name}.example"),
    ))
    .connector(server.connector(name))
    .options(options())
    .build()
    .await
    .unwrap()
}

/// Wait for the next event other than relay connectivity changes.
async fn next(events: &mut SignEvents) -> SignEvent {
    loop {
        let event = timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("no event within 5s")
            .expect("event stream closed");
        match event {
            SignEvent::RelayConnected | SignEvent::RelayDisconnected => continue,
            other => return other,
        }
    }
}

fn required() -> ProposalNamespaces {
    BTreeMap::from([(
        "eip155".to_owned(),
        ProposalNamespace::new(["eip155:1"], ["personal_sign"], ["accountsChanged"]),
    )])
}

fn optional() -> ProposalNamespaces {
    BTreeMap::from([(
        "eip155".to_owned(),
        ProposalNamespace::new(
            ["eip155:10", "eip155:1"],
            ["eth_sendTransaction", "eth_signTypedData_v4"],
            ["chainChanged"],
        ),
    )])
}

fn supported() -> BTreeMap<String, SupportedNamespace> {
    let chains = ["eip155:1", "eip155:10", "eip155:137"];
    BTreeMap::from([(
        "eip155".to_owned(),
        SupportedNamespace {
            chains: chains.iter().map(|c| c.to_string()).collect(),
            methods: ["personal_sign", "eth_sendTransaction"]
                .map(String::from)
                .to_vec(),
            events: ["accountsChanged", "chainChanged"]
                .map(String::from)
                .to_vec(),
            accounts: chains.iter().map(|c| format!("{c}:{ACCOUNT}")).collect(),
        },
    )])
}

struct Pair {
    dapp: SignClient,
    dapp_events: SignEvents,
    wallet: SignClient,
    wallet_events: SignEvents,
    session: Session,
}

/// Run connect → pair → propose → approve → settle.
async fn establish(server: &RelayServer) -> Pair {
    let (dapp, mut dapp_events) = client(server, "dapp").await;
    let (wallet, mut wallet_events) = client(server, "wallet").await;

    let connect = dapp
        .connect(ConnectParams {
            required_namespaces: required(),
            optional_namespaces: optional(),
            ..Default::default()
        })
        .await
        .unwrap();
    let uri = connect.uri.expect("fresh pairing has a uri");
    wallet.pair(&uri.to_string()).await.unwrap();

    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };
    assert_eq!(proposal.pairing_topic, connect.pairing_topic);
    assert_eq!(proposal.proposer.metadata.name, "dapp");
    assert_eq!(proposal.required_namespaces, required());
    assert_eq!(wallet.proposals().len(), 1);

    let namespaces = build_approved_namespaces(
        &proposal.required_namespaces,
        &proposal.optional_namespaces,
        &supported(),
    )
    .unwrap();
    let approved = wallet
        .approve(proposal.id, namespaces.clone())
        .await
        .unwrap();
    assert!(!approved.session.acknowledged);
    assert!(wallet.proposals().is_empty());

    let session = connect.approval.await.unwrap();
    assert_eq!(session.topic, approved.session.topic);
    assert_eq!(session.namespaces, namespaces);
    assert_eq!(session.peer.metadata.name, "wallet");
    assert!(!session.is_controller());
    assert!(approved.session.is_controller());
    let SignEvent::SessionConnect(connected) = next(&mut dapp_events).await else {
        panic!("expected session_connect")
    };
    assert_eq!(connected.topic, session.topic);

    approved.acknowledged.await.unwrap();
    assert!(wallet.session(&session.topic).unwrap().acknowledged);
    assert!(wallet.pairings()[0].active);
    assert!(dapp.pairings()[0].active);

    Pair {
        dapp,
        dapp_events,
        wallet,
        wallet_events,
        session,
    }
}

#[tokio::test]
async fn full_session_lifecycle() {
    let server = RelayServer::new();
    let Pair {
        dapp,
        mut dapp_events,
        wallet,
        mut wallet_events,
        session,
    } = establish(&server).await;
    let topic = session.topic.clone();
    assert_eq!(
        session.accounts(),
        vec![
            format!("eip155:1:{ACCOUNT}"),
            format!("eip155:10:{ACCOUNT}")
        ]
    );

    // --- request / respond --------------------------------------------
    let request = {
        let dapp = dapp.clone();
        let topic = topic.clone();
        tokio::spawn(async move {
            dapp.request(
                &topic,
                "eip155:1",
                SessionRequest::new("personal_sign", json!(["0x48656c6c6f", ACCOUNT])),
            )
            .await
        })
    };
    let SignEvent::SessionRequest(pending) = next(&mut wallet_events).await else {
        panic!("expected a session request")
    };
    assert_eq!(pending.chain_id, "eip155:1");
    assert_eq!(pending.request.method, "personal_sign");
    assert!(pending.request.expiry_timestamp.is_some());
    assert_eq!(wallet.pending_requests().len(), 1);
    wallet
        .respond(&topic, pending.id, Ok(json!("0xdeadbeef")))
        .await
        .unwrap();
    assert_eq!(request.await.unwrap().unwrap(), json!("0xdeadbeef"));
    assert!(wallet.pending_requests().is_empty());

    // A rejection surfaces as a peer error.
    let request = {
        let dapp = dapp.clone();
        let topic = topic.clone();
        tokio::spawn(async move {
            dapp.request(
                &topic,
                "eip155:10",
                SessionRequest::new("eth_sendTransaction", json!([{}])),
            )
            .await
        })
    };
    let SignEvent::SessionRequest(pending) = next(&mut wallet_events).await else {
        panic!("expected a session request")
    };
    wallet
        .respond(&topic, pending.id, Err(SdkError::UserRejected.error()))
        .await
        .unwrap();
    match request.await.unwrap() {
        Err(Error::Peer(e)) => assert_eq!(e.code, 5000),
        other => panic!("{other:?}"),
    }

    // --- events -------------------------------------------------------
    wallet
        .emit(
            &topic,
            "eip155:1",
            SessionEvent::new("accountsChanged", json!([ACCOUNT])),
        )
        .await
        .unwrap();
    match next(&mut dapp_events).await {
        SignEvent::SessionEvent {
            chain_id, event, ..
        } => {
            assert_eq!(chain_id, "eip155:1");
            assert_eq!(event.name, "accountsChanged");
            assert_eq!(event.data, json!([ACCOUNT]));
        }
        other => panic!("{other:?}"),
    }

    // --- update -------------------------------------------------------
    let mut namespaces = session.namespaces.clone();
    let ns = namespaces.get_mut("eip155").unwrap();
    ns.accounts.push(format!("eip155:137:{ACCOUNT}"));
    ns.chains.as_mut().unwrap().push("eip155:137".into());
    let ack = wallet.update(&topic, namespaces.clone()).await.unwrap();
    match next(&mut dapp_events).await {
        SignEvent::SessionUpdate {
            namespaces: got, ..
        } => assert_eq!(got, namespaces),
        other => panic!("{other:?}"),
    }
    ack.await.unwrap();
    assert_eq!(dapp.session(&topic).unwrap().namespaces, namespaces);
    assert!(
        dapp.session(&topic)
            .unwrap()
            .chains()
            .contains(&"eip155:137".to_owned())
    );

    // --- extend -------------------------------------------------------
    let before = dapp.session(&topic).unwrap().expiry;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let ack = wallet.extend(&topic).await.unwrap();
    match next(&mut dapp_events).await {
        SignEvent::SessionExtend { expiry, .. } => assert!(expiry > before),
        other => panic!("{other:?}"),
    }
    ack.await.unwrap();
    assert!(dapp.session(&topic).unwrap().expiry > before);

    // --- ping both ways -----------------------------------------------
    dapp.ping(&topic).await.unwrap();
    assert!(matches!(
        next(&mut wallet_events).await,
        SignEvent::SessionPing { .. }
    ));
    wallet.ping(&topic).await.unwrap();
    assert!(matches!(
        next(&mut dapp_events).await,
        SignEvent::SessionPing { .. }
    ));

    // --- disconnect ---------------------------------------------------
    dapp.disconnect(&topic).await.unwrap();
    match next(&mut wallet_events).await {
        SignEvent::SessionDelete {
            topic: t, reason, ..
        } => {
            assert_eq!(t, topic);
            assert_eq!(reason.code, 6000);
        }
        other => panic!("{other:?}"),
    }
    assert!(dapp.sessions().is_empty());
    assert!(wallet.sessions().is_empty());
    assert!(matches!(dapp.ping(&topic).await, Err(Error::NoSession(_))));
}

#[tokio::test]
async fn wallet_rejects_proposal() {
    let server = RelayServer::new();
    let (dapp, _dapp_events) = client(&server, "dapp").await;
    let (wallet, mut wallet_events) = client(&server, "wallet").await;

    let connect = dapp
        .connect(ConnectParams {
            required_namespaces: required(),
            ..Default::default()
        })
        .await
        .unwrap();
    wallet
        .pair(&connect.uri.unwrap().to_string())
        .await
        .unwrap();
    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };
    wallet
        .reject(proposal.id, SdkError::UserRejected)
        .await
        .unwrap();
    match connect.approval.await {
        Err(Error::Peer(e)) => assert_eq!(e, SdkError::UserRejected.error()),
        other => panic!("{other:?}"),
    }
    assert!(wallet.proposals().is_empty());
    assert!(matches!(
        wallet.approve(proposal.id, BTreeMap::new()).await,
        Err(Error::NoProposal(_))
    ));
}

#[tokio::test]
async fn approval_must_conform_to_required_namespaces() {
    let server = RelayServer::new();
    let (dapp, _dapp_events) = client(&server, "dapp").await;
    let (wallet, mut wallet_events) = client(&server, "wallet").await;
    let connect = dapp
        .connect(ConnectParams {
            required_namespaces: required(),
            ..Default::default()
        })
        .await
        .unwrap();
    wallet
        .pair(&connect.uri.unwrap().to_string())
        .await
        .unwrap();
    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };

    // Wrong chain.
    let namespaces: SessionNamespaces = BTreeMap::from([(
        "eip155".to_owned(),
        SessionNamespace {
            chains: None,
            accounts: vec![format!("eip155:10:{ACCOUNT}")],
            methods: vec!["personal_sign".into()],
            events: vec!["accountsChanged".into()],
        },
    )]);
    match wallet.approve(proposal.id, namespaces).await {
        Err(Error::Protocol(e)) => assert_eq!(e.code, 9),
        other => panic!("{other:?}"),
    }
    // Malformed account.
    let namespaces: SessionNamespaces = BTreeMap::from([(
        "eip155".to_owned(),
        SessionNamespace {
            accounts: vec!["eip155:1".into()],
            ..Default::default()
        },
    )]);
    match wallet.approve(proposal.id, namespaces).await {
        Err(Error::Protocol(e)) => assert_eq!(e.code, 5103),
        other => panic!("{other:?}"),
    }
    // The proposal is still there and can be rejected.
    wallet
        .reject(proposal.id, SdkError::UserRejectedChains)
        .await
        .unwrap();
    assert!(matches!(connect.approval.await, Err(Error::Peer(e)) if e.code == 5001));
}

#[tokio::test]
async fn local_validation_of_requests_and_permissions() {
    let server = RelayServer::new();
    let Pair {
        dapp,
        wallet,
        session,
        ..
    } = establish(&server).await;
    let topic = &session.topic;

    let unsupported_chain = dapp
        .request(
            topic,
            "eip155:5",
            SessionRequest::new("personal_sign", json!([])),
        )
        .await;
    assert!(matches!(unsupported_chain, Err(Error::Protocol(e)) if e.code == 5100));
    let unauthorized = dapp
        .request(
            topic,
            "eip155:1",
            SessionRequest::new("eth_signTypedData_v4", json!([])),
        )
        .await;
    assert!(matches!(unauthorized, Err(Error::Protocol(e)) if e.code == 3001));

    // Only the controller (wallet) may update; either peer may extend, as
    // with the reference SDK.
    assert!(matches!(
        dapp.update(topic, session.namespaces.clone()).await,
        Err(Error::Protocol(e)) if e.code == 3003
    ));
    dapp.extend(topic).await.unwrap().await.unwrap();

    // Events must be granted.
    assert!(matches!(
        wallet.emit(topic, "eip155:1", SessionEvent::new("somethingElse", json!(null))).await,
        Err(Error::Protocol(e)) if e.code == 3002
    ));
    // Updates must keep satisfying the required namespaces.
    let mut shrunk = session.namespaces.clone();
    shrunk.get_mut("eip155").unwrap().methods.clear();
    assert!(matches!(wallet.update(topic, shrunk).await, Err(Error::Protocol(e)) if e.code == 9));

    // Unknown request ids / topics.
    assert!(matches!(
        wallet.respond(topic, 42, Ok(json!(null))).await,
        Err(Error::NoRequest(42))
    ));
    let unknown = Topic::generate();
    assert!(matches!(
        dapp.disconnect(&unknown).await,
        Err(Error::NoSession(_))
    ));
}

#[tokio::test]
async fn pairing_ping_reuse_and_delete() {
    let server = RelayServer::new();
    let Pair {
        dapp,
        wallet,
        mut wallet_events,
        session,
        ..
    } = establish(&server).await;
    let pairing = session.pairing_topic.clone();

    dapp.ping(&pairing).await.unwrap();
    assert!(
        matches!(next(&mut wallet_events).await, SignEvent::PairingPing { topic, .. } if topic == pairing)
    );

    // A second session over the same pairing: no new URI.
    let connect = dapp
        .connect(ConnectParams {
            required_namespaces: required(),
            pairing_topic: Some(pairing.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(connect.uri.is_none());
    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };
    let namespaces = build_approved_namespaces(
        &proposal.required_namespaces,
        &proposal.optional_namespaces,
        &supported(),
    )
    .unwrap();
    wallet.approve(proposal.id, namespaces).await.unwrap();
    let second = connect.approval.await.unwrap();
    assert_ne!(second.topic, session.topic);
    assert_eq!(dapp.sessions().len(), 2);

    dapp.disconnect(&pairing).await.unwrap();
    assert!(
        matches!(next(&mut wallet_events).await, SignEvent::PairingDelete { topic, .. } if topic == pairing)
    );
    assert!(wallet.pairings().is_empty());
    // Sessions outlive their pairing.
    assert_eq!(wallet.sessions().len(), 2);
}

#[tokio::test]
async fn survives_relay_reconnect() {
    let server = RelayServer::new();
    let Pair {
        dapp,
        wallet,
        mut wallet_events,
        session,
        ..
    } = establish(&server).await;

    server.disconnect_all();
    // Wait for both clients to come back.
    for _ in 0..100 {
        if server.connection_count() == 2
            && dapp.relay().is_connected()
            && wallet.relay().is_connected()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let topic = session.topic.clone();
    let request = tokio::spawn(async move {
        dapp.request(
            &topic,
            "eip155:1",
            SessionRequest::new("personal_sign", json!(["0x00"])),
        )
        .await
    });
    let SignEvent::SessionRequest(pending) = next(&mut wallet_events).await else {
        panic!("expected a session request")
    };
    wallet
        .respond(&session.topic, pending.id, Ok(json!("0x01")))
        .await
        .unwrap();
    assert_eq!(request.await.unwrap().unwrap(), json!("0x01"));
}

#[tokio::test]
async fn wallet_restores_from_snapshot_and_receives_offline_requests() {
    let server = RelayServer::new();
    let Pair {
        dapp,
        wallet,
        session,
        ..
    } = establish(&server).await;

    // Persist through JSON, as an application would, then go offline.
    let saved = serde_json::to_string(&wallet.snapshot()).unwrap();
    wallet.shutdown();
    drop(wallet);

    // The dapp asks while the wallet is offline; the relay keeps the message.
    let topic = session.topic.clone();
    let request = tokio::spawn(async move {
        dapp.request(
            &topic,
            "eip155:1",
            SessionRequest::new("personal_sign", json!(["0x00"])),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (wallet, mut wallet_events) = SignClient::builder(Metadata::new(
        "wallet",
        "wallet (test)",
        "https://wallet.example",
    ))
    .connector(server.connector("wallet"))
    .options(options())
    .snapshot(serde_json::from_str(&saved).unwrap())
    .build()
    .await
    .unwrap();
    assert_eq!(wallet.sessions().len(), 1);
    let SignEvent::SessionRequest(pending) = next(&mut wallet_events).await else {
        panic!("expected the queued session request")
    };
    wallet
        .respond(&session.topic, pending.id, Ok(json!("0x02")))
        .await
        .unwrap();
    assert_eq!(request.await.unwrap().unwrap(), json!("0x02"));
}

#[tokio::test]
async fn pairing_uri_cannot_be_reused_once_active() {
    let server = RelayServer::new();
    let (dapp, _) = client(&server, "dapp").await;
    let (wallet, mut wallet_events) = client(&server, "wallet").await;
    let connect = dapp.connect(ConnectParams::default()).await.unwrap();
    let uri = connect.uri.unwrap().to_string();
    wallet.pair(&uri).await.unwrap();
    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };
    // No namespaces requested: grant everything supported.
    let namespaces =
        build_approved_namespaces(&BTreeMap::new(), &BTreeMap::new(), &supported()).unwrap();
    wallet.approve(proposal.id, namespaces).await.unwrap();
    connect.approval.await.unwrap();
    assert!(matches!(wallet.pair(&uri).await, Err(Error::Protocol(_))));
    assert!(wallet.pair("wc:nonsense").await.is_err());
}

/// What [`Meddler`] does to a publish.
#[derive(Clone, Copy)]
enum Meddle {
    /// The relay takes the message, but its answer never comes back.
    LoseAnswer,
    /// The relay refuses the message.
    Refuse,
}

/// A connector to an in-process relay that meddles with the client's next
/// `irn_publish` carrying a given tag.
#[derive(Clone)]
struct Meddler {
    server: RelayServer,
    client_id: &'static str,
    next: Arc<Mutex<Option<(u32, Meddle)>>>,
}

impl Meddler {
    fn new(server: &RelayServer, client_id: &'static str) -> Self {
        Meddler {
            server: server.clone(),
            client_id,
            next: Arc::default(),
        }
    }

    fn next_publish(&self, tag: u32, meddle: Meddle) {
        *self.next.lock().unwrap() = Some((tag, meddle));
    }
}

impl Connector for Meddler {
    fn connect(&self) -> BoxFuture<wallet_connect::Result<Connection>> {
        let meddler = self.clone();
        Box::pin(async move {
            let Connection {
                sender: to_server,
                receiver: mut from_server,
            } = meddler.server.accept(meddler.client_id);
            let (client_end, proxy_end) = Connection::pair();
            let Connection {
                sender: to_client,
                receiver: mut from_client,
            } = proxy_end;
            tokio::spawn(async move {
                let mut lost = HashSet::new();
                loop {
                    tokio::select! {
                        frame = from_client.recv() => {
                            let Some(text) = frame else { break };
                            let request: Value = serde_json::from_str(&text).unwrap();
                            let meddle = {
                                let mut next = meddler.next.lock().unwrap();
                                match *next {
                                    Some((tag, meddle))
                                        if request["method"] == "irn_publish"
                                            && request["params"]["tag"] == tag =>
                                    {
                                        *next = None;
                                        Some(meddle)
                                    }
                                    _ => None,
                                }
                            };
                            let id = request["id"].as_u64().unwrap();
                            match meddle {
                                Some(Meddle::LoseAnswer) => {
                                    lost.insert(id);
                                }
                                Some(Meddle::Refuse) => {
                                    let refusal = json!({
                                        "id": id,
                                        "jsonrpc": "2.0",
                                        "error": {"code": -32000, "message": "refused"},
                                    });
                                    let _ = to_client.send(refusal.to_string());
                                    continue;
                                }
                                None => {}
                            }
                            if to_server.send(text).is_err() {
                                break;
                            }
                        }
                        frame = from_server.recv() => {
                            let Some(text) = frame else { break };
                            let answer: Value = serde_json::from_str(&text).unwrap();
                            if answer.get("method").is_none()
                                && answer["id"].as_u64().is_some_and(|id| lost.remove(&id))
                            {
                                continue;
                            }
                            if to_client.send(text).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            Ok(client_end)
        })
    }
}

/// A proposal from a dapp, received by a wallet whose relay traffic goes
/// through a [`Meddler`].
struct Proposed {
    dapp: SignClient,
    approval: wallet_connect::sign::Pending<Session>,
    wallet: SignClient,
    wallet_events: SignEvents,
    meddler: Meddler,
    id: u64,
    namespaces: SessionNamespaces,
}

async fn propose_to_meddled_wallet(server: &RelayServer) -> Proposed {
    let (dapp, _) = client(server, "dapp").await;
    let meddler = Meddler::new(server, "wallet");
    let (wallet, mut wallet_events) = SignClient::builder(Metadata::new(
        "wallet",
        "wallet (test)",
        "https://wallet.example",
    ))
    .connector(meddler.clone())
    .options(options())
    .relay_options(RelayClientOptions {
        request_timeout: Duration::from_millis(500),
        ..Default::default()
    })
    .build()
    .await
    .unwrap();
    let connect = dapp
        .connect(ConnectParams {
            required_namespaces: required(),
            ..Default::default()
        })
        .await
        .unwrap();
    wallet
        .pair(&connect.uri.unwrap().to_string())
        .await
        .unwrap();
    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };
    let namespaces = build_approved_namespaces(
        &proposal.required_namespaces,
        &proposal.optional_namespaces,
        &supported(),
    )
    .unwrap();
    Proposed {
        dapp,
        approval: connect.approval,
        wallet,
        wallet_events,
        meddler,
        id: proposal.id,
        namespaces,
    }
}

#[tokio::test]
async fn approve_keeps_the_session_when_the_relay_does_not_confirm_the_settlement() {
    let server = RelayServer::new();
    let Proposed {
        dapp,
        approval,
        wallet,
        mut wallet_events,
        meddler,
        id,
        namespaces,
    } = propose_to_meddled_wallet(&server).await;

    // The relay passes the settlement on, but the wallet never hears back.
    meddler.next_publish(1102, Meddle::LoseAnswer);
    let approved = wallet.approve(id, namespaces).await.unwrap();
    assert!(wallet.proposals().is_empty());

    // The dapp has the session, so the wallet must still have it too.
    let session = approval.await.unwrap();
    assert_eq!(session.topic, approved.session.topic);
    approved.acknowledged.await.unwrap();
    assert!(wallet.session(&session.topic).unwrap().acknowledged);

    let topic = session.topic.clone();
    let request = tokio::spawn(async move {
        dapp.request(
            &topic,
            "eip155:1",
            SessionRequest::new("personal_sign", json!(["0x00"])),
        )
        .await
    });
    let SignEvent::SessionRequest(pending) = next(&mut wallet_events).await else {
        panic!("expected a session request")
    };
    wallet
        .respond(&session.topic, pending.id, Ok(json!("0x04")))
        .await
        .unwrap();
    assert_eq!(request.await.unwrap().unwrap(), json!("0x04"));
}

#[tokio::test]
async fn approve_settles_when_the_relay_does_not_confirm_the_answer() {
    let server = RelayServer::new();
    let Proposed {
        dapp: _dapp,
        approval,
        wallet,
        meddler,
        id,
        namespaces,
        ..
    } = propose_to_meddled_wallet(&server).await;

    // The dapp gets the answer and waits for the settlement.
    meddler.next_publish(1101, Meddle::LoseAnswer);
    let approved = wallet.approve(id, namespaces).await.unwrap();
    let session = approval.await.unwrap();
    assert_eq!(session.topic, approved.session.topic);
    approved.acknowledged.await.unwrap();
}

#[tokio::test]
async fn approve_changes_nothing_when_the_relay_refuses_the_answer() {
    let server = RelayServer::new();
    let Proposed {
        dapp: _dapp,
        approval,
        wallet,
        meddler,
        id,
        namespaces,
        ..
    } = propose_to_meddled_wallet(&server).await;

    meddler.next_publish(1101, Meddle::Refuse);
    assert!(matches!(
        wallet.approve(id, namespaces.clone()).await,
        Err(Error::Relay(_))
    ));
    assert!(wallet.sessions().is_empty());

    // Nothing reached the dapp: the proposal can be answered again.
    assert_eq!(wallet.proposals().len(), 1);
    let approved = wallet.approve(id, namespaces).await.unwrap();
    assert_eq!(approval.await.unwrap().topic, approved.session.topic);
}

#[tokio::test]
async fn approve_drops_the_session_when_the_relay_refuses_the_settlement() {
    let server = RelayServer::new();
    let Proposed {
        wallet,
        meddler,
        id,
        namespaces,
        ..
    } = propose_to_meddled_wallet(&server).await;

    meddler.next_publish(1102, Meddle::Refuse);
    assert!(matches!(
        wallet.approve(id, namespaces.clone()).await,
        Err(Error::Relay(_))
    ));
    // Without the settlement the dapp has no session.
    assert!(wallet.sessions().is_empty());
    // But it has the answer and would ignore another one.
    assert!(wallet.proposals().is_empty());
    assert!(matches!(
        wallet.approve(id, namespaces).await,
        Err(Error::NoProposal(_))
    ));
}

#[cfg(feature = "ws")]
#[tokio::test]
async fn full_flow_over_websocket() {
    let server = RelayServer::new();
    let (addr, _task) = server.listen("127.0.0.1:0").await.unwrap();
    let build = |name: &str| {
        SignClient::builder(Metadata::new(name, name, "https://example.com"))
            .relay_url(format!("ws://{addr}"))
            .project_id("local")
            .options(options())
            .build()
    };
    let (dapp, _dapp_events) = build("dapp").await.unwrap();
    let (wallet, mut wallet_events) = build("wallet").await.unwrap();

    let connect = dapp
        .connect(ConnectParams {
            required_namespaces: required(),
            ..Default::default()
        })
        .await
        .unwrap();
    wallet
        .pair(&connect.uri.unwrap().to_string())
        .await
        .unwrap();
    let SignEvent::SessionProposal(proposal) = next(&mut wallet_events).await else {
        panic!("expected a proposal")
    };
    let namespaces = build_approved_namespaces(
        &proposal.required_namespaces,
        &proposal.optional_namespaces,
        &supported(),
    )
    .unwrap();
    wallet.approve(proposal.id, namespaces).await.unwrap();
    let session = connect.approval.await.unwrap();

    let topic = session.topic.clone();
    let request = tokio::spawn(async move {
        dapp.request(
            &topic,
            "eip155:1",
            SessionRequest::new("personal_sign", json!(["0x00"])),
        )
        .await
    });
    let SignEvent::SessionRequest(pending) = next(&mut wallet_events).await else {
        panic!("expected a session request")
    };
    wallet
        .respond(&session.topic, pending.id, Ok(json!("0x03")))
        .await
        .unwrap();
    assert_eq!(request.await.unwrap().unwrap(), json!("0x03"));
}
