//! Port of the `@walletconnect/sign-client` 2.26.0 test suite
//! (`packages/sign-client/test/**` in WalletConnect/walletconnect-monorepo):
//! `sdk/client.spec.ts`, `sdk/validation.spec.ts`, `sdk/persistence.spec.ts`,
//! `sdk/subscription-cleanup.spec.ts`, `sdk/transport.spec.ts`,
//! `sdk/integration/*.spec.ts` and `concurrency/concurrency.spec.ts`.
//!
//! "A" is the dapp and "B" the wallet, as in the JS suite. Everything runs
//! against the in-process [`RelayServer`] instead of a live relay. JS tests
//! that drive private engine handlers are ported by putting the equivalent
//! message on the wire with a [`RawPeer`]. Tests that exercise features this
//! crate does not implement (one-click auth, link mode, Verify, TVF,
//! telemetry events, deep links) are listed in `docs/js-test-port.md`.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::task::JoinHandle;
use wallet_connect::Error;
use wallet_connect::crypto::{KeyPair, PublicKey, SymKey, Topic};
use wallet_connect::relay::RelayServer;
use wallet_connect::rpc::{ErrorObject, Response, payload_id};
use wallet_connect::sign::{
    ApproveParams, ConnectParams, Metadata, PendingRequest, Proposal, ProposalNamespaces, SdkError,
    SessionEvent, SessionNamespaces, SessionRequest, SignClient, SignEvent, SignEvents, Snapshot,
};
use wallet_connect::time::{FIFTEEN_MINUTES, SEVEN_DAYS, now_secs};
use wallet_connect::uri::PairingUri;

use common::*;

/// `client.request(...)` in the background.
fn spawn_request(
    client: &SignClient,
    topic: &Topic,
    (chain, request): (&str, SessionRequest),
) -> JoinHandle<wallet_connect::Result<Value>> {
    let client = client.clone();
    let topic = topic.clone();
    let chain = chain.to_owned();
    tokio::spawn(async move { client.request(&topic, &chain, request).await })
}

async fn next_proposal(events: &mut SignEvents) -> Proposal {
    wait_for(events, |e| match e {
        SignEvent::SessionProposal(p) => Some(p),
        _ => None,
    })
    .await
}

async fn next_request(events: &mut SignEvents) -> PendingRequest {
    wait_for(events, |e| match e {
        SignEvent::SessionRequest(r) => Some(r),
        _ => None,
    })
    .await
}

fn protocol_code<T: std::fmt::Debug>(result: wallet_connect::Result<T>) -> i64 {
    match result {
        Err(Error::Protocol(e)) => e.code,
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

/// A snapshot as an application would persist it.
fn persisted(client: &SignClient) -> Snapshot {
    serde_json::from_str(&serde_json::to_string(&client.snapshot()).unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// sdk/client.spec.ts
// ---------------------------------------------------------------------------

mod client {
    use super::*;

    #[tokio::test]
    async fn init() {
        let server = RelayServer::new();
        // TEST_SIGN_CLIENT_OPTIONS.metadata: only a universal redirect.
        let metadata: Metadata = from_json(json!({
            "name": "App A (Proposer)",
            "description": "Description of Proposer App run by client A",
            "url": "https://walletconnect.com",
            "icons": ["https://avatars.githubusercontent.com/u/37784886"],
            "redirect": {"universal": "App A (Proposer)"},
        }));
        let (client, _) = client(&server, "init", metadata).await;
        let redirect = client.metadata().redirect.clone().unwrap();
        assert!(redirect.universal.is_some());
        assert!(redirect.native.is_none());
    }

    #[tokio::test]
    async fn should_initialize_with_empty_metadata() {
        let server = RelayServer::new();
        let (client, _) = client(&server, "init", Metadata::default()).await;
        assert_eq!(client.metadata(), &Metadata::default());
    }

    mod connect {
        use super::*;

        #[tokio::test]
        async fn connect_with_new_pairing() {
            let server = RelayServer::new();
            let (clients, connected) = init_two_paired_clients(&server).await;
            let session_a = &connected.session_a;

            let namespaces = &session_a.namespaces;
            let approved_methods: Vec<&String> =
                namespaces.values().flat_map(|ns| &ns.methods).collect();
            let approved_events: Vec<&String> =
                namespaces.values().flat_map(|ns| &ns.events).collect();
            assert!(session_a.chains().len() > 1);
            assert!(approved_methods.len() > 1);
            assert!(approved_events.len() > 1);

            assert_eq!(connected.pairing_a.topic, session_a.pairing_topic);
            let session_b = clients.b.session(&session_a.topic).unwrap();
            assert_eq!(session_b.pairing_topic, session_a.pairing_topic);
            for client in [&clients.a, &clients.b] {
                let redirect = client.metadata().redirect.clone().unwrap();
                assert!(redirect.native.is_some());
                assert!(redirect.universal.is_some());
            }
            // `expirer.keys`: one session and one pairing on each side.
            for client in [&clients.a, &clients.b] {
                assert_eq!(client.sessions().len(), 1);
                assert_eq!(client.pairings().len(), 1);
            }
        }

        #[tokio::test]
        async fn should_set_scoped_properties_in_session() {
            let server = RelayServer::new();
            let mut clients = init_two_clients(&server).await;
            let requested =
                from_json::<wallet_connect::sign::Properties>(json!({"eip155": "test"}));
            let approved =
                from_json::<wallet_connect::sign::Properties>(json!({"polkadot": "approved"}));
            let connect = clients
                .a
                .connect(ConnectParams {
                    required_namespaces: test_required_namespaces(),
                    scoped_properties: Some(requested.clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            clients
                .b
                .pair(&connect.uri.unwrap().to_string())
                .await
                .unwrap();
            let proposal = next_proposal(&mut clients.b_events).await;
            assert_eq!(proposal.scoped_properties, Some(requested));
            clients
                .b
                .approve_with(ApproveParams {
                    id: proposal.id,
                    namespaces: test_namespaces(),
                    scoped_properties: Some(approved.clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let dapp_session = connect.approval.await.unwrap();
            let wallet_session = clients.b.sessions().remove(0);
            assert_eq!(dapp_session.scoped_properties, Some(approved.clone()));
            assert_eq!(wallet_session.scoped_properties, Some(approved));
            assert_eq!(dapp_session.topic, wallet_session.topic);
        }

        #[tokio::test]
        async fn should_connect_with_out_of_order_uris() {
            let server = RelayServer::new();
            let mut clients = init_two_clients(&server).await;
            let params = || ConnectParams {
                required_namespaces: test_required_namespaces(),
                ..Default::default()
            };
            let one = clients.a.connect(params()).await.unwrap();
            let two = clients.a.connect(params()).await.unwrap();
            let three = clients.a.connect(params()).await.unwrap();

            let mut sessions = Vec::new();
            // approve the oldest, then the newest, then the middle one
            for connect in [one, three, two] {
                clients
                    .b
                    .pair(&connect.uri.unwrap().to_string())
                    .await
                    .unwrap();
                let proposal = next_proposal(&mut clients.b_events).await;
                assert_eq!(proposal.pairing_topic, connect.pairing_topic);
                clients
                    .b
                    .approve(proposal.id, test_namespaces())
                    .await
                    .unwrap();
                sessions.push(connect.approval.await.unwrap());
            }

            assert_ne!(sessions[0].topic, sessions[1].topic);
            assert_ne!(sessions[0].topic, sessions[2].topic);
            assert_ne!(sessions[1].topic, sessions[2].topic);
            assert_eq!(clients.b.sessions().len(), 3);
            for session in &sessions {
                assert!(clients.b.session(&session.topic).is_some());
            }
        }

        #[tokio::test]
        async fn should_remove_duplicate_pairing() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            assert_eq!(clients.a.pairings().len(), 1);
            assert_eq!(clients.b.pairings().len(), 1);

            let again = test_connect(&mut clients, TestConnectParams::default()).await;
            assert_ne!(again.pairing_a.topic, connected.pairing_a.topic);
            // The older pairing with the same peer is deleted on both sides.
            eventually("both sides keep only the new pairing", || {
                let a: Vec<Topic> = clients.a.pairings().into_iter().map(|p| p.topic).collect();
                let b: Vec<Topic> = clients.b.pairings().into_iter().map(|p| p.topic).collect();
                a == [again.pairing_a.topic.clone()] && b == a
            })
            .await;
            // Sessions outlive their pairings.
            assert_eq!(clients.a.sessions().len(), 2);
            assert_eq!(clients.b.sessions().len(), 2);
        }

        #[tokio::test]
        async fn should_receive_session_acknowledge() {
            let server = RelayServer::new();
            let (clients, connected) = init_two_paired_clients(&server).await;
            let session = clients.b.session(&connected.session_a.topic).unwrap();
            assert!(session.acknowledged);
            assert!(connected.session_a.acknowledged);
        }

        #[tokio::test]
        async fn should_cleanup_duplicate_pairings() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let session_a = connected.session_a;
            assert_eq!(connected.pairing_a.topic, session_a.pairing_topic);

            clients.a.disconnect(&session_a.topic).await.unwrap();
            assert!(clients.a.sessions().is_empty());
            wait_for(&mut clients.b_events, |e| match e {
                SignEvent::SessionDelete { .. } => Some(()),
                _ => None,
            })
            .await;
            assert!(clients.b.sessions().is_empty());
            assert_eq!(clients.a.pairings().len(), 1);

            let after = test_connect(&mut clients, TestConnectParams::default()).await;
            assert_ne!(connected.pairing_a.topic, after.pairing_a.topic);
            assert_ne!(session_a.topic, after.session_a.topic);
            assert_ne!(session_a.pairing_topic, after.session_a.pairing_topic);
            assert_eq!(after.session_a.pairing_topic, after.pairing_a.topic);
            eventually("A keeps a single pairing", || {
                clients.a.pairings().len() == 1
            })
            .await;
        }

        #[tokio::test]
        async fn should_emit_session_proposal_on_every_pair_attempt_with_same_uri() {
            let server = RelayServer::new();
            let (dapp, _dapp_events) = client(&server, "dapp", test_app_metadata_a()).await;
            let (wallet, mut wallet_events) =
                client(&server, "wallet", test_wallet_metadata()).await;
            let connect = dapp
                .connect(ConnectParams {
                    required_namespaces: test_required_namespaces(),
                    ..Default::default()
                })
                .await
                .unwrap();
            let uri = connect.uri.unwrap();

            // 1-3. pair, receive the proposal, neither approve nor reject it
            // (the app or modal was closed by accident).
            wallet.pair(&uri.to_string()).await.unwrap();
            let first = next_proposal(&mut wallet_events).await;
            assert_eq!(first.pairing_topic, uri.topic);

            // 4-6. pair again with the same URI: the proposal comes again.
            wallet.pair(&uri.to_string()).await.unwrap();
            let second = next_proposal(&mut wallet_events).await;
            assert_eq!(second.pairing_topic, uri.topic);
            assert_eq!(second.id, first.id);
            wallet.approve(second.id, test_namespaces()).await.unwrap();
            let session = connect.approval.await.unwrap();
            assert_eq!(session.pairing_topic, uri.topic);

            // 7-8. once approved, the URI cannot be used again.
            assert!(wallet.pair(&uri.to_string()).await.is_err());
        }

        /// JS: "should use rejected tag for session_propose" (skipped there,
        /// ported here with a relay tap).
        #[tokio::test]
        async fn should_use_rejected_tag_for_session_propose() {
            let server = RelayServer::new();
            let (dapp, _) = client(&server, "dapp", test_app_metadata_a()).await;
            let (wallet, mut wallet_events, tap) =
                tapped_client(&server, "wallet", test_wallet_metadata()).await;
            let connect = dapp
                .connect(ConnectParams {
                    required_namespaces: test_required_namespaces(),
                    ..Default::default()
                })
                .await
                .unwrap();
            wallet
                .pair(&connect.uri.unwrap().to_string())
                .await
                .unwrap();
            let proposal = next_proposal(&mut wallet_events).await;
            tap.clear();
            wallet
                .reject(proposal.id, SdkError::UserRejected)
                .await
                .unwrap();
            let published = tap.published();
            assert_eq!(published.len(), 1);
            // ENGINE_RPC_OPTS.wc_sessionPropose.reject
            assert_eq!(published[0].tag, 1120);
            assert_eq!(published[0].ttl, 300);
            assert_eq!(published[0].prompt, None);
            assert!(matches!(connect.approval.await, Err(Error::Peer(e)) if e.code == 5000));
        }

        /// The publish options of every leg of a session, as in
        /// `ENGINE_RPC_OPTS` (the JS tests check them through
        /// `relayer.publish` events and the `wc_proposeSession` /
        /// `wc_approveSession` payloads).
        #[tokio::test]
        async fn publishes_with_the_reference_rpc_options() {
            let server = RelayServer::new();
            let (a, a_events, tap_a) =
                tapped_client(&server, "client_a", test_app_metadata_a()).await;
            let (b, b_events, tap_b) =
                tapped_client(&server, "client_b", test_app_metadata_b()).await;
            let mut clients = Clients {
                a,
                a_events,
                b,
                b_events,
            };
            let connected = test_connect(&mut clients, TestConnectParams::default()).await;
            let topic = connected.session_a.topic.clone();
            let request = spawn_request(&clients.a, &topic, test_request_params());
            let pending = next_request(&mut clients.b_events).await;
            clients
                .b
                .respond(&topic, pending.id, Ok(json!("0x")))
                .await
                .unwrap();
            request.await.unwrap().unwrap();

            let opts = |tap: &Tap| -> Vec<(u32, u64, Option<bool>)> {
                tap.published()
                    .into_iter()
                    .map(|p| (p.tag, p.ttl, p.prompt))
                    .collect()
            };
            // dapp: propose (1100, prompt), settle ack (1103), request (1108, prompt)
            assert_eq!(
                opts(&tap_a),
                [
                    (1100, 300, Some(true)),
                    (1103, 300, None),
                    (1108, 900, Some(true))
                ]
            );
            // wallet: propose response (1101), settle (1102), request response (1109)
            assert_eq!(
                opts(&tap_b),
                [(1101, 300, None), (1102, 300, None), (1109, 900, None)]
            );
        }

        /// `ENGINE_RPC_OPTS.wc_sessionPropose.autoReject`: an invalid proposal
        /// is rejected with tag 1121.
        #[tokio::test]
        async fn should_use_auto_reject_tag_for_invalid_proposals() {
            let server = RelayServer::new();
            let (wallet, mut wallet_events, tap) =
                tapped_client(&server, "wallet", test_wallet_metadata()).await;
            let mut dapp = RawPeer::connect(&server, "dapp").await;
            let pairing_key = SymKey::generate();
            let uri = PairingUri::new(pairing_key.clone(), now_secs() + 300);
            dapp.subscribe(&uri.topic, pairing_key).await;
            let id = payload_id();
            dapp.request(
                &uri.topic,
                id,
                "wc_sessionPropose",
                json!({
                    "relays": [{"protocol": "irn"}],
                    "proposer": {"publicKey": KeyPair::generate().public_key(), "metadata": test_app_metadata_a()},
                    // no chains: invalid
                    "requiredNamespaces": {"eip155": {"methods": [], "events": []}},
                    "optionalNamespaces": {},
                    "expiryTimestamp": now_secs() + 300,
                }),
            )
            .await;
            wallet.pair(&uri.to_string()).await.unwrap();
            let response = dapp.next_response(&uri.topic).await;
            assert_eq!(response.id, id);
            assert_eq!(response.outcome.unwrap_err().code, 5100);
            assert_eq!(tap.published().last().unwrap().tag, 1121);
            assert_no_event(&mut wallet_events, Duration::from_millis(200), |e| {
                matches!(e, SignEvent::SessionProposal(_))
            })
            .await;
            assert!(wallet.proposals().is_empty());
        }
    }

    mod disconnect {
        use super::*;

        #[tokio::test]
        async fn deletes_the_pairing_on_disconnect() {
            let server = RelayServer::new();
            let (clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.pairing_a.topic;
            clients.a.disconnect(&topic).await.unwrap();
            assert!(find_pairing(&clients.a, &topic).is_none());
            assert!(matches!(
                clients.a.ping(&topic).await,
                Err(Error::NoSession(_))
            ));
        }

        #[tokio::test]
        async fn deletes_the_session_on_disconnect() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            assert!(sym_key(&clients.a, &topic).is_some());
            assert!(sym_key(&clients.b, &topic).is_some());
            // Neither side keeps the X25519 secret once the session is settled.
            assert!(key_pairs(&clients.a).is_empty());
            assert!(key_pairs(&clients.b).is_empty());

            clients.a.disconnect(&topic).await.unwrap();
            assert!(clients.a.session(&topic).is_none());
            assert!(matches!(
                clients.a.ping(&topic).await,
                Err(Error::NoSession(_))
            ));
            wait_for(&mut clients.b_events, |e| match e {
                SignEvent::SessionDelete {
                    topic: t, reason, ..
                } if t == topic => Some(reason),
                _ => None,
            })
            .await;
            assert_eq!(sym_key(&clients.a, &topic), None);
            assert_eq!(sym_key(&clients.b, &topic), None);
            assert!(clients.b.session(&topic).is_none());
        }

        /// JS: "should reset request queue state on disconnect".
        #[tokio::test]
        async fn drops_pending_requests_on_disconnect() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let request = spawn_request(&clients.a, &topic, test_request_params());
            next_request(&mut clients.b_events).await;
            assert_eq!(clients.b.pending_requests().len(), 1);

            clients.a.disconnect(&topic).await.unwrap();
            wait_for(&mut clients.b_events, |e| match e {
                SignEvent::SessionDelete { .. } => Some(()),
                _ => None,
            })
            .await;
            assert!(clients.b.pending_requests().is_empty());
            // The dapp's own pending request ends with the session.
            assert!(request.await.unwrap().is_err());
        }
    }

    mod ping {
        use super::*;

        #[tokio::test]
        async fn throws_if_the_topic_is_not_a_known_pairing_or_session_topic() {
            let server = RelayServer::new();
            let clients = init_two_clients(&server).await;
            assert!(matches!(
                clients.a.ping(&Topic::new("nonsense")).await,
                Err(Error::NoSession(_))
            ));
        }

        async fn ping(from: &SignClient, to_events: &mut SignEvents, topic: &Topic, pairing: bool) {
            from.ping(topic).await.unwrap();
            wait_for(to_events, |e| match e {
                SignEvent::PairingPing { topic: t, .. } if pairing && &t == topic => Some(()),
                SignEvent::SessionPing { topic: t, .. } if !pairing && &t == topic => Some(()),
                _ => None,
            })
            .await;
        }

        #[tokio::test]
        async fn pairing_a_pings_b_and_b_pings_a() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.pairing_a.topic;
            ping(&clients.a, &mut clients.b_events, &topic, true).await;
            ping(&clients.b, &mut clients.a_events, &topic, true).await;
        }

        #[tokio::test]
        async fn session_a_pings_b_and_b_pings_a() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            ping(&clients.a, &mut clients.b_events, &topic, false).await;
            ping(&clients.b, &mut clients.a_events, &topic, false).await;
        }
    }

    mod session_requests {
        use super::*;

        #[tokio::test]
        async fn can_get_pending_session_request() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let request = spawn_request(&clients.a, &topic, test_request_params());

            let event = next_request(&mut clients.b_events).await;
            let pending = clients.b.pending_requests();
            assert_eq!(pending, std::slice::from_ref(&event));
            assert_eq!(pending[0].topic, topic);
            let rejection = SdkError::UserRejectedMethods.error();
            clients
                .b
                .respond(&topic, event.id, Err(rejection.clone()))
                .await
                .unwrap();
            match request.await.unwrap() {
                Err(Error::Peer(e)) => assert_eq!(e.message, rejection.message),
                other => panic!("{other:?}"),
            }
            assert!(clients.b.pending_requests().is_empty());
        }

        #[tokio::test]
        async fn should_process_requests_queue() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let requests: Vec<_> = (0..5)
                .map(|_| spawn_request(&clients.a, &topic, test_request_params()))
                .collect();
            for _ in 0..5 {
                let pending = next_request(&mut clients.b_events).await;
                clients
                    .b
                    .respond(&pending.topic, pending.id, Ok(json!("ok")))
                    .await
                    .unwrap();
            }
            for request in requests {
                assert_eq!(request.await.unwrap().unwrap(), json!("ok"));
            }
        }

        /// JS: "should disable requests queue via `signConfig`". This crate
        /// never queues: every request is emitted as soon as it arrives, as
        /// with `disableRequestQueue: true`.
        #[tokio::test]
        async fn requests_are_emitted_without_waiting_for_earlier_answers() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;

            let first_request = spawn_request(&clients.a, &topic, test_request_params());
            let first = next_request(&mut clients.b_events).await;
            assert_eq!(clients.b.pending_requests().len(), 1);

            let second_request = spawn_request(&clients.a, &topic, test_request_params());
            let second = next_request(&mut clients.b_events).await;
            assert_ne!(second.id, first.id);
            assert_eq!(clients.b.pending_requests().len(), 2);
            clients
                .b
                .respond(&topic, second.id, Ok(json!("ok")))
                .await
                .unwrap();
            assert_eq!(second_request.await.unwrap().unwrap(), json!("ok"));

            let still_pending = clients.b.pending_requests();
            assert_eq!(still_pending.len(), 1);
            assert_eq!(still_pending[0].id, first.id);
            clients
                .b
                .respond(&topic, first.id, Ok(json!("ok")))
                .await
                .unwrap();
            assert_eq!(first_request.await.unwrap().unwrap(), json!("ok"));
        }

        /// JS: "continue processing requests queue after respond rejection
        /// due to disconnected session".
        #[tokio::test]
        async fn continue_processing_requests_after_a_session_is_disconnected() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic_a = connected.session_a.topic;

            let connect = clients.a.connect(ConnectParams::default()).await.unwrap();
            clients
                .b
                .pair(&connect.uri.unwrap().to_string())
                .await
                .unwrap();
            let proposal = next_proposal(&mut clients.b_events).await;
            clients
                .b
                .approve(proposal.id, test_namespaces())
                .await
                .unwrap();
            let topic_b = connect.approval.await.unwrap().topic;

            let on_a: Vec<_> = (0..5)
                .map(|_| spawn_request(&clients.a, &topic_a, test_request_params()))
                .collect();
            let on_b = spawn_request(&clients.a, &topic_b, test_request_params());

            for _ in 0..6 {
                let pending = next_request(&mut clients.b_events).await;
                if pending.topic == topic_b {
                    // Disconnect while the request is being handled...
                    clients.b.disconnect(&topic_b).await.unwrap();
                    // ...so answering it fails.
                    assert!(
                        clients
                            .b
                            .respond(&topic_b, pending.id, Ok(json!("ok")))
                            .await
                            .is_err()
                    );
                } else {
                    clients
                        .b
                        .respond(&pending.topic, pending.id, Ok(json!("ok")))
                        .await
                        .unwrap();
                }
            }
            for request in on_a {
                assert_eq!(request.await.unwrap().unwrap(), json!("ok"));
            }
            match on_b.await.unwrap() {
                Err(Error::Peer(e)) => assert_eq!(e.code, SdkError::UserDisconnected.code()),
                other => panic!("{other:?}"),
            }
            assert!(clients.b.pending_requests().is_empty());
        }

        #[tokio::test]
        async fn should_set_custom_request_expiry() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let expiry = 600; // 10 minutes in seconds
            let (chain, mut request) = test_request_params();
            request.expiry_timestamp = Some(now_secs() + expiry);
            let request = spawn_request(&clients.a, &topic, (chain, request));

            let pending = next_request(&mut clients.b_events).await;
            let got = pending.request.expiry_timestamp.unwrap();
            assert!(got.abs_diff(now_secs() + expiry) <= 2, "{got}");
            clients
                .b
                .respond(&topic, pending.id, Ok(json!("test response")))
                .await
                .unwrap();
            assert_eq!(request.await.unwrap().unwrap(), json!("test response"));
        }

        #[tokio::test]
        async fn should_send_request_on_optional_namespace() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let request =
                spawn_request(&clients.a, &topic, test_request_params_optional_namespace());
            let pending = next_request(&mut clients.b_events).await;
            assert_eq!(pending.chain_id, TEST_POLKADOT_CHAIN);
            assert_eq!(pending.request.method, TEST_POLKADOT_METHODS[0]);
            assert_eq!(pending.request.params, json!([]));
            clients
                .b
                .respond(&topic, pending.id, Ok(json!("test response")))
                .await
                .unwrap();
            assert_eq!(request.await.unwrap().unwrap(), json!("test response"));
        }

        #[tokio::test]
        async fn should_throw_an_error_when_responding_to_request_on_mismatched_topic() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            // A second session to answer on by mistake.
            let other = test_connect(&mut clients, TestConnectParams::default())
                .await
                .session_a
                .topic;

            let request =
                spawn_request(&clients.a, &topic, test_request_params_optional_namespace());
            let pending = next_request(&mut clients.b_events).await;
            let mismatched = clients
                .b
                .respond(&other, pending.id, Ok(json!("test response")))
                .await;
            match mismatched {
                Err(Error::Protocol(e)) => {
                    assert_eq!(e.code, 8);
                    assert!(e.message.starts_with("Mismatched topic."), "{}", e.message);
                }
                other => panic!("{other:?}"),
            }
            // The request is still pending and can be answered on the right topic.
            clients
                .b
                .respond(&topic, pending.id, Ok(json!("test response")))
                .await
                .unwrap();
            assert_eq!(request.await.unwrap().unwrap(), json!("test response"));
        }

        #[tokio::test]
        async fn should_send_request_on_inline_indexed_namespace() {
            let server = RelayServer::new();
            let mut clients = init_two_clients(&server).await;
            let connected = test_connect(
                &mut clients,
                TestConnectParams {
                    optional_namespaces: test_required_namespaces_v2(),
                    namespaces: test_namespaces_v2(),
                    ..Default::default()
                },
            )
            .await;
            let topic = connected.session_a.topic;
            let (_, request) = test_request_params();
            let request = spawn_request(&clients.a, &topic, (TEST_AVALANCHE_CHAIN, request));
            let pending = next_request(&mut clients.b_events).await;
            assert_eq!(pending.chain_id, TEST_AVALANCHE_CHAIN);
            let session = clients.b.session(&pending.topic).unwrap();
            assert!(
                session.namespaces["eip155"]
                    .accounts
                    .iter()
                    .any(|a| a.starts_with(TEST_AVALANCHE_CHAIN))
            );
            clients
                .b
                .respond(&topic, pending.id, Ok(json!("test response")))
                .await
                .unwrap();
            assert_eq!(request.await.unwrap().unwrap(), json!("test response"));
        }

        /// JS: "should set default request expiry to 15 minutes and respect
        /// dApp expiryTimestamp".
        #[tokio::test]
        async fn should_set_default_request_expiry_to_15_minutes() {
            assert_eq!(FIFTEEN_MINUTES, 900);
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let request = spawn_request(&clients.a, &topic, test_request_params());
            let pending = next_request(&mut clients.b_events).await;
            let expiry = pending.request.expiry_timestamp.unwrap();
            assert!(
                expiry.abs_diff(now_secs() + FIFTEEN_MINUTES) <= 5,
                "{expiry}"
            );
            clients
                .b
                .respond(
                    &topic,
                    pending.id,
                    Ok(json!("test response after 14 minutes")),
                )
                .await
                .unwrap();
            assert_eq!(
                request.await.unwrap().unwrap(),
                json!("test response after 14 minutes")
            );
        }

        /// JS: "should respect dApp expiryTimestamp even when wallet uses old
        /// 5-min config". The wallet times a pending request out at the
        /// dapp's `expiryTimestamp`, whatever it is, not by a local default.
        #[tokio::test]
        async fn wallet_expires_pending_requests_at_the_dapps_expiry_timestamp() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            // Speak for the dapp: the relay does not echo to the publisher's
            // client id, so only the wallet sees the crafted request.
            let mut dapp = RawPeer::connect(&server, "client_a").await;
            dapp.add_key(&topic, sym_key(&clients.a, &topic).unwrap());
            let id = payload_id();
            dapp.request(
                &topic,
                id,
                "wc_sessionRequest",
                json!({
                    "request": {"method": TEST_METHODS[0], "params": [], "expiryTimestamp": now_secs() + 2},
                    "chainId": TEST_CHAINS[0],
                }),
            )
            .await;
            let pending = next_request(&mut clients.b_events).await;
            assert_eq!(pending.id, id);
            wait_for(&mut clients.b_events, |e| match e {
                SignEvent::SessionRequestExpire { id: expired, .. } if expired == id => Some(()),
                _ => None,
            })
            .await;
            assert!(clients.b.pending_requests().is_empty());
            assert!(matches!(
                clients.b.respond(&topic, id, Ok(json!("late"))).await,
                Err(Error::NoRequest(_))
            ));
        }
    }

    mod update {
        use super::*;

        fn with_eip9001(namespaces: &SessionNamespaces) -> SessionNamespaces {
            let mut after = namespaces.clone();
            after.insert(
                "eip9001".into(),
                from_json(json!({
                    "accounts": ["eip9001:1:0x000000000000000000000000000000000000dead"],
                    "methods": ["eth_sendTransaction"],
                    "events": ["accountsChanged"],
                })),
            );
            after
        }

        #[tokio::test]
        async fn updates_session_namespaces_state_with_provided_namespaces() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let after = with_eip9001(&clients.a.session(&topic).unwrap().namespaces);
            let acknowledged = clients.b.update(&topic, after.clone()).await.unwrap();
            acknowledged.await.unwrap();
            assert_eq!(clients.a.session(&topic).unwrap().namespaces, after);
            let event = wait_for(&mut clients.a_events, |e| match e {
                SignEvent::SessionUpdate { namespaces, .. } => Some(namespaces),
                _ => None,
            })
            .await;
            assert_eq!(event, after);
        }

        #[tokio::test]
        async fn should_reject_update_from_non_controller_peer() {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let before = clients.b.session(&topic).unwrap().namespaces;

            // The dapp (not the controller) sends wc_sessionUpdate.
            let mut dapp = RawPeer::connect(&server, "client_a").await;
            dapp.subscribe(&topic, sym_key(&clients.a, &topic).unwrap())
                .await;
            let id = payload_id();
            dapp.request(
                &topic,
                id,
                "wc_sessionUpdate",
                json!({"namespaces": with_eip9001(&before)}),
            )
            .await;
            let response = dapp.next_response(&topic).await;
            assert_eq!(response.id, id);
            assert_eq!(
                response.outcome.unwrap_err(),
                SdkError::UnauthorizedUpdateRequest.error()
            );
            assert_no_event(&mut clients.b_events, Duration::from_millis(200), |e| {
                matches!(e, SignEvent::SessionUpdate { .. })
            })
            .await;
            assert_eq!(clients.b.session(&topic).unwrap().namespaces, before);
        }
    }

    mod namespaces {
        use super::*;

        #[tokio::test]
        async fn should_pair_with_empty_namespaces() {
            let server = RelayServer::new();
            let mut clients = init_two_clients(&server).await;
            let connected = test_connect(
                &mut clients,
                TestConnectParams {
                    required_namespaces: BTreeMap::new(),
                    namespaces: test_namespaces(),
                    ..Default::default()
                },
            )
            .await;
            assert!(connected.session_a.required_namespaces.is_empty());
            assert_eq!(
                connected.session_a.required_namespaces,
                connected.session_b.required_namespaces
            );
        }
    }

    mod extend {
        use super::*;

        async fn extend_from(dapp_initiates: bool) {
            let server = RelayServer::new();
            let (mut clients, connected) = init_two_paired_clients(&server).await;
            let topic = connected.session_a.topic;
            let prev_a = clients.a.session(&topic).unwrap().expiry;
            let prev_b = clients.b.session(&topic).unwrap().expiry;
            // JS fast-forwards the clock by a minute; expiries have a
            // one-second resolution, so a second is enough here.
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let (from, peer_events) = if dapp_initiates {
                (&clients.a, &mut clients.b_events)
            } else {
                (&clients.b, &mut clients.a_events)
            };
            let acknowledged = from.extend(&topic).await.unwrap();
            acknowledged.await.unwrap();
            wait_for(peer_events, |e| match e {
                SignEvent::SessionExtend { topic: t, .. } if t == topic => Some(()),
                _ => None,
            })
            .await;
            let updated_a = clients.a.session(&topic).unwrap().expiry;
            let updated_b = clients.b.session(&topic).unwrap().expiry;
            assert!(updated_a > prev_a);
            assert!(updated_b > prev_b);
            assert!(updated_a.abs_diff(now_secs() + SEVEN_DAYS) <= 2);
            assert!(updated_b.abs_diff(now_secs() + SEVEN_DAYS) <= 2);
        }

        #[tokio::test]
        async fn updates_session_expiry_state_initiated_by_client_a() {
            extend_from(true).await;
        }

        #[tokio::test]
        async fn updates_session_expiry_state_initiated_by_client_b() {
            extend_from(false).await;
        }
    }

    /// JS: "should create event during pairing flow" checks that the
    /// proposal ends as `proposal_expired`; the wallet drops it and tells
    /// the application.
    #[tokio::test]
    async fn proposal_expires_on_the_wallet() {
        let server = RelayServer::new();
        let (wallet, mut wallet_events) = client(&server, "wallet", test_wallet_metadata()).await;
        let mut dapp = RawPeer::connect(&server, "dapp").await;
        let pairing_key = SymKey::generate();
        let uri = PairingUri::new(pairing_key.clone(), now_secs() + 300);
        dapp.subscribe(&uri.topic, pairing_key).await;
        let id = payload_id();
        dapp.request(
            &uri.topic,
            id,
            "wc_sessionPropose",
            json!({
                "relays": [{"protocol": "irn"}],
                "proposer": {"publicKey": KeyPair::generate().public_key(), "metadata": test_app_metadata_a()},
                "requiredNamespaces": {},
                "optionalNamespaces": test_optional_namespaces(),
                "expiryTimestamp": now_secs() + 2,
                "pairingTopic": uri.topic,
            }),
        )
        .await;
        wallet.pair(&uri.to_string()).await.unwrap();
        assert_eq!(next_proposal(&mut wallet_events).await.id, id);
        wait_for(&mut wallet_events, |e| match e {
            SignEvent::ProposalExpire { id: expired } if expired == id => Some(()),
            _ => None,
        })
        .await;
        assert!(wallet.proposals().is_empty());
        assert!(matches!(
            wallet.approve(id, test_namespaces()).await,
            Err(Error::NoProposal(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// sdk/validation.spec.ts
// ---------------------------------------------------------------------------

mod validation {
    use super::*;

    struct Fixture {
        clients: Clients,
        topic: Topic,
        pairing_topic: Topic,
        server: RelayServer,
    }

    /// `beforeAll`: two paired clients with one session.
    async fn fixture() -> Fixture {
        let server = RelayServer::new();
        let (clients, connected) = init_two_paired_clients(&server).await;
        Fixture {
            clients,
            topic: connected.session_a.topic,
            pairing_topic: connected.pairing_a.topic,
            server,
        }
    }

    /// A proposal the wallet (B) has received and not yet answered.
    async fn pending_proposal(f: &mut Fixture, params: ConnectParams) -> Proposal {
        let connect = f.clients.a.connect(params).await.unwrap();
        f.clients
            .b
            .pair(&connect.uri.unwrap().to_string())
            .await
            .unwrap();
        next_proposal(&mut f.clients.b_events).await
    }

    mod connect {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_pairing_topic_is_provided() {
            let f = fixture().await;
            let result = f
                .clients
                .a
                .connect(ConnectParams {
                    required_namespaces: test_required_namespaces(),
                    pairing_topic: Some(Topic::new("none")),
                    ..Default::default()
                })
                .await;
            assert!(matches!(result, Err(Error::NoPairing(t)) if t == "none"));
            // An existing pairing works.
            let ok = f
                .clients
                .a
                .connect(ConnectParams {
                    pairing_topic: Some(f.pairing_topic.clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert!(ok.uri.is_none());
        }

        #[tokio::test]
        async fn throws_when_no_chains_are_specified_within_required_or_optional_namespaces() {
            let f = fixture().await;
            let no_chains: ProposalNamespaces = from_json(json!({"eip155": {"chains": []}}));
            for params in [
                ConnectParams {
                    required_namespaces: no_chains.clone(),
                    ..Default::default()
                },
                ConnectParams {
                    optional_namespaces: no_chains.clone(),
                    ..Default::default()
                },
            ] {
                match f.clients.a.connect(params).await {
                    Err(Error::Protocol(e)) => {
                        assert_eq!(e.code, 5100);
                        assert!(
                            e.message.contains(
                                r#"chains must be defined as "namespace:chainId" e.g. "eip155:1": {...} in the namespace key OR as an array of CAIP-2 chainIds"#
                            ),
                            "{}",
                            e.message
                        );
                    }
                    other => panic!("{other:?}"),
                }
            }
        }

        #[tokio::test]
        async fn should_create_pairing_with_inline_defined_chain() {
            let f = fixture().await;
            let connect = f
                .clients
                .a
                .connect(ConnectParams {
                    optional_namespaces: from_json(
                        json!({"eip155:1": {"methods": [], "events": []}}),
                    ),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert!(connect.uri.unwrap().to_string().starts_with("wc:"));
        }

        #[tokio::test]
        async fn should_reject_connect_with_scoped_properties_not_in_namespaces() {
            let f = fixture().await;
            let result = f
                .clients
                .a
                .connect(ConnectParams {
                    scoped_properties: Some(from_json(json!({"eip155:1": {}}))),
                    ..Default::default()
                })
                .await;
            match result {
                Err(Error::Protocol(e)) => assert!(
                    e.message.contains(
                        "Scoped properties must be a subset of required/optional namespaces"
                    ),
                    "{}",
                    e.message
                ),
                other => panic!("{other:?}"),
            }
            // Inline chain keys count by their namespace.
            f.clients
                .a
                .connect(ConnectParams {
                    optional_namespaces: test_optional_namespaces(),
                    scoped_properties: Some(from_json(
                        json!({"polkadot:91b171bb158e2d3848fa23a9f1c25182": {}}),
                    )),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn should_reject_session_properties_without_a_value() {
            let f = fixture().await;
            let result = f
                .clients
                .a
                .connect(ConnectParams {
                    session_properties: Some(from_json(json!({"caip154-mandatory": null}))),
                    ..Default::default()
                })
                .await;
            assert_eq!(protocol_code(result), 5);
        }
    }

    mod approve {
        use super::*;

        #[tokio::test]
        async fn should_reject_approve_with_scoped_properties_not_in_namespaces() {
            let mut f = fixture().await;
            let proposal = pending_proposal(
                &mut f,
                ConnectParams {
                    required_namespaces: test_required_namespaces(),
                    ..Default::default()
                },
            )
            .await;
            let result = f
                .clients
                .b
                .approve_with(ApproveParams {
                    id: proposal.id,
                    namespaces: test_namespaces(),
                    scoped_properties: Some(from_json(json!({"solana": "test"}))),
                    ..Default::default()
                })
                .await;
            match result {
                Err(Error::Protocol(e)) => assert!(
                    e.message
                        .contains("Scoped properties must be a subset of approved namespaces"),
                    "{}",
                    e.message
                ),
                other => panic!("{other:?}"),
            }
            // The proposal survives a failed validation.
            assert_eq!(f.clients.b.proposals().len(), 1);
        }

        #[tokio::test]
        async fn throws_when_non_existent_id_is_provided() {
            let f = fixture().await;
            assert!(matches!(
                f.clients.b.approve(123, test_namespaces()).await,
                Err(Error::NoProposal(123))
            ));
        }

        #[tokio::test]
        async fn throws_when_empty_namespaces_are_provided() {
            let mut f = fixture().await;
            let proposal = pending_proposal(&mut f, ConnectParams::default()).await;
            let result = f.clients.b.approve(proposal.id, BTreeMap::new()).await;
            match result {
                Err(Error::Protocol(e)) => {
                    assert_eq!(e.code, 5);
                    assert!(
                        e.message
                            .contains("namespaces should be an object with data")
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }

    mod reject {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_id_is_provided() {
            let f = fixture().await;
            assert!(matches!(
                f.clients.b.reject(123, SdkError::UserRejected).await,
                Err(Error::NoProposal(123))
            ));
        }

        #[tokio::test]
        async fn throws_when_invalid_reason_is_provided() {
            let mut f = fixture().await;
            let proposal = pending_proposal(&mut f, ConnectParams::default()).await;
            // TEST_REJECT_PARAMS.reason is {code: 0, message: "GENERIC"}: a
            // zero code, or an empty message, is not a valid reason.
            for reason in [
                ErrorObject::new(0, "GENERIC"),
                ErrorObject::new(5000, ""),
                ErrorObject::new(5000, "  "),
            ] {
                let result = f.clients.b.reject(proposal.id, reason.clone()).await;
                assert_eq!(protocol_code(result), 5, "{reason:?}");
            }
            // Still pending, so a valid reason goes through.
            f.clients
                .b
                .reject(proposal.id, SdkError::UserRejected)
                .await
                .unwrap();
        }
    }

    mod update {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_topic_is_provided() {
            let f = fixture().await;
            assert!(matches!(
                f.clients
                    .b
                    .update(&Topic::new("none"), test_namespaces())
                    .await,
                Err(Error::NoSession(_))
            ));
        }

        #[tokio::test]
        async fn throws_when_empty_namespaces_are_provided() {
            let f = fixture().await;
            match f.clients.b.update(&f.topic, BTreeMap::new()).await {
                Err(Error::Protocol(e)) => {
                    assert_eq!(e.code, 5);
                    assert!(
                        e.message
                            .contains("namespaces should be an object with data")
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }

    mod extend {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_topic_is_provided() {
            let f = fixture().await;
            assert!(matches!(
                f.clients.a.extend(&Topic::new("none")).await,
                Err(Error::NoSession(_))
            ));
        }
    }

    mod request {
        use super::*;

        /// JS: "should emit session_request event once" (calls
        /// `engine.emitSessionRequest` 100 times with the same request).
        #[tokio::test]
        async fn should_emit_session_request_event_once() {
            let mut f = fixture().await;
            let mut dapp = RawPeer::connect(&f.server, "client_a").await;
            dapp.add_key(&f.topic, sym_key(&f.clients.a, &f.topic).unwrap());
            let id = payload_id();
            let params = json!({
                "request": {"method": TEST_METHODS[0], "params": [], "expiryTimestamp": now_secs() + 300},
                "chainId": TEST_CHAINS[0],
            });
            // Each publish is a fresh ciphertext (random IV) of the same request.
            for _ in 0..10 {
                dapp.request(&f.topic, id, "wc_sessionRequest", params.clone())
                    .await;
            }
            assert_eq!(next_request(&mut f.clients.b_events).await.id, id);
            assert_no_event(&mut f.clients.b_events, Duration::from_millis(300), |e| {
                matches!(e, SignEvent::SessionRequest(_))
            })
            .await;
            assert_eq!(f.clients.b.pending_requests().len(), 1);
        }

        #[tokio::test]
        async fn throws_when_non_existent_topic_is_provided() {
            let f = fixture().await;
            assert!(matches!(
                f.clients
                    .a
                    .request(&Topic::new("none"), TEST_CHAINS[0], test_request_params().1)
                    .await,
                Err(Error::NoSession(_))
            ));
        }

        #[tokio::test]
        async fn throws_when_chain_id_is_empty_or_not_in_session_namespace() {
            let f = fixture().await;
            for chain in ["", "eip000:0", "eip155:5"] {
                let result = f
                    .clients
                    .a
                    .request(&f.topic, chain, test_request_params().1)
                    .await;
                assert_eq!(protocol_code(result), 5100, "{chain}");
            }
        }

        #[tokio::test]
        async fn throws_when_method_is_empty_or_not_in_session_namespace() {
            let f = fixture().await;
            for method in ["", "unknown"] {
                let result = f
                    .clients
                    .a
                    .request(
                        &f.topic,
                        TEST_CHAINS[0],
                        SessionRequest::new(method, json!([])),
                    )
                    .await;
                assert_eq!(protocol_code(result), 3001, "{method}");
            }
        }

        #[tokio::test]
        async fn throws_when_invalid_expiry_is_provided() {
            let f = fixture().await;
            for ttl in [10, 299, SEVEN_DAYS + 60] {
                let (chain, mut request) = test_request_params();
                request.expiry_timestamp = Some(now_secs() + ttl);
                match f.clients.a.request(&f.topic, chain, request).await {
                    Err(Error::Protocol(e)) => {
                        assert_eq!(e.code, 5);
                        assert!(
                            e.message.contains("between 300 and 604800"),
                            "{}",
                            e.message
                        );
                    }
                    other => panic!("{ttl}: {other:?}"),
                }
            }
        }
    }

    mod respond {
        use super::*;

        #[tokio::test]
        async fn throws_when_the_request_does_not_exist() {
            let f = fixture().await;
            assert!(matches!(
                f.clients.b.respond(&f.topic, 1, Ok(json!({}))).await,
                Err(Error::NoRequest(1))
            ));
        }
    }

    mod ping {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_topic_is_provided() {
            let f = fixture().await;
            for topic in ["", "none"] {
                assert!(matches!(
                    f.clients.a.ping(&Topic::new(topic)).await,
                    Err(Error::NoSession(_))
                ));
            }
        }
    }

    mod emit {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_topic_is_provided() {
            let f = fixture().await;
            let (chain, event) = test_emit_params();
            assert!(matches!(
                f.clients.b.emit(&Topic::new("none"), chain, event).await,
                Err(Error::NoSession(_))
            ));
        }

        #[tokio::test]
        async fn throws_when_chain_id_is_empty() {
            let f = fixture().await;
            let (_, event) = test_emit_params();
            assert_eq!(
                protocol_code(f.clients.b.emit(&f.topic, "", event).await),
                5100
            );
        }

        #[tokio::test]
        async fn throws_when_event_name_is_empty_or_unknown() {
            let f = fixture().await;
            for name in ["", "unknown"] {
                let result = f
                    .clients
                    .b
                    .emit(&f.topic, TEST_CHAINS[0], SessionEvent::new(name, json!("")))
                    .await;
                assert_eq!(protocol_code(result), 3002, "{name}");
            }
        }
    }

    mod disconnect {
        use super::*;

        #[tokio::test]
        async fn throws_when_non_existent_topic_is_provided() {
            let f = fixture().await;
            for topic in ["", "none"] {
                assert!(matches!(
                    f.clients.a.disconnect(&Topic::new(topic)).await,
                    Err(Error::NoSession(_))
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// sdk/persistence.spec.ts
// ---------------------------------------------------------------------------

mod persistence {
    use super::*;

    async fn restart(
        server: &RelayServer,
        client: SignClient,
        client_id: &str,
    ) -> (SignClient, SignEvents) {
        let snapshot = persisted(&client);
        let metadata = client.metadata().clone();
        client.shutdown();
        drop(client);
        client_with(server, client_id, metadata, Some(snapshot)).await
    }

    async fn ping_both_ways(clients: &mut Clients, topic: &Topic) {
        clients.a.ping(topic).await.unwrap();
        wait_for(&mut clients.b_events, |e| match e {
            SignEvent::SessionPing { topic: t, .. } if &t == topic => Some(()),
            _ => None,
        })
        .await;
        clients.b.ping(topic).await.unwrap();
        wait_for(&mut clients.a_events, |e| match e {
            SignEvent::SessionPing { topic: t, .. } if &t == topic => Some(()),
            _ => None,
        })
        .await;
    }

    #[tokio::test]
    async fn clients_can_ping_each_other_after_restart() {
        let server = RelayServer::new();
        let (mut clients, connected) = init_two_paired_clients(&server).await;
        let topic = connected.session_a.topic;
        ping_both_ways(&mut clients, &topic).await;

        let Clients { a, b, .. } = clients;
        let (a, a_events) = restart(&server, a, "client_a").await;
        let (b, b_events) = restart(&server, b, "client_b").await;
        let mut clients = Clients {
            a,
            a_events,
            b,
            b_events,
        };
        ping_both_ways(&mut clients, &topic).await;
    }

    #[tokio::test]
    async fn should_respond_to_pending_request_after_restart() {
        let server = RelayServer::new();
        let (clients, connected) = init_two_paired_clients(&server).await;
        let topic = connected.session_a.topic;
        let snapshot = persisted(&clients.b);
        clients.b.shutdown();

        let request = spawn_request(&clients.a, &topic, test_request_params());
        tokio::time::sleep(Duration::from_millis(200)).await;

        let (wallet, mut wallet_events) =
            client_with(&server, "client_b", test_app_metadata_b(), Some(snapshot)).await;
        let event = next_request(&mut wallet_events).await;
        let pending = wallet.pending_requests();
        assert_eq!(pending, std::slice::from_ref(&event));
        let rejection = SdkError::UserRejectedMethods.error();
        wallet
            .respond(&topic, event.id, Err(rejection.clone()))
            .await
            .unwrap();
        match request.await.unwrap() {
            Err(Error::Peer(e)) => assert_eq!(e.message, rejection.message),
            other => panic!("{other:?}"),
        }
        // The pending request was received only once.
        assert_no_event(&mut wallet_events, Duration::from_millis(300), |e| {
            matches!(e, SignEvent::SessionRequest(_))
        })
        .await;
    }

    #[tokio::test]
    async fn should_complete_a_session_after_dapp_restart() {
        let server = RelayServer::new();
        let mut clients = init_two_clients(&server).await;
        let connect = clients.a.connect(ConnectParams::default()).await.unwrap();
        let uri = connect.uri.unwrap();
        drop(connect.approval);

        let Clients { a, .. } = clients;
        let (dapp, mut dapp_events) = restart(&server, a, "client_a").await;

        clients.b.pair(&uri.to_string()).await.unwrap();
        let proposal = next_proposal(&mut clients.b_events).await;
        let approved = clients
            .b
            .approve(proposal.id, test_namespaces())
            .await
            .unwrap();
        let session = wait_for(&mut dapp_events, |e| match e {
            SignEvent::SessionConnect(s) => Some(s),
            _ => None,
        })
        .await;
        assert_eq!(session.topic, approved.session.topic);
        assert_eq!(dapp.sessions().len(), 1);
        approved.acknowledged.await.unwrap();
    }

    /// The dapp is offline while the wallet adds accounts and emits events;
    /// it processes everything, in order, when it comes back.
    #[tokio::test]
    async fn should_process_incoming_mailbox_messages_after_restart() {
        let chain = "eip155:1";
        let accounts = ["0x0000000", "0x1111111", "0x2222222"];
        let required: ProposalNamespaces = from_json(json!({"eip155": {
            "chains": [chain],
            "methods": ["eth_sendTransaction"],
            "events": ["chainChanged", "accountsChanged"],
        }}));
        let approved_namespaces = |n: usize| -> SessionNamespaces {
            from_json(json!({"eip155": {
                "chains": [chain],
                "methods": ["eth_sendTransaction"],
                "events": ["chainChanged", "accountsChanged"],
                "accounts": accounts[..n].iter().map(|a| account(chain, a)).collect::<Vec<_>>(),
            }}))
        };

        let server = RelayServer::new();
        let mut clients = init_two_clients(&server).await;
        let connected = test_connect(
            &mut clients,
            TestConnectParams {
                required_namespaces: required,
                namespaces: approved_namespaces(1),
                ..Default::default()
            },
        )
        .await;
        let topic = connected.session_a.topic;

        // The dapp goes offline.
        let snapshot = persisted(&clients.a);
        clients.a.shutdown();

        let _first_ack = clients
            .b
            .update(&topic, approved_namespaces(2))
            .await
            .unwrap();
        let _last_ack = clients
            .b
            .update(&topic, approved_namespaces(3))
            .await
            .unwrap();
        let emitted = [
            account(chain, accounts[1]),
            account(chain, accounts[2]),
            account(chain, accounts[1]),
        ];
        for data in &emitted {
            clients
                .b
                .emit(
                    &topic,
                    chain,
                    SessionEvent::new("accountsChanged", json!([data])),
                )
                .await
                .unwrap();
        }

        // Restart the dapp.
        let (dapp, mut dapp_events) =
            client_with(&server, "client_a", test_app_metadata_a(), Some(snapshot)).await;
        let mut updates = Vec::new();
        let mut events = Vec::new();
        while events.len() < emitted.len() {
            match next_event(&mut dapp_events).await {
                SignEvent::SessionUpdate { namespaces, .. } => updates.push(namespaces),
                SignEvent::SessionEvent { event, .. } => events.push(event.data),
                _ => {}
            }
        }
        assert_eq!(updates, [approved_namespaces(2), approved_namespaces(3)]);
        assert_eq!(
            events,
            emitted.iter().map(|a| json!([a])).collect::<Vec<_>>()
        );
        assert_eq!(
            dapp.session(&topic).unwrap().namespaces,
            approved_namespaces(3)
        );
    }
}

// ---------------------------------------------------------------------------
// sdk/subscription-cleanup.spec.ts
// ---------------------------------------------------------------------------

mod subscription_cleanup {
    use super::*;

    /// A dapp driven by hand: proposes over a fresh pairing and returns the
    /// URI for the wallet, the pairing topic and the proposer's key pair.
    async fn raw_dapp_proposal(dapp: &mut RawPeer) -> (PairingUri, KeyPair) {
        let pairing_key = SymKey::generate();
        let uri = PairingUri::new(pairing_key.clone(), now_secs() + 300);
        dapp.subscribe(&uri.topic, pairing_key).await;
        let key_pair = KeyPair::generate();
        dapp.request(
            &uri.topic,
            payload_id(),
            "wc_sessionPropose",
            json!({
                "relays": [{"protocol": "irn"}],
                "proposer": {"publicKey": key_pair.public_key(), "metadata": test_app_metadata_a()},
                "requiredNamespaces": {},
                "optionalNamespaces": test_optional_namespaces(),
                "expiryTimestamp": now_secs() + 300,
                "pairingTopic": uri.topic,
            }),
        )
        .await;
        (uri, key_pair)
    }

    #[tokio::test]
    async fn should_unsubscribe_session_topic_when_settle_is_rejected() {
        let server = RelayServer::new();
        let (wallet, mut wallet_events) = client(&server, "client_b", test_app_metadata_b()).await;
        let mut dapp = RawPeer::connect(&server, "client_a").await;
        let (uri, key_pair) = raw_dapp_proposal(&mut dapp).await;

        wallet.pair(&uri.to_string()).await.unwrap();
        let proposal = next_proposal(&mut wallet_events).await;
        let approved = wallet
            .approve(proposal.id, test_namespaces())
            .await
            .unwrap();
        let session_topic = approved.session.topic.clone();
        assert!(wallet.relay().subscriptions().contains(&session_topic));

        // The dapp derives the session key from the wallet's response...
        let response = dapp.next_response(&uri.topic).await;
        let responder: PublicKey =
            from_json(response.outcome.unwrap()["responderPublicKey"].clone());
        let session_key = key_pair.derive_sym_key(&responder).unwrap();
        assert_eq!(session_key.topic(), session_topic);
        dapp.subscribe(&session_topic, session_key).await;
        // ...and refuses the settlement.
        let settle = dapp.next_request(&session_topic, "wc_sessionSettle").await;
        dapp.respond(
            &session_topic,
            Response::error(settle.id, SdkError::SessionSettlementFailed.error()),
        )
        .await;

        assert!(matches!(
            approved.acknowledged.await,
            Err(Error::Peer(e)) if e.code == 7000
        ));
        eventually("the wallet dropped the session", || {
            wallet.sessions().is_empty() && !wallet.relay().subscriptions().contains(&session_topic)
        })
        .await;
        assert_eq!(sym_key(&wallet, &session_topic), None);
    }

    /// The JS test's actual assertion: once the session ends, the wallet is
    /// no longer subscribed to its topic.
    #[tokio::test]
    async fn wallet_unsubscribes_session_topic_after_disconnect() {
        let server = RelayServer::new();
        let (mut clients, connected) = init_two_paired_clients(&server).await;
        let topic = connected.session_a.topic;
        assert!(clients.b.relay().subscriptions().contains(&topic));
        clients.a.disconnect(&topic).await.unwrap();
        wait_for(&mut clients.b_events, |e| match e {
            SignEvent::SessionDelete { .. } => Some(()),
            _ => None,
        })
        .await;
        eventually("the wallet unsubscribed", || {
            !clients.b.relay().subscriptions().contains(&topic)
        })
        .await;
        assert!(!clients.a.relay().subscriptions().contains(&topic));
    }

    #[tokio::test]
    async fn should_unsubscribe_session_topic_when_session_expires() {
        let server = RelayServer::new();
        let (dapp, mut dapp_events) = client(&server, "client_a", test_app_metadata_a()).await;
        let connect = dapp
            .connect(ConnectParams {
                optional_namespaces: test_optional_namespaces(),
                ..Default::default()
            })
            .await
            .unwrap();
        let uri = connect.uri.unwrap();

        // A wallet driven by hand settles a session that expires in 2s.
        let mut wallet = RawPeer::connect(&server, "client_b").await;
        wallet.subscribe(&uri.topic, uri.sym_key.clone()).await;
        let propose = wallet.next_request(&uri.topic, "wc_sessionPropose").await;
        let proposer: PublicKey = from_json(propose.params["proposer"]["publicKey"].clone());
        let key_pair = KeyPair::generate();
        let session_key = key_pair.derive_sym_key(&proposer).unwrap();
        let session_topic = session_key.topic();
        wallet.subscribe(&session_topic, session_key).await;
        wallet
            .respond(
                &uri.topic,
                Response::result(
                    propose.id,
                    json!({"relay": {"protocol": "irn"}, "responderPublicKey": key_pair.public_key()}),
                ),
            )
            .await;
        wallet
            .request(
                &session_topic,
                payload_id(),
                "wc_sessionSettle",
                json!({
                    "relay": {"protocol": "irn"},
                    "namespaces": test_namespaces(),
                    "expiry": now_secs() + 2,
                    "controller": {"publicKey": key_pair.public_key(), "metadata": test_app_metadata_b()},
                }),
            )
            .await;

        let session = connect.approval.await.unwrap();
        assert_eq!(session.topic, session_topic);
        assert!(dapp.relay().subscriptions().contains(&session_topic));

        wait_for(&mut dapp_events, |e| match e {
            SignEvent::SessionExpire { topic } if topic == session_topic => Some(()),
            _ => None,
        })
        .await;
        assert!(dapp.session(&session_topic).is_none());
        assert_eq!(sym_key(&dapp, &session_topic), None);
        eventually("the dapp unsubscribed", || {
            !dapp.relay().subscriptions().contains(&session_topic)
        })
        .await;
    }

    /// JS: "heartbeat orphan cleanup". This crate keeps subscriptions in step
    /// with its records instead of sweeping periodically, so after any flow
    /// every subscribed topic belongs to a session or a pairing.
    #[tokio::test]
    async fn no_orphaned_subscriptions_after_a_session_lifecycle() {
        let server = RelayServer::new();
        let (mut clients, connected) = init_two_paired_clients(&server).await;
        let topic = connected.session_a.topic;

        let assert_no_orphans = |client: &SignClient| {
            let mut known: Vec<Topic> = client.sessions().into_iter().map(|s| s.topic).collect();
            known.extend(client.pairings().into_iter().map(|p| p.topic));
            known.sort();
            let mut subscribed = client.relay().subscriptions();
            subscribed.sort();
            assert_eq!(subscribed, known);
        };
        assert_no_orphans(&clients.a);
        assert_no_orphans(&clients.b);

        // A rejected proposal over the same pairing leaves nothing behind.
        let connect = clients
            .a
            .connect(ConnectParams {
                pairing_topic: Some(connected.pairing_a.topic.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        let proposal = next_proposal(&mut clients.b_events).await;
        clients
            .b
            .reject(proposal.id, SdkError::UserRejected)
            .await
            .unwrap();
        assert!(connect.approval.await.is_err());

        clients.a.disconnect(&topic).await.unwrap();
        wait_for(&mut clients.b_events, |e| match e {
            SignEvent::SessionDelete { .. } => Some(()),
            _ => None,
        })
        .await;
        eventually("subscriptions match records", || {
            clients.b.relay().subscriptions().len() == 1
        })
        .await;
        assert_no_orphans(&clients.a);
        assert_no_orphans(&clients.b);
    }
}

// ---------------------------------------------------------------------------
// sdk/integration/integration.spec.ts, sdk/transport.spec.ts
// ---------------------------------------------------------------------------

mod transport {
    use super::*;

    async fn ping_both_ways(clients: &mut Clients, topic: &Topic) {
        clients.a.ping(topic).await.unwrap();
        clients.b.ping(topic).await.unwrap();
        for events in [&mut clients.a_events, &mut clients.b_events] {
            wait_for(events, |e| match e {
                SignEvent::SessionPing { topic: t, .. } if &t == topic => Some(()),
                _ => None,
            })
            .await;
        }
    }

    async fn reconnected(events: &mut SignEvents) {
        wait_for(events, |e| {
            (e == SignEvent::RelayDisconnected).then_some(())
        })
        .await;
        wait_for(events, |e| (e == SignEvent::RelayConnected).then_some(())).await;
    }

    #[tokio::test]
    async fn should_connect_ping_restart_transport_ping_and_disconnect() {
        let server = RelayServer::new();
        let (mut clients, connected) = init_two_paired_clients(&server).await;
        let topic = connected.session_a.topic;
        ping_both_ways(&mut clients, &topic).await;

        server.disconnect_all();
        reconnected(&mut clients.a_events).await;
        reconnected(&mut clients.b_events).await;
        ping_both_ways(&mut clients, &topic).await;

        clients.a.disconnect(&topic).await.unwrap();
        let deleted = wait_for(&mut clients.b_events, |e| match e {
            SignEvent::SessionDelete { topic, .. } => Some(topic),
            _ => None,
        })
        .await;
        assert_eq!(deleted, topic);
    }

    #[tokio::test]
    async fn should_disconnect_and_reestablish_socket_transport_with_delay() {
        let server = RelayServer::new();
        let (a, a_events, tap_a) = tapped_client(&server, "client_a", test_app_metadata_a()).await;
        let (b, b_events, tap_b) = tapped_client(&server, "client_b", test_app_metadata_b()).await;
        let mut clients = Clients {
            a,
            a_events,
            b,
            b_events,
        };
        let connected = test_connect(&mut clients, TestConnectParams::default()).await;
        let topic = connected.session_a.topic;

        tap_a.drop_connection();
        reconnected(&mut clients.a_events).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        tap_b.drop_connection();
        reconnected(&mut clients.b_events).await;
        ping_both_ways(&mut clients, &topic).await;
    }
}

// ---------------------------------------------------------------------------
// concurrency/concurrency.spec.ts (scaled down: no live relay)
// ---------------------------------------------------------------------------

mod concurrency {
    use super::*;

    const CLIENT_PAIRS: usize = 10;
    const MESSAGES_PER_PAIR: usize = 20;

    async fn exchange(server: RelayServer, index: usize) {
        let (a, a_events) = client(&server, &format!("a{index}"), test_app_metadata_a()).await;
        let (b, b_events) = client(&server, &format!("b{index}"), test_app_metadata_b()).await;
        let mut clients = Clients {
            a,
            a_events,
            b,
            b_events,
        };
        let topic = test_connect(&mut clients, TestConnectParams::default())
            .await
            .session_a
            .topic;
        let (chain, event) = test_emit_params();
        // Alternate the sender, as the JS test picks one at random.
        for i in 0..MESSAGES_PER_PAIR {
            let from = if i % 2 == 0 { &clients.a } else { &clients.b };
            from.emit(&topic, chain, event.clone()).await.unwrap();
        }
        for events in [&mut clients.a_events, &mut clients.b_events] {
            for _ in 0..MESSAGES_PER_PAIR / 2 {
                let (t, chain_id, got) = wait_for(events, |e| match e {
                    SignEvent::SessionEvent {
                        topic,
                        chain_id,
                        event,
                        ..
                    } => Some((topic, chain_id, event)),
                    _ => None,
                })
                .await;
                assert_eq!(
                    (t, chain_id.as_str(), got),
                    (topic.clone(), chain, event.clone())
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn should_successfully_handle_concurrent_clients() {
        let server = RelayServer::new();
        let pairs: Vec<_> = (0..CLIENT_PAIRS)
            .map(|i| tokio::spawn(exchange(server.clone(), i)))
            .collect();
        for pair in pairs {
            pair.await.unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Robustness (core crypto.spec.ts "should not throw on failed decrypt" and
// the engine's handling of undecodable relay messages)
// ---------------------------------------------------------------------------

mod robustness {
    use super::*;
    use base64::Engine as _;

    #[tokio::test]
    async fn undecodable_messages_are_dropped_and_the_client_keeps_working() {
        let server = RelayServer::new();
        let (mut clients, connected) = init_two_paired_clients(&server).await;
        let topic = connected.session_a.topic;
        let key = sym_key(&clients.a, &topic).unwrap();
        let dapp = RawPeer::connect(&server, "client_a").await;
        let opts = RAW_OPTS;
        let garbage = [
            "dummymessage".to_owned(),
            "!!!".to_owned(),
            // encrypted with the wrong key
            SymKey::generate()
                .encrypt(br#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#),
            // valid envelope, not JSON-RPC
            key.encrypt(b"not json"),
            key.encrypt(br#"{"jsonrpc":"2.0"}"#),
            // type 1 envelopes are not used on session topics
            wallet_connect::crypto::encrypt(&key, b"{}", Some(&KeyPair::generate().public_key())),
            // type 2 (plaintext) envelopes are ignored outside link mode
            base64::engine::general_purpose::STANDARD.encode(
                [
                    &[2u8][..],
                    br#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#,
                ]
                .concat(),
            ),
        ];
        for message in &garbage {
            dapp.relay.publish(&topic, message, opts).await.unwrap();
        }
        assert_no_event(&mut clients.b_events, Duration::from_millis(200), |e| {
            matches!(e, SignEvent::SessionPing { .. })
        })
        .await;
        clients.a.ping(&topic).await.unwrap();
        clients.b.ping(&topic).await.unwrap();
    }
}
