//! Port of the `@walletconnect/core` 2.26.0 test suite
//! (`packages/core/test/{crypto,pairing,relayer,subscriber,publisher}.spec.ts`
//! in WalletConnect/walletconnect-monorepo).
//!
//! The core package's pairing API is folded into [`SignClient`] here
//! (`connect` creates a pairing, `pair` joins one), and its relayer into
//! [`RelayClient`]. Tests of JS internals (storage keys, keychain/messages
//! stores, `isInitialized` guards, heartbeat, mobile bundle checks) have no
//! counterpart and are not ported; see `docs/js-test-port.md`.

mod common;

use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::timeout;
use wallet_connect::Error;
use wallet_connect::crypto::{SymKey, Topic, sha256_hex};
use wallet_connect::relay::rpc::{PublishParams, SubscriptionData};
use wallet_connect::relay::{
    Connection, PublishOptions, RelayClient, RelayClientOptions, RelayEvent, RelayServer,
};
use wallet_connect::sign::{ConnectParams, SignEvent, build_approved_namespaces};
use wallet_connect::time::{THIRTY_DAYS, now_secs};
use wallet_connect::uri::PairingUri;

use common::*;

// ---------------------------------------------------------------------------
// crypto.spec.ts
// ---------------------------------------------------------------------------

mod crypto {
    use super::*;

    #[test]
    fn decrypts_payload_if_the_passed_topic_is_known() {
        let sym_key =
            SymKey::from_hex("5720435e682cd03ee45b484f9a213f0e3246a0ccc2cca183b72ab1cbfbefb702")
                .unwrap();
        let encoded = "AG7iJl9mMl9K04REnuWaKLQU6kwMcQWUd69OxGOJ5/A+VRRKkxnKhBeIAl4JRaIft3qZKEfnBvc7/Fife1DWcERqAfJwzPI=";
        let decoded: Value = serde_json::from_slice(&sym_key.decrypt(encoded).unwrap()).unwrap();
        assert_eq!(
            decoded,
            json!({"id": 1, "jsonrpc": "2.0", "result": "result"})
        );
    }

    #[test]
    fn should_not_throw_on_failed_decrypt() {
        assert!(SymKey::generate().decrypt("dummymessage").is_err());
    }

    #[test]
    fn set_sym_key_returns_the_hash_of_the_key_as_topic() {
        let key = SymKey::generate();
        assert_eq!(key.topic().as_str(), sha256_hex(key.as_bytes()));
    }
}

// ---------------------------------------------------------------------------
// pairing.spec.ts
// ---------------------------------------------------------------------------

mod pairing {
    use super::*;

    /// `coreA.pairing.create()`: a dapp's `connect` creates the pairing.
    async fn create(clients: &Clients) -> PairingUri {
        clients
            .a
            .connect(ConnectParams::default())
            .await
            .unwrap()
            .uri
            .expect("new pairing has a uri")
    }

    async fn assert_paired(clients: &Clients, topic: &Topic) {
        let a = clients.a.pairings();
        let b = clients.b.pairings();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(&a[0].topic, topic);
        assert_eq!(&b[0].topic, topic);
        assert!(!a[0].active);
        assert!(!b[0].active);
    }

    #[tokio::test]
    async fn returns_the_pairing_topic_and_uri_in_expected_format() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let connect = clients.a.connect(ConnectParams::default()).await.unwrap();
        let uri = connect.uri.unwrap();
        let topic = connect.pairing_topic;
        assert_eq!(topic.as_str().len(), 64);
        assert_eq!(uri.topic, topic);
        assert!(uri.to_string().starts_with(&format!("wc:{topic}@2")));
        // The pairing expires five minutes after creation.
        let expiry = uri.expiry_timestamp.unwrap();
        assert!(expiry.abs_diff(now_secs() + 300) <= 5);
    }

    #[tokio::test]
    async fn can_pair_via_provided_uri() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.pair(&uri.to_string()).await.unwrap();
        assert_paired(&clients, &uri.topic).await;
    }

    #[tokio::test]
    async fn can_pair_via_base64_provided_uri() {
        use base64::Engine as _;
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        // `toBase64(uri, true)` strips the padding.
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(uri.to_string());
        clients.b.pair(&encoded).await.unwrap();
        assert_paired(&clients, &uri.topic).await;
    }

    #[tokio::test]
    async fn can_pair_via_provided_android_deeplink_uri() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.pair(&format!("wc://{uri}")).await.unwrap();
        assert_paired(&clients, &uri.topic).await;
    }

    #[tokio::test]
    async fn can_pair_via_provided_ios_deeplink_uri() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.pair(&format!("wc:{uri}")).await.unwrap();
        assert_paired(&clients, &uri.topic).await;
    }

    #[tokio::test]
    async fn throws_when_pairing_is_attempted_on_topic_that_already_exists() {
        let server = RelayServer::new();
        let (clients, connected) = init_two_paired_clients(&server).await;
        let uri = PairingUri::new(
            sym_key(&clients.b, &connected.pairing_b.topic).unwrap(),
            now_secs() + 300,
        );
        let err = clients.b.pair(&uri.to_string()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("pairing already exists: {}", uri.topic)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn should_not_override_existing_keychain_values() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.pair(&uri.to_string()).await.unwrap();
        // Same topic, different key.
        let mut other = uri.clone();
        other.sym_key = SymKey::generate();
        clients.b.pair(&other.to_string()).await.unwrap();
        assert_eq!(sym_key(&clients.b, &uri.topic), Some(uri.sym_key));
    }

    #[tokio::test]
    async fn throws_when_uri_has_expired() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = PairingUri::new(SymKey::generate(), now_secs() - 1);
        assert!(matches!(
            clients.b.pair(&uri.to_string()).await,
            Err(Error::Expired(_))
        ));
        assert!(clients.b.pairings().is_empty());
    }

    /// The reference SDK (2.26) keeps an activated pairing for five more
    /// minutes only; this crate follows the pairing spec ("Active pairings
    /// should have a 30 days expiry period").
    #[tokio::test]
    async fn can_activate_a_pairing() {
        let server = RelayServer::new();
        let (clients, connected) = init_two_paired_clients(&server).await;
        for pairing in [
            find_pairing(&clients.a, &connected.pairing_a.topic).unwrap(),
            find_pairing(&clients.b, &connected.pairing_b.topic).unwrap(),
        ] {
            assert!(pairing.active);
            assert!(pairing.expiry.abs_diff(now_secs() + THIRTY_DAYS) <= 5);
        }
    }

    /// `updateMetadata`: the peer's metadata is recorded on the pairing.
    #[tokio::test]
    async fn records_the_peers_metadata() {
        // Unknown while the pairing is inactive...
        {
            let server = RelayServer::new();
            let clients = init_two_clients(&server).await;
            let uri = create(&clients).await;
            let pairing = clients.b.pair(&uri.to_string()).await.unwrap();
            assert!(pairing.peer_metadata.is_none());
            assert!(clients.a.pairings()[0].peer_metadata.is_none());
        }
        // ...and recorded on both sides once a session was negotiated.
        let server = RelayServer::new();
        let (_clients, connected) = init_two_paired_clients(&server).await;
        assert_eq!(
            connected.pairing_a.peer_metadata,
            Some(test_app_metadata_b())
        );
        assert_eq!(
            connected.pairing_b.peer_metadata,
            Some(test_app_metadata_a())
        );
    }

    #[tokio::test]
    async fn clients_can_ping_each_other() {
        let server = RelayServer::new();
        let mut clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.pair(&uri.to_string()).await.unwrap();

        clients.a.ping(&uri.topic).await.unwrap();
        wait_for(&mut clients.b_events, |e| match e {
            SignEvent::PairingPing { topic, .. } if topic == uri.topic => Some(()),
            _ => None,
        })
        .await;

        clients.b.ping(&uri.topic).await.unwrap();
        wait_for(&mut clients.a_events, |e| match e {
            SignEvent::PairingPing { topic, .. } if topic == uri.topic => Some(()),
            _ => None,
        })
        .await;
    }

    #[tokio::test]
    async fn can_disconnect_a_known_pairing() {
        let server = RelayServer::new();
        let mut clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.pair(&uri.to_string()).await.unwrap();

        clients.b.disconnect(&uri.topic).await.unwrap();
        wait_for(&mut clients.a_events, |e| match e {
            SignEvent::PairingDelete { topic, .. } if topic == uri.topic => Some(()),
            _ => None,
        })
        .await;
        assert!(clients.a.pairings().is_empty());
        assert!(clients.b.pairings().is_empty());
        // The key is gone too and the topic is no longer subscribed.
        assert_eq!(sym_key(&clients.a, &uri.topic), None);
        assert_eq!(sym_key(&clients.b, &uri.topic), None);
        assert!(!clients.b.relay().subscriptions().contains(&uri.topic));
        eventually("A unsubscribed from the pairing", || {
            !clients.a.relay().subscriptions().contains(&uri.topic)
        })
        .await;
    }

    mod validations {
        use super::*;

        #[tokio::test]
        async fn pair_throws_when_empty_uri_is_provided() {
            let server = RelayServer::new();
            let clients = init_two_clients(&server).await;
            assert!(matches!(
                clients.b.pair("").await,
                Err(Error::InvalidUri(_))
            ));
        }

        #[tokio::test]
        async fn pair_throws_on_a_v1_uri() {
            let server = RelayServer::new();
            let clients = init_two_clients(&server).await;
            // A v1 URI: unsupported version, no relay protocol, no symKey.
            let v1 = "wc:e9d6ef98-6b65-490b-8726-a21e1afb181d@1?bridge=https%3A%2F%2Fwalletconnect.com&key=73f096cb97aaee97b3d9871ced35fdce1668e652db3d39423ea6cd22e14528bf";
            assert!(matches!(
                clients.b.pair(v1).await,
                Err(Error::InvalidUri(_))
            ));
        }

        #[tokio::test]
        async fn pair_throws_when_uri_is_missing_relay_protocol_or_sym_key() {
            let topic = Topic::generate();
            let key = SymKey::generate().to_hex();
            for uri in [
                format!("wc:{topic}@2?symKey={key}"),
                format!("wc:{topic}@2?relay-protocol=irn"),
            ] {
                let err = uri.parse::<PairingUri>().unwrap_err();
                assert!(matches!(err, Error::InvalidUri(_)), "{uri}: {err}");
            }
        }

        #[tokio::test]
        async fn ping_throws_when_empty_or_non_existent_topic_is_provided() {
            let server = RelayServer::new();
            let clients = init_two_clients(&server).await;
            for topic in ["", "none"] {
                assert!(matches!(
                    clients.a.ping(&Topic::new(topic)).await,
                    Err(Error::NoSession(_))
                ));
            }
        }

        #[tokio::test]
        async fn disconnect_throws_when_empty_or_non_existent_topic_is_provided() {
            let server = RelayServer::new();
            let clients = init_two_clients(&server).await;
            for topic in ["", "none"] {
                assert!(matches!(
                    clients.a.disconnect(&Topic::new(topic)).await,
                    Err(Error::NoSession(_))
                ));
            }
        }
    }

    /// "should store pairing before subscribing to its topic": a failed
    /// subscription leaves no pairing behind.
    #[tokio::test]
    async fn pairing_is_rolled_back_when_subscribing_fails() {
        let server = RelayServer::new();
        let clients = init_two_clients(&server).await;
        let uri = create(&clients).await;
        clients.b.relay().close();
        assert!(clients.b.pair(&uri.to_string()).await.is_err());
        assert!(clients.b.pairings().is_empty());
        assert_eq!(sym_key(&clients.b, &uri.topic), None);
    }

    /// Port of the namespace-free pairing flow used throughout: approving
    /// with no namespaces requested grants everything supported.
    #[tokio::test]
    async fn pairing_becomes_active_on_both_sides_after_approval() {
        let server = RelayServer::new();
        let mut clients = init_two_clients(&server).await;
        let connect = clients.a.connect(ConnectParams::default()).await.unwrap();
        clients
            .b
            .pair(&connect.uri.unwrap().to_string())
            .await
            .unwrap();
        let SignEvent::SessionProposal(proposal) = next_event(&mut clients.b_events).await else {
            panic!("expected a proposal")
        };
        let supported = from_json(json!({"eip155": {
            "chains": [TEST_ETHEREUM_CHAIN],
            "methods": ["personal_sign"],
            "events": [],
            "accounts": [account(TEST_ETHEREUM_CHAIN, TEST_ETHEREUM_ADDRESS)],
        }}));
        let namespaces = build_approved_namespaces(
            &proposal.required_namespaces,
            &proposal.optional_namespaces,
            &supported,
        )
        .unwrap();
        clients.b.approve(proposal.id, namespaces).await.unwrap();
        connect.approval.await.unwrap();
        assert!(clients.a.pairings()[0].active);
        assert!(clients.b.pairings()[0].active);
    }
}

// ---------------------------------------------------------------------------
// relayer.spec.ts, subscriber.spec.ts, publisher.spec.ts
// ---------------------------------------------------------------------------

mod relayer {
    use super::*;

    const OPTS: PublishOptions = PublishOptions {
        ttl: 300,
        tag: 1108,
        prompt: false,
    };

    async fn relay_client(
        connector: impl wallet_connect::relay::Connector,
    ) -> (
        RelayClient,
        tokio::sync::mpsc::UnboundedReceiver<RelayEvent>,
    ) {
        let (client, mut events) = RelayClient::connect(connector, RelayClientOptions::default())
            .await
            .unwrap();
        assert_eq!(events.recv().await, Some(RelayEvent::Connected));
        (client, events)
    }

    async fn next_message(
        events: &mut tokio::sync::mpsc::UnboundedReceiver<RelayEvent>,
    ) -> SubscriptionData {
        loop {
            match timeout(WAIT, events.recv()).await {
                Ok(Some(RelayEvent::Message(m))) => return m,
                Ok(Some(_)) => continue,
                other => panic!("no message: {other:?}"),
            }
        }
    }

    async fn assert_no_message(events: &mut tokio::sync::mpsc::UnboundedReceiver<RelayEvent>) {
        if let Ok(Some(RelayEvent::Message(m))) =
            timeout(Duration::from_millis(200), events.recv()).await
        {
            panic!("unexpected message {m:?}");
        }
    }

    /// Next JSON frame the client sent on a hand-driven connection.
    async fn next_frame(relay_end: &mut Connection) -> Value {
        let text = timeout(WAIT, relay_end.receiver.recv())
            .await
            .expect("frame in time")
            .expect("connection open");
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test]
    async fn returns_the_subscription_id_hash_of_topic_and_client_id() {
        let server = RelayServer::new();
        let (client, _) = relay_client(server.connector("client-id")).await;
        let topic = Topic::generate();
        let id = client.subscribe(&topic).await.unwrap();
        assert_eq!(id, sha256_hex(format!("{topic}client-id").as_bytes()));
    }

    #[tokio::test]
    async fn should_be_able_to_resubscribe_on_topic_that_already_exists() {
        let server = RelayServer::new();
        let (alice, _) = relay_client(server.connector("alice")).await;
        let (bob, mut bob_events) = relay_client(server.connector("bob")).await;
        let topic = Topic::generate();
        let expected = sha256_hex(format!("{topic}bob").as_bytes());
        let id = bob.subscribe(&topic).await.unwrap();
        let a = bob.subscribe(&topic).await.unwrap();
        let b = bob.subscribe(&topic).await.unwrap();
        let c = bob.subscribe(&topic).await.unwrap();
        for got in [&id, &a, &b, &c] {
            assert_eq!(got, &expected);
        }
        assert_eq!(bob.subscriptions(), vec![topic.clone()]);
        // Subscribing repeatedly does not duplicate deliveries.
        alice.publish(&topic, "once", OPTS).await.unwrap();
        assert_eq!(next_message(&mut bob_events).await.message, "once");
        assert_no_message(&mut bob_events).await;
    }

    #[tokio::test]
    async fn should_subscribe_multiple_topics() {
        let server = RelayServer::new();
        let (alice, _) = relay_client(server.connector("alice")).await;
        let (bob, mut bob_events) = relay_client(server.connector("bob")).await;
        let topics: Vec<Topic> = (0..5).map(|_| Topic::generate()).collect();
        bob.batch_subscribe(&topics).await.unwrap();
        let mut subscribed = bob.subscriptions();
        subscribed.sort();
        let mut expected = topics.clone();
        expected.sort();
        assert_eq!(subscribed, expected);
        for (i, topic) in topics.iter().enumerate() {
            alice.publish(topic, &format!("m{i}"), OPTS).await.unwrap();
            let m = next_message(&mut bob_events).await;
            assert_eq!(
                (&m.topic, m.message.as_str()),
                (topic, format!("m{i}").as_str())
            );
        }
    }

    #[tokio::test]
    async fn unsubscribes_by_topic() {
        let server = RelayServer::new();
        let tap = Tap::new(&server, "client");
        let (client, _) = relay_client(tap.clone()).await;
        let topic = Topic::generate();
        let id = client.subscribe(&topic).await.unwrap();
        assert_eq!(client.subscriptions().len(), 1);
        client.unsubscribe(&topic).await.unwrap();
        assert!(client.subscriptions().is_empty());
        let unsubscribes = tap.requests("irn_unsubscribe");
        assert_eq!(unsubscribes.len(), 1);
        assert_eq!(unsubscribes[0]["params"], json!({"topic": topic, "id": id}));
    }

    #[tokio::test]
    async fn subscribe_calls_the_relay_with_the_expected_request_shape() {
        let server = RelayServer::new();
        let tap = Tap::new(&server, "client");
        let (client, _) = relay_client(tap.clone()).await;
        let topic = Topic::generate();
        client.subscribe(&topic).await.unwrap();
        let frames = tap.requests("irn_subscribe");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["jsonrpc"], "2.0");
        assert!(frames[0]["id"].is_u64());
        assert_eq!(frames[0]["params"], json!({"topic": topic}));

        let topics = [Topic::generate(), Topic::generate()];
        client.batch_subscribe(&topics).await.unwrap();
        let frames = tap.requests("irn_batchSubscribe");
        assert_eq!(frames[0]["params"], json!({"topics": topics}));
    }

    #[tokio::test]
    async fn publish_calls_the_relay_with_the_expected_request_shape() {
        let server = RelayServer::new();
        let tap = Tap::new(&server, "client");
        let (client, _) = relay_client(tap.clone()).await;
        let topic = Topic::generate();
        client
            .publish(
                &topic,
                "test message",
                PublishOptions {
                    ttl: 300,
                    tag: 0,
                    prompt: false,
                },
            )
            .await
            .unwrap();
        // "allows overriding of defaults via `opts` param"
        client
            .publish(
                &topic,
                "test message 2",
                PublishOptions {
                    ttl: 1,
                    tag: 1,
                    prompt: true,
                },
            )
            .await
            .unwrap();
        let frames = tap.requests("irn_publish");
        assert_eq!(frames.len(), 2);
        assert!(frames[0]["id"].is_u64());
        // `prompt: false` is omitted, which the relay treats the same.
        assert_eq!(
            frames[0]["params"],
            json!({"topic": topic, "message": "test message", "ttl": 300, "tag": 0})
        );
        assert_eq!(
            frames[1]["params"],
            json!({"topic": topic, "message": "test message 2", "ttl": 1, "tag": 1, "prompt": true})
        );
        let parsed: Vec<PublishParams> = tap.published();
        assert_eq!(parsed[1].prompt, Some(true));
    }

    /// `onProviderPayload`: only `*_subscription` requests become messages.
    #[tokio::test]
    async fn handles_provider_payloads() {
        let (connector, mut connections) = manual_connector();
        let (_client, mut events) = relay_client(connector).await;
        let mut relay_end = connections.recv().await.unwrap();

        // "does nothing if payload is not a valid JsonRpcRequest"
        relay_end.sender.send("{}".into()).unwrap();
        relay_end.sender.send("not json".into()).unwrap();
        assert_no_message(&mut events).await;

        // "does nothing if payload.method does not have the _subscription suffix"
        let mut valid = json!({
            "id": 123,
            "jsonrpc": "2.0",
            "method": "mock_subscription",
            "params": {
                "id": "abc123",
                "data": {"topic": "ababab", "message": "deadbeef", "publishedAt": 1677151760537u64},
            },
        });
        let mut unsuffixed = valid.clone();
        unsuffixed["method"] = json!("mock");
        relay_end.sender.send(unsuffixed.to_string()).unwrap();
        assert_no_message(&mut events).await;
        let reply = next_frame(&mut relay_end).await;
        assert_eq!(reply["id"], 123);
        assert_eq!(reply["error"]["code"], -32601);

        // "emits an event based on payload.params.id", acknowledging it.
        relay_end.sender.send(valid.to_string()).unwrap();
        let message = next_message(&mut events).await;
        assert_eq!(
            message,
            SubscriptionData {
                topic: Topic::new("ababab"),
                message: "deadbeef".into(),
                published_at: 1677151760537,
                tag: 0,
                attestation: None,
            }
        );
        let ack = next_frame(&mut relay_end).await;
        assert_eq!(ack, json!({"id": 123, "jsonrpc": "2.0", "result": true}));

        // The canonical method and an attestation are passed through.
        valid["method"] = json!("irn_subscription");
        valid["id"] = json!(124);
        valid["params"]["data"]["attestation"] = json!("att");
        relay_end.sender.send(valid.to_string()).unwrap();
        assert_eq!(
            next_message(&mut events).await.attestation.as_deref(),
            Some("att")
        );
    }

    #[tokio::test]
    async fn should_throw_when_subscribe_reaches_a_timeout() {
        let (connector, mut connections) = manual_connector();
        let (client, _events) = RelayClient::connect(
            connector,
            RelayClientOptions {
                request_timeout: Duration::from_millis(200),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let _relay_end = connections.recv().await.unwrap(); // never answers
        let topic = Topic::generate();
        assert!(matches!(
            client.subscribe(&topic).await,
            Err(Error::Timeout)
        ));
        assert!(client.subscriptions().is_empty());
    }

    /// Answer the next request on a hand-driven connection with an error.
    async fn fail_next_request(relay_end: &mut Connection, method: &str) {
        let request = next_frame(relay_end).await;
        assert_eq!(request["method"], method);
        relay_end
            .sender
            .send(
                json!({"id": request["id"], "jsonrpc": "2.0", "error": {"code": -32000, "message": "nope"}})
                    .to_string(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn should_throw_when_subscribe_fails() {
        let (connector, mut connections) = manual_connector();
        let (client, _events) = relay_client(connector).await;
        let mut relay_end = connections.recv().await.unwrap();
        let subscribe = {
            let client = client.clone();
            tokio::spawn(async move { client.subscribe(&Topic::generate()).await })
        };
        fail_next_request(&mut relay_end, "irn_subscribe").await;
        match subscribe.await.unwrap() {
            Err(Error::Relay(e)) => assert_eq!(e.code, -32000),
            other => panic!("{other:?}"),
        }
        assert!(client.subscriptions().is_empty());
    }

    /// subscriber.spec.ts: "should not mark topics as subscribed when batch
    /// subscribe RPC fails".
    #[tokio::test]
    async fn should_not_mark_topics_as_subscribed_when_batch_subscribe_fails() {
        let (connector, mut connections) = manual_connector();
        let (client, _events) = relay_client(connector).await;
        let mut relay_end = connections.recv().await.unwrap();
        let subscribe = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .batch_subscribe(&[Topic::generate(), Topic::generate()])
                    .await
            })
        };
        fail_next_request(&mut relay_end, "irn_batchSubscribe").await;
        assert!(matches!(subscribe.await.unwrap(), Err(Error::Relay(_))));
        assert!(client.subscriptions().is_empty());
    }

    /// "should restart transport after connection drop": the client
    /// reconnects and resubscribes everything in one batch.
    #[tokio::test]
    async fn should_restart_transport_after_connection_drop() {
        let server = RelayServer::new();
        let tap = Tap::new(&server, "bob");
        let (alice, _) = relay_client(server.connector("alice")).await;
        let (bob, mut bob_events) = relay_client(tap.clone()).await;
        let topics = [Topic::generate(), Topic::generate()];
        for topic in &topics {
            bob.subscribe(topic).await.unwrap();
        }
        tap.clear();
        tap.drop_connection();
        loop {
            match timeout(WAIT, bob_events.recv()).await.unwrap() {
                Some(RelayEvent::Disconnected) => continue,
                Some(RelayEvent::Connected) => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        eventually("bob resubscribed", || {
            !tap.requests("irn_batchSubscribe").is_empty()
        })
        .await;
        let resubscribed = &tap.requests("irn_batchSubscribe")[0]["params"]["topics"];
        let mut got: Vec<Topic> = serde_json::from_value(resubscribed.clone()).unwrap();
        got.sort();
        let mut expected = topics.to_vec();
        expected.sort();
        assert_eq!(got, expected);
        tokio::time::sleep(Duration::from_millis(50)).await;

        alice
            .publish(&topics[0], "after reconnect", OPTS)
            .await
            .unwrap();
        assert_eq!(
            next_message(&mut bob_events).await.message,
            "after reconnect"
        );
    }

    #[tokio::test]
    async fn should_not_reconnect_after_explicit_close() {
        let server = RelayServer::new();
        let (client, mut events) = relay_client(server.connector("client")).await;
        client.close();
        assert!(!client.is_connected());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(server.connection_count(), 0);
        while let Ok(event) = events.try_recv() {
            assert_ne!(event, RelayEvent::Connected);
        }
    }
}
