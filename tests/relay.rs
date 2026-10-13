//! Relay client ↔ relay server behaviour, in-process and over WebSocket.

use std::time::Duration;

use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;
use wallet_connect::crypto::Topic;
use wallet_connect::relay::rpc::{ApproveSessionParams, ProposeSessionParams};
use wallet_connect::relay::{
    PublishOptions, RelayClient, RelayClientOptions, RelayEvent, RelayServer,
};

const OPTS: PublishOptions = PublishOptions {
    ttl: 300,
    tag: 1108,
    prompt: false,
};

async fn client(server: &RelayServer, id: &str) -> (RelayClient, UnboundedReceiver<RelayEvent>) {
    let (client, mut events) =
        RelayClient::connect(server.connector(id), RelayClientOptions::default())
            .await
            .unwrap();
    assert_eq!(events.recv().await, Some(RelayEvent::Connected));
    (client, events)
}

/// Next message event, skipping connection events.
async fn next_message(events: &mut UnboundedReceiver<RelayEvent>) -> (Topic, String) {
    loop {
        match timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(RelayEvent::Message(m))) => return (m.topic, m.message),
            Ok(Some(_)) => continue,
            Ok(None) => panic!("event stream closed"),
            Err(_) => panic!("no message within 5s"),
        }
    }
}

async fn assert_quiet(events: &mut UnboundedReceiver<RelayEvent>) {
    if let Ok(Some(RelayEvent::Message(m))) =
        timeout(Duration::from_millis(200), events.recv()).await
    {
        panic!("unexpected message {m:?}");
    }
}

#[tokio::test]
async fn publish_reaches_subscriber_but_not_publisher() {
    let server = RelayServer::new();
    let (alice, mut alice_events) = client(&server, "alice").await;
    let (bob, mut bob_events) = client(&server, "bob").await;
    let topic = Topic::generate();

    alice.subscribe(&topic).await.unwrap();
    bob.subscribe(&topic).await.unwrap();
    alice.publish(&topic, "hello", OPTS).await.unwrap();

    assert_eq!(
        next_message(&mut bob_events).await,
        (topic.clone(), "hello".into())
    );
    assert_quiet(&mut alice_events).await;
}

#[tokio::test]
async fn messages_wait_for_late_subscribers_and_are_delivered_once() {
    let server = RelayServer::new();
    let (alice, _) = client(&server, "alice").await;
    let topic = Topic::generate();
    alice.publish(&topic, "m1", OPTS).await.unwrap();
    alice.publish(&topic, "m2", OPTS).await.unwrap();
    // A retried publish of the same message is not stored twice.
    alice.publish(&topic, "m2", OPTS).await.unwrap();
    assert_eq!(server.stored_message_count(&topic), 2);

    let (bob, mut bob_events) = client(&server, "bob").await;
    bob.subscribe(&topic).await.unwrap();
    assert_eq!(next_message(&mut bob_events).await.1, "m1");
    assert_eq!(next_message(&mut bob_events).await.1, "m2");

    // Acknowledged messages are not delivered to the same client again,
    // even on a new connection.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(bob);
    let (bob2, mut bob2_events) = client(&server, "bob").await;
    bob2.subscribe(&topic).await.unwrap();
    assert_quiet(&mut bob2_events).await;

    // A different client still gets them.
    let (carol, mut carol_events) = client(&server, "carol").await;
    let fetched = carol.fetch_messages(&topic).await.unwrap();
    assert_eq!(fetched.messages.len(), 2);
    carol.subscribe(&topic).await.unwrap();
    assert_quiet(&mut carol_events).await;
}

#[tokio::test]
async fn unsubscribe_stops_delivery() {
    let server = RelayServer::new();
    let (alice, _) = client(&server, "alice").await;
    let (bob, mut bob_events) = client(&server, "bob").await;
    let topic = Topic::generate();
    bob.subscribe(&topic).await.unwrap();
    bob.unsubscribe(&topic).await.unwrap();
    assert!(bob.subscriptions().is_empty());
    alice.publish(&topic, "ignored", OPTS).await.unwrap();
    assert_quiet(&mut bob_events).await;
}

#[tokio::test]
async fn reconnects_and_resubscribes() {
    let server = RelayServer::new();
    let (alice, _) = client(&server, "alice").await;
    let (bob, mut bob_events) = client(&server, "bob").await;
    let topics = [Topic::generate(), Topic::generate()];
    bob.batch_subscribe(&topics).await.unwrap();

    server.disconnect_all();
    let mut saw_disconnect = false;
    loop {
        match timeout(Duration::from_secs(5), bob_events.recv())
            .await
            .unwrap()
        {
            Some(RelayEvent::Disconnected) => saw_disconnect = true,
            Some(RelayEvent::Connected) if saw_disconnect => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    // Alice reconnected too; wait until both are back and resubscribed.
    for _ in 0..50 {
        if alice.is_connected() && server.connection_count() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    alice
        .publish(&topics[1], "after reconnect", OPTS)
        .await
        .unwrap();
    assert_eq!(
        next_message(&mut bob_events).await,
        (topics[1].clone(), "after reconnect".into())
    );
}

#[tokio::test]
async fn requests_fail_fast_when_closed() {
    let server = RelayServer::new();
    let (alice, _) = client(&server, "alice").await;
    alice.close();
    let err = alice
        .publish(&Topic::generate(), "x", OPTS)
        .await
        .unwrap_err();
    assert!(matches!(err, wallet_connect::Error::Closed), "{err}");
}

#[tokio::test]
async fn relay_errors_are_reported() {
    let server = RelayServer::new();
    let (alice, _) = client(&server, "alice").await;
    let err = alice
        .request::<_, serde_json::Value>("irn_nope", serde_json::json!({}))
        .await
        .unwrap_err();
    match err {
        wallet_connect::Error::Relay(e) => assert_eq!(e.code, -32601),
        other => panic!("{other}"),
    }
    let err = alice
        .request::<_, serde_json::Value>("irn_publish", serde_json::json!({"topic": 1}))
        .await
        .unwrap_err();
    assert!(matches!(err, wallet_connect::Error::Relay(e) if e.code == -32602));
}

#[tokio::test]
async fn combined_session_methods() {
    let server = RelayServer::new();
    let (dapp, mut dapp_events) = client(&server, "dapp").await;
    let (wallet, mut wallet_events) = client(&server, "wallet").await;
    let pairing = Topic::generate();
    let session = Topic::generate();

    dapp.propose_session(ProposeSessionParams {
        pairing_topic: pairing.clone(),
        session_proposal: "proposal".into(),
        ttl: 300,
        tag: None,
        prompt: Some(true),
        attestation: None,
    })
    .await
    .unwrap();

    wallet.subscribe(&pairing).await.unwrap();
    assert_eq!(next_message(&mut wallet_events).await.1, "proposal");

    wallet
        .approve_session(ApproveSessionParams {
            session_topic: session.clone(),
            pairing_topic: pairing.clone(),
            session_proposal_response: "response".into(),
            session_settlement_request: "settle".into(),
            ttl: 300,
            tag: None,
            prompt: None,
        })
        .await
        .unwrap();
    // The dapp was subscribed to the pairing topic by wc_proposeSession.
    assert_eq!(
        next_message(&mut dapp_events).await,
        (pairing, "response".into())
    );
    dapp.subscribe(&session).await.unwrap();
    assert_eq!(
        next_message(&mut dapp_events).await,
        (session.clone(), "settle".into())
    );

    // ...and the wallet to the session topic by wc_approveSession.
    dapp.publish(&session, "settle ack", OPTS).await.unwrap();
    assert_eq!(
        next_message(&mut wallet_events).await,
        (session, "settle ack".into())
    );
}

#[cfg(feature = "ws")]
mod ws {
    use super::*;
    use wallet_connect::auth::{IdentityKey, JwtClaims, encode_jwt};
    use wallet_connect::relay::{WsConnector, connect_ws};

    #[tokio::test]
    async fn websocket_end_to_end() {
        let server = RelayServer::new();
        let (addr, _task) = server.listen("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{addr}");

        let connect = |identity: IdentityKey| {
            let url = url.clone();
            async move {
                let (c, mut ev) = RelayClient::connect(
                    WsConnector::new(url, identity).project_id("test"),
                    RelayClientOptions::default(),
                )
                .await
                .unwrap();
                assert_eq!(ev.recv().await, Some(RelayEvent::Connected));
                (c, ev)
            }
        };
        let (alice, _) = connect(IdentityKey::generate()).await;
        let (bob, mut bob_events) = connect(IdentityKey::generate()).await;

        let topic = Topic::generate();
        bob.subscribe(&topic).await.unwrap();
        alice.publish(&topic, "over the wire", OPTS).await.unwrap();
        assert_eq!(next_message(&mut bob_events).await.1, "over the wire");
    }

    #[tokio::test]
    async fn websocket_rejects_bad_tokens() {
        let server = RelayServer::new();
        let (addr, _task) = server.listen("127.0.0.1:0").await.unwrap();
        let key = IdentityKey::generate();
        let expired = encode_jwt(
            &key,
            &JwtClaims {
                iss: key.client_id(),
                sub: "s".into(),
                aud: format!("ws://{addr}"),
                iat: 1,
                exp: 2,
                act: None,
            },
        );
        let err = connect_ws(&format!("ws://{addr}/?auth={expired}"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("401"), "{err}");
        // A valid token is accepted.
        let url = WsConnector::new(format!("ws://{addr}"), key)
            .connection_url()
            .unwrap();
        connect_ws(url.as_str()).await.unwrap();
    }
}
