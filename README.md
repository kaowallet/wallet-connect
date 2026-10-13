# wallet-connect

The [WalletConnect v2](https://specs.walletconnect.com/2.0) protocol in Rust:
pairing, the relay protocol and the Sign API, for **dapps and wallets** alike.
It also ships a self-contained **relay server**.

It is wire-compatible with the reference JavaScript SDK
(`@walletconnect/sign-client` 2.26.0). Test vectors pin the cryptography to
the SDK's output byte for byte, and live sessions run against the SDK in both
directions (see [Interoperability](#interoperability)).

## What's in the box

| Module   | Contents |
|----------|----------|
| `crypto` | X25519 key agreement → HKDF-SHA256 → symmetric key; `topic = sha256(key)`; type 0/1/2 envelopes (ChaCha20-Poly1305) |
| `uri`    | `wc:{topic}@2?expiryTimestamp=…&relay-protocol=irn&symKey=…` parsing and formatting |
| `auth`   | `did:key` client ids, the Ed25519 (`EdDSA`) JWT presented to the relay |
| `relay`  | relay JSON-RPC client (`irn_publish`, `irn_subscribe`, batch variants, `irn_fetchMessages`, acks, auto-reconnect with resubscribe), WebSocket and in-process transports, and a relay **server** |
| `sign`   | `SignClient`: `connect`/`pair`/`approve`/`reject`/`request`/`respond`/`emit`/`update`/`extend`/`ping`/`disconnect`; namespace validation and `build_approved_namespaces`; expiry handling; snapshot/restore |

The Sign client implements every `wc_session*` and `wc_pairing*` method:

| Method | Tag (req/res) | Who sends it |
|---|---|---|
| `wc_sessionPropose` | 1100/1101 (reject 1120, auto-reject 1121) | dapp |
| `wc_sessionSettle` | 1102/1103 | wallet |
| `wc_sessionUpdate` | 1104/1105 | wallet (controller) |
| `wc_sessionExtend` | 1106/1107 | either |
| `wc_sessionRequest` | 1108/1109 | dapp |
| `wc_sessionEvent` | 1110/1111 | wallet |
| `wc_sessionDelete` | 1112 | either |
| `wc_sessionPing` | 1114/1115 | either |
| `wc_pairingPing`, `wc_pairingDelete` | 1002/1003, 1000 | either |

## Quick start

Everything runs locally. No project id or internet access is needed:

```sh
cargo run --example relay_server -- 127.0.0.1:8080        # terminal 1
cargo run --example dapp -- --relay ws://127.0.0.1:8080    # terminal 2: prints a wc: URI
cargo run --example wallet -- --relay ws://127.0.0.1:8080 'wc:…'   # terminal 3
```

The dapp proposes a session, the wallet approves it, and the dapp asks for a
`personal_sign` and gets the answer. It then pings and disconnects. To use
the public relay instead, drop `--relay` and pass
`--project-id <WalletConnect Cloud project id>`.

### As a dapp

```rust
let (client, _events) = SignClient::builder(Metadata::new("My dapp", "…", "https://dapp.example"))
    .project_id(PROJECT_ID)
    .build()
    .await?;

let connect = client.connect(ConnectParams {
    optional_namespaces: BTreeMap::from([(
        "eip155".to_owned(),
        ProposalNamespace::new(["eip155:1"], ["personal_sign"], ["accountsChanged"]),
    )]),
    ..Default::default()
}).await?;
show_qr_code(connect.uri.unwrap());

let session = connect.approval.await?;
let signature = client
    .request(&session.topic, "eip155:1", SessionRequest::new("personal_sign", json!([msg, address])))
    .await?;
```

### As a wallet

```rust
let (client, mut events) = SignClient::builder(metadata).project_id(PROJECT_ID).build().await?;
client.pair(&scanned_uri).await?;

while let Some(event) = events.recv().await {
    match event {
        SignEvent::SessionProposal(p) => {
            let ns = build_approved_namespaces(&p.required_namespaces, &p.optional_namespaces, &supported)
                .map_err(Error::Protocol)?;
            client.approve(p.id, ns).await?;
        }
        SignEvent::SessionRequest(r) => client.respond(&r.topic, r.id, Ok(sign(&r)?)).await?,
        SignEvent::SessionDelete { .. } => break,
        _ => {}
    }
}
```

`SignClient::snapshot()` returns serializable state (keys, pairings,
sessions, pending requests). Pass it to `SignClientBuilder::snapshot` to
resume after a restart. Messages that arrived while the client was offline
are delivered by the relay on resubscription. The snapshot contains private
keys, so store it encrypted.

### The relay server

`RelayServer` keeps published messages for their TTL and pushes them to every
subscriber that hasn't acknowledged them yet, including subscribers that only
show up later. It supports the `irn_*` methods and the newer
`wc_proposeSession`/`wc_approveSession` calls of recent JS SDKs. Clients
authenticate with their relay JWT, and invalid tokens are refused with `401`.
Use it in-process for tests (`server.connector("client-id")`) or over WebSocket
(`server.listen(addr)`). It is meant for development and private setups. It has
no rate limiting, persistence or clustering.

## Interoperability

* `tests/js_vectors.rs` holds vectors produced by the JS SDK from fixed
  inputs: derived key, topic, all three envelope types, `did:key`, the full
  relay JWT, the pairing URI, and the subscription id. `interop/js/vectors.mjs`
  regenerates them.
* `tests/js_utils.rs`, `tests/js_core.rs` and `tests/js_sign_client.rs` port
  the JS SDK's own test suites (`@walletconnect/utils`, `core` and
  `sign-client` 2.26.0) to this crate. [`docs/js-test-port.md`](docs/js-test-port.md)
  maps every JS test to its port, or says why it has none.
* `interop/run.sh` starts this crate's relay and runs a full session (pair,
  propose, approve, settle, event, request/response, rejection, ping, extend,
  delete) for every combination:

  ```
  $ interop/run.sh
  ok   js-dapp_js-wallet
  ok   js-dapp_rust-wallet
  ok   rust-dapp_js-wallet
  ok   rust-dapp_rust-wallet
  ```

Compatibility choices worth knowing:

* Publishing uses `irn_publish`/`irn_subscribe`, which every relay supports.
  The client also exposes `propose_session`/`approve_session` for the combined
  relay calls.
* Like the reference SDK, `wc_sessionDelete` gets no response, and unknown
  methods (e.g. `wc_sessionAuthenticate`) are ignored rather than answered
  with an error. Otherwise the dapp's fallback to a normal proposal would
  break.
* Out-of-order `wc_sessionUpdate`s and events are discarded by comparing the
  timestamps embedded in request ids, as the reference SDK does.
* Either peer may extend a session. The spec is ambiguous here, and the
  reference SDK lets dapps call `extend` too.
* Pairing the same URI again while its proposal is unanswered emits the
  proposal again. When a dapp settles a session, it deletes its older pairings
  with the same wallet (same metadata URL).
* Unlike the reference SDK 2.26, `connect` sends `requiredNamespaces` as given
  instead of folding them into `optionalNamespaces`, wallets get every
  session request right away instead of one at a time, and an active pairing
  lives for 30 days (as the pairing spec says) rather than five minutes.

## Not implemented

One-click authentication (`wc_sessionAuthenticate`, SIWE/CACAO), link mode,
the Verify attestation API, and the Notify API.

## Development

```sh
cargo test                          # unit, vector, ported JS SDK, relay and end-to-end tests
cargo clippy --all-targets          # lint
interop/run.sh                      # live checks against the JS SDK (needs node + npm)
```

## License

GPL-3.0-only, see [LICENSE](LICENSE).
