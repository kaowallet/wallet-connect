# The JavaScript SDK's tests, ported

`tests/js_utils.rs`, `tests/js_core.rs` and `tests/js_sign_client.rs` port the
test suites of the reference SDK, [WalletConnect/walletconnect-monorepo] at
tag `@walletconnect/sign-client@2.26.0` (commit `63094dc`), to this crate.
This page maps every JS test to its port, or says why it has none, and lists
what the port found.

[WalletConnect/walletconnect-monorepo]: https://github.com/WalletConnect/walletconnect-monorepo

## How the tests are ported

* **Fixtures** (keys, envelopes, namespaces, metadata) are copied verbatim
  from `test/shared/values.ts` and the spec files; `tests/common/mod.rs` holds
  the sign-client ones.
* **Relay.** The JS suites run against a live relay. The ports use the
  in-process `RelayServer`, so they run offline in a few seconds.
* **`testConnectMethod`** is ported as `common::test_connect`, with the same
  assertions on both sides' sessions and pairings.
* **Private engine handlers.** Some JS tests call private methods such as
  `engine.onSessionUpdateRequest(topic, payload)`. Their ports put the same
  message on the wire with `common::RawPeer`, which encrypts and decrypts
  payloads by hand. To speak for one side of an existing session, it connects
  under that side's client id; the relay does not echo a message to its
  publisher's client id, so only the other side sees it.
* **Spies.** Where the JS tests spy on `relayer.publish` or
  `provider.request`, the ports record frames with `common::Tap`, a connector
  that sits between a client and the relay. It can also cut the connection.
* **Keychain checks** read the client's `Snapshot` as JSON.
* **Clock.** The JS tests move the system clock with fake timers. The ports
  use short real expiries instead (a peer driven by hand settles a session,
  proposes or requests with a 2-second expiry), or wait a second where an
  expiry has to change.
* **Dynamic typing.** Many `validation.spec.ts` cases pass `123`, `""` or
  `undefined` where a string is expected. Rust's types rule most of these
  out, so only the ones with a meaningful counterpart are ported.

## What the port found

The first run of the ports failed in 12 places, each a real difference from
the reference SDK. Reading the reference alongside the tests turned up one
more (the event error code). The fixes are in `src/`.

| Finding | Effect before the fix | Fix | Tests |
|---|---|---|---|
| Deep-link URIs `wc://wc:<topic>@2?…` (Android) and `wc:wc:<topic>@2?…` (iOS) parsed to topic `wc:<topic>` | The wallet subscribed to a topic nobody publishes on; pairing silently never completed | `uri.rs` strips the repeated scheme | `js_core` `can_pair_via_provided_{android,ios}_deeplink_uri` |
| Base64 URIs without padding (`toBase64(uri, true)`, e.g. Telegram) rejected | `pair()` failed with "missing `wc:` scheme" | Base64 decoding ignores padding | `js_core` `can_pair_via_base64_provided_uri`, `js_utils` `should_parse_unpadded_base64_uri` |
| `wc_sessionExtend` from the dapp answered with 3004 | **Interop failure**: a JS dapp's `extend()` against a Rust wallet rejected, and the two sides disagreed on the expiry. Reproduced with `interop/run.sh` (`js-dapp_rust-wallet` failed with `{code: 3004}`) | Either peer may extend, on both the sending and receiving side | `client::extend::*`, `interop/js/dapp.mjs`, `examples/dapp.rs` |
| Blank event names in namespaces reported as 5101 (Unsupported methods); whitespace-only names accepted | Wrong error code to the peer | Events are 5102; names are trimmed before the emptiness check | `namespaces::tests::proposal_namespace_validation` |
| Pairing the same URI again did not show the unanswered proposal again | A wallet that closed before deciding could not get the proposal back | `pair` emits the proposals still waiting on that pairing | `client::connect::should_emit_session_proposal_on_every_pair_attempt_with_same_uri` |
| Older pairings with the same wallet were kept | Every `connect` added an active pairing, kept for 30 days with a relay subscription | After settlement the dapp deletes its other pairings with the same peer metadata URL and tells the wallet (`wc_pairingDelete`) | `client::connect::should_remove_duplicate_pairing`, `should_cleanup_duplicate_pairings` |
| `scopedProperties` not checked against the namespaces | Properties for namespaces nobody asked for or granted went out | `connect`/`approve_with` reject keys outside the requested/approved namespaces | `validation::{connect,approve}::should_reject_*_with_scoped_properties_not_in_namespaces` |
| `null` property values accepted | Sent to the peer as is | `sessionProperties`/`scopedProperties` need a value per key | `validation::connect::should_reject_session_properties_without_a_value` |
| `reject()` accepted a reason with code 0 or an empty message | Meaningless rejection sent to the dapp | Reason needs a non-zero code and a message | `validation::reject::throws_when_invalid_reason_is_provided` |

## Deliberate differences

These differences are kept. The tests assert this crate's behavior and say so.

* **`requiredNamespaces`.** Since 2.26, the reference `connect()` folds
  `requiredNamespaces` into `optionalNamespaces` and sends `{}` as required.
  This crate sends them as given. Both are accepted by either SDK's wallet.
  (`should assign requiredNamespaces to optionalNamespaces` is not ported.)
* **Request queue.** The reference wallet emits one `session_request` at a
  time and waits for `respond` before the next one. This crate emits each one
  as it arrives, which matches `signConfig.disableRequestQueue: true`
  (`requests_are_emitted_without_waiting_for_earlier_answers`).
* **Active pairing expiry.** The reference SDK keeps an activated pairing for
  five more minutes. This crate follows the pairing spec ("Active pairings
  should have a 30 days expiry period"); see `can_activate_a_pairing`. As a
  consequence, reusing a pairing with a JS wallet after five minutes fails,
  because that wallet has dropped it. The reference SDK deprecates pairing
  reuse.
* **Combined relay methods.** The reference SDK publishes proposals and
  approvals with `wc_proposeSession`/`wc_approveSession` and attaches TVF
  data (`correlationId` etc.). This crate uses `irn_publish` with the same
  tags, TTLs and prompts (`publishes_with_the_reference_rpc_options`); the
  combined calls are available on `RelayClient`.
* **`wc_sessionEvent` response.** The reference dapp does not answer events.
  This crate answers with `true`, which a JS wallet ignores.
* **Unconfirmed approvals.** The reference `approve()` deletes the session
  whenever publishing the approval fails, including after a timeout, when
  the dapp may already have the session. This crate keeps the session unless
  the relay refused the settlement or never got it, and
  `Approved::acknowledged` tells whether the dapp has it (`tests/sign.rs`
  `approve_*`).
* **Local validation errors** are typed: unknown records are `NoSession`,
  `NoPairing`, `NoProposal` and `NoRequest`, and unsupported chains, methods
  and events are 5100/3001/3002 where the reference throws code 5 ("Missing
  or invalid.") with a message.
* **Stricter checks.** Proposal chains must belong to their namespace key
  (5104), CAIP-2/10 parts must be non-empty, and the dapp checks that the
  settled namespaces conform to its required namespaces. The reference SDK
  does none of these.
* **Auto-reject.** The reference `onSessionProposeRequest` does not await
  `isValidConnect`, so an invalid proposal is never auto-rejected there. This
  crate auto-rejects it with tag 1121 (`should_use_auto_reject_tag_for_invalid_proposals`).
* **Wire details.** `irn_publish` omits `prompt: false`, and the relay URL's
  query parameters are in a different order.

## Mapping

✓ ported · ✓\* ported with a difference noted above · — not ported (reason given)

### `packages/utils/test` → `tests/js_utils.rs`

| JS test | Port |
|---|---|
| crypto: `generateRandomBytes32`, `generateKeyPair`, `(cross-test)`, `(same random)`, `deriveSymKey`, `hashKey`, `hashMessage` | ✓ `crypto::*` |
| crypto: `encrypt`/`decrypt` type 0/1, with and without link mode; `encode`/`decode` type 2 | ✓ `crypto::*`. "encrypt" compares the reference envelope's IV and sealed bytes and its re-encoding; this crate never encodes base64url (link mode is not implemented) |
| crypto: verify v2 JWT (3 tests) | — Verify API not implemented |
| uri: `formatUri`, `parseUri`, `parseTopic`, base64 URI | ✓ `uri::*` (plus unpadded base64) |
| validators: `isSessionCompatible` | — no `find()` |
| validators: configurations 1–4, invalid accounts/namespace/methods/CAIP-2 key | ✓ `validators::*` |
| validators: `buildApprovedNamespaces` configs 1–13, failure configs 1–7, unmatched bip122 | ✓ `build_approved_namespaces::*` |
| validators: merge namespaces cases 1–4 | ✓ `merge_namespaces::*` |
| misc: `formatRpcRelayUrl` | ✓ `misc::format_relay_rpc_url` (`ws` feature) |
| misc: `calcExpiry`, `isExpired` | ✓ `misc::*` |
| misc: `toBase64`/`fromBase64` | ✓ through `uri::should_parse_unpadded_base64_uri` |
| misc: `hasOverlap`, `getSearchParamFromURL`, deep links, `openDeeplink`, `isIframe`, `createDelayedPromise` | — internal helpers or browser-only |
| `errors.ts` tables | ✓ `misc::error_codes_and_messages_match_the_reference` |
| cacao, signatures, canton, metadata specs | — one-click auth/SIWE, TVF and browser metadata are not implemented |

### `packages/core/test` → `tests/js_core.rs`

| JS test | Port |
|---|---|
| crypto: `setSymKey`, `decode`, "should not throw on failed decrypt" | ✓ `crypto::*` |
| crypto: keychain/`isInitialized` internals, `generateSharedKey`, delete key pair/sym key | — internals; key derivation is covered in `js_utils`, key deletion by the sign-client tests through snapshots |
| pairing: `create` | ✓ `returns_the_pairing_topic_and_uri_in_expected_format` |
| pairing: pair via URI, base64 URI, Android and iOS deep links | ✓ `can_pair_via_*` |
| pairing: already exists, keychain not overridden | ✓ |
| pairing: `activate` | ✓\* `can_activate_a_pairing` (30 days) |
| pairing: `updateMetadata` | ✓ `records_the_peers_metadata` |
| pairing: ping, disconnect | ✓ |
| pairing: validations (pair, ping, disconnect) | ✓ where meaningful; type-confusion cases n/a |
| pairing: "store pairing before subscribing" | ✓ `pairing_is_rolled_back_when_subscribing_fails` |
| pairing: auto-activate, `updateExpiry`, `formatUriFromPairing`, `pairing_create` event | — no such API |
| relayer: subscribe returns id, multiple topics, resubscribe, unsubscribe | ✓ `relayer::*` |
| relayer: subscribe timeout / failure | ✓ |
| relayer: `onProviderPayload` (3 tests) | ✓ `handles_provider_payloads` |
| relayer: restart transport after connection drop | ✓ (also checks the batch resubscription) |
| relayer: explicit close | ✓ `should_not_reconnect_after_explicit_close` |
| relayer: init internals, lazy transport, heartbeat, fatal errors, reconnect guards, `connection_stalled`, mobile bundle/package checks | — JS transport internals or need the public relay; reconnection is also covered by `tests/relay.rs` |
| subscriber: request shape, subscription id, unsubscribe | ✓ |
| subscriber: batch subscribe failure | ✓ `should_not_mark_topics_as_subscribed_when_batch_subscribe_fails` |
| subscriber: storage keys, init, pending retries, `connection_stalled` | — internals |
| publisher: request shape, overriding options | ✓ `publish_calls_the_relay_with_the_expected_request_shape` |
| publisher: queue processing | — JS retry queue internals |
| messages, history, expirer, keychain, store, events, persistence, core, verify | — storage and telemetry internals with no counterpart: this crate keeps its state in memory and exports it as a `Snapshot` |

### `packages/sign-client/test` → `tests/js_sign_client.rs`

| JS test | Port |
|---|---|
| client: init, empty metadata | ✓ (metadata is required in Rust, so "without metadata" is n/a) |
| client: connect with new pairing | ✓ (the TVF/correlation-id parts: see above) |
| client: scoped properties, out-of-order URIs, session acknowledge | ✓ |
| client: remove/cleanup duplicate pairings, re-emit proposal on re-pair | ✓ (fixed) |
| client: assign required to optional namespaces | — deliberate difference |
| client: attestation/encryptedId, `sessionConfig` | — Verify and `sessionConfig` not implemented |
| client: rejected tag (skipped in JS) | ✓ `should_use_rejected_tag_for_session_propose`, plus auto-reject and all-legs RPC options |
| client: disconnect pairing/session, request queue reset | ✓ |
| client: deeplink storage | — no deep-link handling |
| client: ping (5 tests) | ✓ |
| client: pending session request, process queue, disable queue, continue after disconnect | ✓ (\*queue) |
| client: TVF params (13 chains) | — TVF not implemented |
| client: missing keychain | — a session and its key live in one record here and cannot diverge |
| client: update, update from non-controller | ✓ (the latter with a raw peer) |
| client: empty namespaces, custom expiry, optional namespace, mismatched topic, inline namespace | ✓ |
| client: Events Client (3 tests) | — telemetry not implemented |
| client: extend by A, extend by B | ✓ (fixed; the JS "by client B" test calls `A.extend`, the port really uses B) |
| client: pairing-flow event | ✓ its proposal-expiry part: `proposal_expires_on_the_wallet` |
| client: 15-minute default request expiry, dapp expiry vs. old wallet config | ✓ |
| validation: connect | ✓ non-existent pairing, no chains, inline chain, scoped properties (+ null properties); type cases n/a |
| validation: approve | ✓ scoped properties, unknown id, empty namespaces; `relayProtocol` n/a (the wallet answers on the proposal's relay) |
| validation: reject, update, extend, request, respond, ping, emit, disconnect | ✓ where meaningful |
| validation: emit `session_request` once | ✓ ten deliveries of one request id give one event |
| validation: `recentlyDeletedMap` | — no "recently deleted" bookkeeping; errors name the missing record |
| persistence: ping after restart, pending request after restart, session after dapp restart, mailbox | ✓ (snapshots instead of a database) |
| subscription cleanup: settle rejected | ✓ the dapp really rejects the settlement here |
| subscription cleanup: session expiry | ✓ |
| subscription cleanup: orphaned subscriptions (3 tests) | ✓\* `no_orphaned_subscriptions_after_a_session_lifecycle`: subscriptions follow the records, so there is nothing to sweep |
| subscription cleanup: authenticate response topic | — one-click auth not implemented |
| transport: restart, restart with delay | ✓ |
| transport: start transport on request after close | — the transport opens eagerly; `close()` is final |
| integration: connect, ping, restart, ping, disconnect | ✓ |
| concurrency | ✓ scaled down to 10 pairs × 20 events |
| events (skipped in JS) | covered by the client tests |
| push, lifecycle, canary, xregion | — need the production relay or a push webhook server |
| 1ca, auth, link-mode, wallet-pay | — not implemented |

`packages/pay` and `packages/pos-client` are separate products and out of
scope.
