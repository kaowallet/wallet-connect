// Reference-SDK dapp: connect, wait for approval, personal_sign, ping, extend,
// disconnect.
// Prints the pairing URI on a line starting with "URI ".
import { getSdkError } from "@walletconnect/utils";
import { ADDRESS, fail, init, log } from "./common.mjs";

const client = await init("JS dapp");
let sawEvent = false;
client.on("session_event", ({ params }) => {
  log("event", params.event.name, JSON.stringify(params.event.data), "on", params.chainId);
  sawEvent = true;
});

const { uri, approval } = await client.connect({
  requiredNamespaces: {
    eip155: { chains: ["eip155:1"], methods: ["personal_sign"], events: ["accountsChanged"] },
  },
  optionalNamespaces: {
    eip155: { chains: ["eip155:10"], methods: ["eth_sendTransaction"], events: ["chainChanged"] },
  },
});
console.log(`URI ${uri}`);

const session = await approval();
log("session", session.topic, "with", session.peer.metadata.name);
log("namespaces", JSON.stringify(session.namespaces));
const account = session.namespaces.eip155.accounts.find((a) => a.startsWith("eip155:1:"));
if (!account) fail("no eip155:1 account granted");

const result = await client.request({
  topic: session.topic,
  chainId: "eip155:1",
  request: { method: "personal_sign", params: ["0x48656c6c6f", account.split(":")[2]] },
});
log("personal_sign ->", result);

try {
  await client.request({
    topic: session.topic,
    chainId: "eip155:10",
    request: { method: "eth_sendTransaction", params: [{ from: ADDRESS }] },
  });
  fail("eth_sendTransaction should have been rejected");
} catch (e) {
  log("eth_sendTransaction rejected:", e.code, e.message);
  if (e.code !== 5000) fail(`unexpected rejection ${JSON.stringify(e)}`);
}

await client.ping({ topic: session.topic });
log("ping ok");

// The reference SDK lets dapps extend sessions too; the wallet must accept it.
const { acknowledged: extended } = await client.extend({ topic: session.topic });
await extended();
log("extend ok");

// Give the wallet's accountsChanged event time to arrive.
for (let i = 0; i < 50 && !sawEvent; i++) await new Promise((r) => setTimeout(r, 100));
if (!sawEvent) fail("no session_event received");

await client.disconnect({ topic: session.topic, reason: getSdkError("USER_DISCONNECTED") });
log("disconnected");
console.log("JS DAPP OK");
process.exit(0);
