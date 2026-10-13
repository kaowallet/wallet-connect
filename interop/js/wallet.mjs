// Reference-SDK wallet: pair, approve, answer requests, emit an event, exit on delete.
//   node wallet.mjs 'wc:...'
import { buildApprovedNamespaces, getSdkError } from "@walletconnect/utils";
import { ADDRESS, fail, init, log } from "./common.mjs";

const uri = process.argv[2];
if (!uri) fail("usage: node wallet.mjs <uri>");
const client = await init("JS wallet");
const chains = ["eip155:1", "eip155:10", "eip155:137"];

client.on("session_proposal", async ({ id, params }) => {
  log("proposal from", params.proposer.metadata.name);
  try {
    const namespaces = buildApprovedNamespaces({
      proposal: params,
      supportedNamespaces: {
        eip155: {
          chains,
          methods: ["personal_sign", "eth_sendTransaction"],
          events: ["accountsChanged", "chainChanged"],
          accounts: chains.map((c) => `${c}:${ADDRESS}`),
        },
      },
    });
    const { topic, acknowledged } = await client.approve({ id, namespaces });
    await acknowledged();
    log("approved", topic);
    await client.emit({ topic, chainId: "eip155:1", event: { name: "accountsChanged", data: [ADDRESS] } });
    log("emitted accountsChanged");
  } catch (e) {
    fail(`approve failed: ${e.message}`);
  }
});

client.on("session_request", async ({ topic, id, params }) => {
  log("request", params.request.method, JSON.stringify(params.request.params), "on", params.chainId);
  const response =
    params.request.method === "personal_sign"
      ? { id, jsonrpc: "2.0", result: "0x" + "22".repeat(65) }
      : { id, jsonrpc: "2.0", error: getSdkError("USER_REJECTED") };
  await client.respond({ topic, response });
});

client.on("session_ping", ({ topic }) => log("ping on", topic));
client.on("session_delete", ({ topic, params }) => {
  log("session deleted", topic, JSON.stringify(params ?? {}));
  console.log("JS WALLET OK");
  process.exit(0);
});

await client.pair({ uri });
log("paired");
