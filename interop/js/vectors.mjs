// Regenerates the vectors pinned in tests/js_vectors.rs from the reference SDK.
//   npm install && node vectors.mjs
import * as utils from "@walletconnect/utils";
import * as relayAuth from "@walletconnect/relay-auth";

// RFC 7748 §6.1 test keys.
const privA = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const pubA = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const pubB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

const symKey = utils.deriveSymKey(privA, pubB);
const topic = utils.hashKey(symKey);
const iv = "000102030405060708090a0b";
const message = JSON.stringify({ id: 1700000000000123, jsonrpc: "2.0", method: "wc_sessionPing", params: {} });
const seed = new Uint8Array(32).map((_, i) => i);
const keyPair = relayAuth.generateKeyPair(seed);
const iss = relayAuth.encodeIss(keyPair.publicKey);

console.log(
  JSON.stringify(
    {
      symKey,
      topic,
      message,
      type0: utils.encrypt({ symKey, message, iv }),
      type1: utils.encrypt({ symKey, message, iv, type: 1, senderPublicKey: pubA }),
      type2: utils.encodeTypeTwoEnvelope(message),
      iss,
      jwt: await relayAuth.signJWT(
        "c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e",
        "wss://relay.walletconnect.org",
        86400,
        keyPair,
        1700000000,
      ),
      uri: utils.formatUri({
        protocol: "wc",
        version: 2,
        topic,
        symKey,
        relay: { protocol: "irn" },
        expiryTimestamp: 1700000300,
      }),
      subscriptionId: utils.hashMessage(topic + iss),
    },
    null,
    2,
  ),
);
