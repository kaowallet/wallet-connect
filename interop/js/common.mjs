import { SignClient } from "@walletconnect/sign-client";

export const RELAY_URL = process.env.RELAY_URL ?? "ws://127.0.0.1:8080";
export const ADDRESS = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

export function log(...args) {
  console.log(`[js ${process.argv[1].split("/").pop()}]`, ...args);
}

export function fail(message) {
  console.error(`[js] FAIL: ${message}`);
  process.exit(1);
}

export async function init(name) {
  // Exit if anything hangs.
  setTimeout(() => fail("timed out"), Number(process.env.TIMEOUT_MS ?? 60000)).unref();
  return SignClient.init({
    projectId: "local-interop",
    relayUrl: RELAY_URL,
    logger: process.env.WC_LOG ?? "silent",
    metadata: {
      name,
      description: `${name} (reference JavaScript SDK)`,
      url: "https://example.com",
      icons: [],
    },
  });
}
