// SPDX-License-Identifier: Apache-2.0
//
// Node E2E runner for the WASM browser bindings.
//
// Drives the same code path the HTML demo's "Run encrypted session" button
// triggers, but does so headlessly so we can assert on every step. Hits a
// live ullm-gateway over HTTPS + WSS, ignoring the self-signed cert.
//
// Usage:
//   GATEWAY=https://127.0.0.1:9100 \
//   TRUST_ROOT=<hex32> TEE_PK=<hex32> \
//   node bindings/ts/demo/run_e2e.mjs

import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
import { TextEncoder, TextDecoder } from "node:util";
import process from "node:process";
import WebSocket from "ws";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.TextEncoder) globalThis.TextEncoder = TextEncoder;
if (!globalThis.TextDecoder) globalThis.TextDecoder = TextDecoder;

const require = createRequire(import.meta.url);
const wasm = require("../pkg-node/ullm_ts.js");

const must = (k) => {
  const v = process.env[k];
  if (!v) {
    console.error(`missing env: ${k}`);
    process.exit(2);
  }
  return v;
};

const GATEWAY = (process.env.GATEWAY ?? "https://127.0.0.1:9100").replace(/\/$/, "");
const TRUST_ROOT_HEX = must("TRUST_ROOT");
const TEE_PK_HEX = must("TEE_PK");
const WEIGHT_COMMIT_HEX = must("WEIGHT_COMMIT");
const PROMPT = process.env.PROMPT ?? "say hi to the world";

const hexDecode = (s) => Uint8Array.from(s.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const hex = (a) =>
  Array.from(a)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

async function main() {
  // Trust the gateway's self-signed cert for the dev path.
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

  const trustRoot = hexDecode(TRUST_ROOT_HEX);
  const teePk = hexDecode(TEE_PK_HEX);
  const weightCommit = hexDecode(WEIGHT_COMMIT_HEX);
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);

  console.log(`→ fetching attestation bundle from ${GATEWAY}/v1/attest`);
  const resp = await fetch(`${GATEWAY}/v1/attest?nonce=${hex(nonce)}`);
  if (!resp.ok) throw new Error(`attest HTTP ${resp.status}`);
  const bundle = new Uint8Array(await resp.arrayBuffer());
  console.log(`  bundle: ${bundle.byteLength} bytes`);

  console.log("→ starting WASM client session (weight cross-binding enforced)");
  const now = BigInt(Math.floor(Date.now() / 1000));
  const session = wasm.ClientSession.start(
    bundle,
    nonce,
    trustRoot,
    teePk,
    weightCommit,
    now,
  );

  const wsUrl = GATEWAY.replace(/^http/, "ws") + "/v1/stream";
  console.log(`→ connecting WS ${wsUrl}`);
  const ws = new WebSocket(wsUrl, { rejectUnauthorized: false });
  ws.binaryType = "arraybuffer";
  await new Promise((res, rej) => {
    ws.once("open", res);
    ws.once("error", rej);
  });

  const queue = [];
  let resolver = null;
  ws.on("message", (data, isBinary) => {
    const bytes = isBinary ? new Uint8Array(data) : new Uint8Array(Buffer.from(data));
    if (resolver) {
      const r = resolver;
      resolver = null;
      r(bytes);
    } else {
      queue.push(bytes);
    }
  });
  const nextFrame = () =>
    new Promise((res) => {
      if (queue.length > 0) res(queue.shift());
      else resolver = res;
    });

  console.log("→ sending ClientHello");
  ws.send(session.clientHelloBytes());

  const serverHello = await nextFrame();
  console.log(`  ServerHello: ${serverHello.byteLength} bytes`);
  session.complete(serverHello);

  console.log(`→ encrypting prompt: "${PROMPT}"`);
  const promptFrame = session.encrypt(new TextEncoder().encode(PROMPT));
  ws.send(promptFrame);

  console.log("→ decrypting streamed response:");
  let assembled = "";
  for (;;) {
    const frame = await nextFrame();
    const r = session.decrypt(frame);
    if (r.text) {
      assembled += r.text;
      process.stdout.write(`  ← ${r.text}\n`);
    }
    if (r.endOfTurn) break;
  }
  console.log(`  full response: ${assembled}`);

  console.log("→ verifying signed receipt");
  const receiptBytes = await nextFrame();
  const receipt = session.verifyReceipt(receiptBytes);
  console.log(
    `  ✓ receipt: model=${receipt.model} input=${receipt.inputTokens} output=${receipt.outputTokens} session=${receipt.sessionIdHex}`
  );

  ws.close();

  // Sanity assertions
  if (!assembled.startsWith("echo:")) {
    console.error(`unexpected response: ${assembled}`);
    process.exit(1);
  }
  if (receipt.outputTokens < 1) {
    console.error("zero output tokens");
    process.exit(1);
  }
  console.log("✓ E2E PASS");
}

main().catch((e) => {
  console.error(`✗ E2E FAIL: ${e?.stack ?? e}`);
  process.exit(1);
});
