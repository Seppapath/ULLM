// SPDX-License-Identifier: Apache-2.0
//
// Headless browser-shape clickthrough.
//
// We avoid a heavy Playwright/Puppeteer dependency. Instead:
//
// 1. Spawn the static server (serves the same HTML the human-driven demo uses).
// 2. Fetch /demo/index.html and assert the expected DOM hooks are present:
//    - the "Run encrypted session" button
//    - the input fields the handler reads
//    - the <script type="module"> that imports the wasm
// 3. Fetch /pkg/ullm_ts.js and /pkg/ullm_ts_bg.wasm — assert content-types
//    + non-zero bytes (the resources the page would load).
// 4. Simulate the click handler by running run_e2e.mjs against the live
//    gateway with the SAME WASM artifact (loaded from pkg-node/). That is
//    cryptographically equivalent to a real browser click since the JS
//    click handler delegates to the WASM API.
//
// A real Chromium drive lands when puppeteer / playwright is installed; for
// now this proves the static assets render and the WASM API completes a
// session end-to-end.

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const STATIC_PORT = 8123;

function startServer() {
  const child = spawn(process.execPath, [path.join(here, "serve.mjs")], {
    env: { ...process.env, PORT: String(STATIC_PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return new Promise((res, rej) => {
    child.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("serving")) res(child);
    });
    child.stderr.on("data", (e) => process.stderr.write(`[serve] ${e}`));
    setTimeout(() => rej(new Error("static server didn't start in time")), 5000);
  });
}

async function fetchText(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
  return [r, await r.text()];
}

async function fetchBytes(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
  return [r, new Uint8Array(await r.arrayBuffer())];
}

function expect(cond, label) {
  if (!cond) {
    console.error(`✗ assert failed: ${label}`);
    process.exit(1);
  }
  console.log(`  ✓ ${label}`);
}

async function main() {
  const server = await startServer();
  try {
    const base = `http://127.0.0.1:${STATIC_PORT}`;
    console.log("→ fetching /demo/index.html");
    const [htmlResp, html] = await fetchText(`${base}/demo/index.html`);
    expect(htmlResp.headers.get("content-type")?.includes("text/html"), "index.html content-type");
    expect(html.includes('id="run"'), 'page has "Run encrypted session" button');
    expect(html.includes('id="gw"'), "page has gateway input");
    expect(html.includes('id="trustRoot"'), "page has trust-root input");
    expect(html.includes('id="teePk"'), "page has tee-pk input");
    expect(html.includes('id="weightCommit"'), "page has weight-commit input");
    expect(html.includes('id="prompt"'), "page has prompt input");
    expect(html.includes('import init, { ClientSession } from "../pkg/ullm_ts.js"'), "page imports WASM");

    console.log("→ fetching /pkg/ullm_ts.js");
    const [jsResp, js] = await fetchText(`${base}/pkg/ullm_ts.js`);
    expect(jsResp.headers.get("content-type")?.includes("javascript"), "ullm_ts.js content-type");
    expect(js.length > 5000, `ullm_ts.js non-trivial (${js.length} bytes)`);
    expect(js.includes("ClientSession"), "ullm_ts.js exports ClientSession");

    console.log("→ fetching /pkg/ullm_ts_bg.wasm");
    const [wasmResp, wasm] = await fetchBytes(`${base}/pkg/ullm_ts_bg.wasm`);
    expect(wasmResp.headers.get("content-type")?.includes("wasm"), "wasm content-type");
    expect(wasm.length > 100_000, `wasm bytes > 100KB (got ${wasm.length})`);
    expect(wasm[0] === 0x00 && wasm[1] === 0x61 && wasm[2] === 0x73 && wasm[3] === 0x6d, "wasm magic header");

    console.log("→ simulating button click (programmatic clickthrough)");
    // Pull the runtime keys from the live gateway, then drive run_e2e.mjs.
    const KEYS_URL = process.env.GATEWAY ?? "https://127.0.0.1:9100";
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const keysResp = await fetch(`${KEYS_URL}/v1/devkeys`);
    if (!keysResp.ok) throw new Error(`devkeys → HTTP ${keysResp.status}`);
    const keys = await keysResp.json();

    const env = {
      ...process.env,
      GATEWAY: KEYS_URL,
      TRUST_ROOT: keys.trust_root_hex,
      TEE_PK: keys.tee_receipt_pk_hex,
      WEIGHT_COMMIT: keys.weight_commit_hex,
      PROMPT: process.env.PROMPT ?? "hello from the headless clickthrough",
    };
    const e2e = spawn(process.execPath, [path.join(here, "run_e2e.mjs")], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    e2e.stdout.on("data", (d) => (stdout += d.toString()));
    e2e.stderr.on("data", (d) => (stderr += d.toString()));
    const code = await new Promise((res) => e2e.on("exit", (c) => res(c)));
    if (code !== 0) {
      console.error("✗ run_e2e.mjs failed");
      console.error(stdout);
      console.error(stderr);
      process.exit(1);
    }
    expect(stdout.includes("E2E PASS"), "WASM session completed end-to-end");
    expect(stdout.includes("✓ receipt:"), "signed receipt verified");

    console.log("✓ headless clickthrough PASS");
  } finally {
    server.kill();
  }
}

main().catch((e) => {
  console.error(`✗ clickthrough FAIL: ${e?.stack ?? e}`);
  process.exit(1);
});
