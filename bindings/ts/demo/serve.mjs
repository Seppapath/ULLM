// SPDX-License-Identifier: Apache-2.0
// Tiny static server for the browser demo. Serves bindings/ts/ at the URL
// the demo's <script type="module" src="../pkg/ullm_ts.js"> import expects.

import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const PORT = Number(process.env.PORT ?? 8000);

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript",
  ".mjs": "application/javascript",
  ".wasm": "application/wasm",
  ".css": "text/css",
  ".json": "application/json",
};

http
  .createServer(async (req, res) => {
    try {
      let url = decodeURIComponent(req.url.split("?")[0]);
      if (url === "/" || url === "") url = "/demo/index.html";
      const abs = path.normalize(path.join(root, url));
      if (!abs.startsWith(root)) {
        res.writeHead(403);
        res.end("forbidden");
        return;
      }
      const body = await fs.readFile(abs);
      const ext = path.extname(abs);
      // P6 demo-security: a defense-in-depth CSP and the cross-origin
      // isolation headers needed for `WebAssembly.instantiate` to work
      // across browsers. The demo loads only same-origin resources
      // (`pkg/ullm_ts.js` and `pkg/ullm_ts_bg.wasm`) plus dynamically
      // connects via WSS to the user-supplied gateway URL — that's
      // covered by `connect-src https: wss:`.
      res.writeHead(200, {
        "Content-Type": mime[ext] ?? "application/octet-stream",
        "Cache-Control": "no-store",
        "Content-Security-Policy":
          "default-src 'self'; " +
          "script-src 'self' 'wasm-unsafe-eval'; " +
          "style-src 'self' 'unsafe-inline'; " +
          "connect-src 'self' https: wss:; " +
          "object-src 'none'; " +
          "base-uri 'self'; " +
          "form-action 'self'; " +
          "frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      });
      res.end(body);
    } catch (e) {
      res.writeHead(404);
      res.end(String(e?.message ?? e));
    }
  })
  .listen(PORT, () => {
    console.log(`serving bindings/ts/ at http://127.0.0.1:${PORT}/`);
  });
