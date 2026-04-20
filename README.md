# @niko122/middleware

Express-style middleware that obfuscates `.html`, `.css`, and `.js` responses on the fly. Every eligible response is rewritten into an encrypted bootstrap that decrypts and reassembles itself in the browser at runtime, with anti-debug traps, a devtools kill switch, env guards, and integrity checks layered on top.

It is security through obfuscation, not a replacement for real server-side secrets. The goal is to make casual viewing of source, copy-pasting of scripts, and reverse-engineering meaningfully harder, not to resist a determined, patient attacker with a disassembler.

## Timeline

| Section |
|---|
| [Quick Start](#quick-start) |
| [Loading CSS](#loading-css) |
| [CLI](#cli) |
| [Features](#features) |
| [How it obfuscates](#how-it-obfuscates) |
| [Configuration / Settings](#configuration) |
| [Programmatic API](#programmatic-api) |
| [Caveats](#caveats) |
| [License](#license) |

## Install

```bash
npm install @niko122/middleware
```

Node 16 or newer. Express is an optional peer dep (the middleware is Connect/Express-shaped; you only need Express if you want to use it in Express).

## Quick start

```js
const express = require('express');
const path = require('path');
const { middleware } = require('@niko122/middleware');

const app = express();

app.use(middleware({
  antiDebug: true,
  devtoolsTrap: true,
  integrityChecks: true,
  pbkdf2Iterations: 250000,
  closeUrl: 'https://example.com/blocked',
  debugRewriteHtml: '<h1>Access denied.</h1>',
  integrityRewriteHtml: '<h1> Access denied. </h1>',
  junkRatio: 2.0,
}));

app.use(express.static(path.join(__dirname, 'public')));

app.listen(3000);
```

Every `text/html`, `application/javascript` (or `.js` / `.mjs` by extension), and `text/css` (or `.css` by extension) response now ships as an obfuscated payload. JSON, images, fonts, downloads, and responses larger than `maxBytes` pass through untouched.

### Loading CSS

CSS mode emits JavaScript that injects a `<style>` tag at runtime, because CSS itself has no way to run a decrypter. That means you load stylesheets as scripts:

```html
<!-- instead of: <link rel="stylesheet" href="/styles.css"> -->
<script src="/styles.css"></script>
```

The middleware automatically flips the outbound `Content-Type` from `text/css` to `application/javascript` so the browser treats the response as a script.

### CLI

There is also a one-shot CLI for offline obfuscation:

```bash
npx web-middleware input.html -o output.html
npx web-middleware input.js   -o output.js
npx web-middleware input.css  -o output.js
```

Extension decides the mode (`.html`, `.htm`, `.js`, `.mjs`, `.css`).

## Features

* Three-layer cipher pipeline with a polymorphic inner layer. Source goes through a per-build random recipe of 3 to 6 operations drawn from `{XOR, ADD, SUB, ROTL, ROTR, NOT}` (each XOR gets a fresh 24 to 96 byte key), then AES-256-GCM in the middle, then AES-256-GCM on the outside. The outer key is derived with PBKDF2-SHA256 (default 250,000 iterations) from a password that is itself masked against the runtime integrity hash. Because the recipe shape changes per build, a hand-rolled offline decrypt script only works for the single build it was written against.
* Split and scattered keys. Each symmetric key is chopped into numbered chunks stored in `Object.create(null)` dictionaries and only reassembled in the derived sort order at decrypt time. Ciphertext is fragmented into `[index, bytes]` pairs that are shuffled and interleaved with decoy and junk statements, so a static scan of the payload finds no contiguous key or cipher blob.
* Decoy key triples. Several fake `(key, salt, iterations)` tuples sit alongside the real one. Only one index is ever used at runtime, but an attacker who wants to brute-force the password has to try every tuple.
* Integrity binding. When on (default for HTML), the outer password is XOR-masked with a SHA-256 of a sentinel-guarded junk region in the emitted bootstrap. Any byte changed between the sentinels breaks key derivation, which breaks AES-GCM authentication, which breaks decryption. Tampering is caught before any plaintext is exposed. AES-GCM auth tags still protect ciphertext integrity when the sentinel-mask check is off (the default for external `.js` / `.css`, where `document.currentScript.textContent` is empty).
* Anti-debug loop. A rotating `new Function('debugger')` is built with a randomized `//# sourceURL=` every call, so Chrome's "Never pause here" can only mute one invocation before the next fresh file shows up. Timing-delta checks (debug-pause slowdowns) and window-size deltas feed into strike counters that have to trip repeatedly before action.
* Multi-signal devtools detection. Weizman-style `Object.defineProperty(div, 'id', { get: ... })` getter trap. Counter-based `funcTrap.toString`, `dateTrap.toString`, and `regTrap.toString` overrides that fire the moment the inspector renders a preview. `console.table` vs `console.log` timing delta (CDP serialization is about 10x slower when devtools is attached). `console.timeStamp` CDP side-channel (attached devtools emits an inspector event per call). These survive "Deactivate breakpoints" and "Never pause here".
* Env guard. Blocks execution under Node, headless runners, and contexts missing `window`, `document`, `navigator`, `crypto.subtle`, `TextEncoder`, or `TextDecoder`. Makes server-side prerendering and dumb scrapers fail loudly before decrypt.
* Opaque predicates. Always-false guards emitted inline at the top of the bootstrap. Trivially true at runtime, non-trivial for static analysis tools that do not constant-fold.
* Junk interleaving. Generated random functions, loops, and predicates are spliced between every real statement at a tunable `junkRatio` so the decompiled flow is buried under noise.
* Kill switch. When the anti-debug or devtools trap fires the bootstrap slots `debugRewriteHtml` into `document.documentElement.innerHTML`, calls `window.stop()`, nulls `window.opener`, and navigates to `closeUrl` (or `about:blank` if unset). When the integrity / tamper trap fires it slots `integrityRewriteHtml` instead and throws. Both fall back to the legacy `rewriteHtml` if unset.
* Streaming-safe middleware. Wraps `res.write` and `res.end` so the full body is buffered only when it is going to be rewritten. Responses bigger than `maxBytes` (default 5 MiB), pre-compressed responses (`Content-Encoding: gzip`, `br`, etc.), `HEAD` / `OPTIONS` requests, and 204 / 205 / 304 statuses flush straight through. `ETag` is removed from rewritten responses because the body is no longer byte-stable across requests.
* Include / exclude matching. Per-URL allow and deny lists accept regexes, substrings, functions, or arrays of those. Evaluated as include-first, then exclude.
* Source map scrubbing. `/*# sourceMappingURL=... */` and `//# sourceMappingURL=...` lines are stripped before obfuscation so an attacker cannot pivot from the payload to the original source.

## How it obfuscates

Every outbound HTML, JS, or CSS response goes through the same pipeline. What changes between the three modes is the final bootstrap wrapper (how the decrypted plaintext gets back into the page).

1. **Strip source maps.** `sourceMappingURL` comments are removed from the source.
2. **Layer 1, polymorphic recipe.** A random recipe of 3 to 6 operations is generated per build. Each operation is drawn from a 6-op alphabet: XOR (with a random 24 to 96 byte key), ADD (scalar), SUB (scalar), ROTL (1 to 7 bits), ROTR (1 to 7 bits), and NOT (bitwise complement). The plaintext is run through the recipe in order. The recipe itself, along with every key and scalar it uses, is emitted into the bootstrap alongside a tiny interpreter that walks it in reverse to decrypt. **Because the recipe shape, op mix, step count, and key sizes all change per build, a hand-rolled re-implementation of one build's decrypt algorithm does not work on any other build.** This is the polymorphism layer, added in 0.2.3 to defeat offline transliteration attacks.
3. **Layer 2, AES-256-GCM (middle).** Encrypt layer-1 output with a random AES-256 key and IV, prepending the IV and appending the auth tag.
4. **Layer 3, AES-256-GCM (outer).** A fresh 32-byte password is generated. PBKDF2-SHA256 with a random salt and 250,000 iterations (configurable) derives the actual AES key. Layer-2 output is encrypted under that key with a random IV, again prepending IV and appending auth tag.
5. **Mask the outer password against runtime integrity.** A block of junk statements is wrapped between two random sentinels and emitted into the bootstrap. The outer password is XORed with SHA-256 of that sentinel-guarded region. At runtime the bootstrap finds the region via `indexOf(startSentinel)` on `document.currentScript.textContent`, hashes it, and unmasks. Any tampering between the sentinels changes the hash, which yields the wrong password, which fails the AES-GCM auth tag. Off by default for external `.js` / `.css` because an external script's `document.currentScript.textContent` is empty.
6. **Split keys into scattered chunks.** Every XOR key in the recipe (there can be zero, one, two, or more per build) is cut into N chunks (default 8), each chunk stored as a numeric-keyed entry in a nested `Object.create(null)` dictionary under its step index. The middle-AES key gets the same treatment. At decrypt time the bootstrap does `Object.keys(...).sort()` to rebuild each key.
7. **Fragment the ciphertext.** Layer-3 output is chopped into randomly-sized slices (default between 24 and 48 bytes each). Each slice becomes a `[originalIndex, bytes]` pair. The pairs are shuffled. The decrypter sorts them back by `originalIndex` before concatenating.
8. **Emit decoy key triples.** Several fake `(maskedKey, salt, iterations)` entries are generated and put in an array alongside the real one. A single `realIdx` points at the one that actually works. Only the real index is used at runtime, so decoys cost the runtime nothing; a brute-forcer has to try every triple.
9. **Interleave junk.** Every real declaration is surrounded by generated junk functions, loops, conditionals, and opaque predicates at the configured `junkRatio`. The result is a pile of statements in which the real logic is a minority.
10. **Emit env guard.** Synchronous guard at the top of the IIFE. Throws and wipes the page if `process.versions.node`, `global.process`, or missing browser globals indicate a non-browser runtime.
11. **Emit opaque predicate.** Always-false expression (`!((a*b) % a === 0)`) wrapped around an `onTamper` branch. Trivially dead code at runtime, looks alive to static analyzers.
12. **Emit sentinel-guarded junk region.** Between two random `/*START*/` and `/*END*/` markers used by the integrity hash.
13. **Emit anti-debug and devtools traps.** A multi-signal setInterval loop (see Features). Every signal has a grace period and a two-strike threshold so spurious browser work does not false-positive.
14. **Emit decrypt pipeline.** `UNMASK`, `DERIVE` (PBKDF2), `AES` (AES-GCM via `crypto.subtle.decrypt`), `DECRYPT_ALL` (puts all three layers together), and `WIPE` (zeroes out every typed array once decryption is done).
15. **Emit bootstrap.** An async IIFE that `await`s `DECRYPT_ALL()`, calls `WIPE()`, runs the mode-specific output step, then nulls the plaintext variable. Any exception falls into the catch, which triggers `onTamper` (wipe `documentElement.innerHTML`, call `window.stop()`, rethrow).
16. **Mode-specific output.**
    * HTML: parse the plaintext with `DOMParser`, copy head children via `importNode`, set `body.innerHTML`, then clone every `<script>` into a fresh element with `document.createElement('script')` so the browser actually executes them. Post-load-safe, unlike `document.write()`, which Chrome silently drops from async callbacks after the parser has finished.
    * JS: indirect eval via `(0, eval)(plain)` so the decrypted code runs in global scope, not inside the bootstrap's closure.
    * CSS: `document.createElement('style')`, set `textContent`, append to `document.head`. The middleware rewrites the `Content-Type` header on the way out so the response is served as `application/javascript`.
17. **Minify and wrap.** The whole script is collapsed onto a single line (comments stripped, whitespace squashed around operators and punctuation) and shipped inside the delivery wrapper: an inline `<script>` in a stub HTML document for HTML mode, or the raw minified script body for JS / CSS mode.

The effect is that the response body an attacker downloads contains no plaintext, no contiguous keys, no contiguous ciphertext, no readable structure, and triggers its self-destruct sequence the moment anyone opens DevTools or runs it outside a real browser.

## Configuration

Full option list lives in `index.d.ts` (TypeScript types) and is also accessible at runtime via `normalizeOptions`. Highlights:

| Option | Default | Meaning |
|---|---|---|
| `antiDebug` | `true` | Install the anti-debug loop. |
| `devtoolsTrap` | `true` | Install the devtools detection signals. |
| `integrityChecks` | `true` for HTML, `false` for external JS/CSS | Mask the outer password against a runtime SHA-256 of the sentinel-guarded region. |
| `pbkdf2Iterations` | `250000` | PBKDF2-SHA256 iteration count for outer-key derivation. |
| `closeUrl` | `''` | URL the close sequence navigates to when a trap fires. |
| `debugRewriteHtml` | `''` | HTML slotted into `documentElement.innerHTML` when the anti-debug / devtools trap fires. Falls back to `rewriteHtml`. |
| `integrityRewriteHtml` | `''` | HTML slotted into `documentElement.innerHTML` when the integrity / tamper trap fires. Falls back to `rewriteHtml`. |
| `rewriteHtml` | `''` | Legacy single-knob fallback used by both traps when the split options are unset. |
| `junkRatio` | `2.0` | Roughly this many junk lines per real line. |
| `stripSourceMaps` | `true` | Strip `sourceMappingURL` comments from the source. |
| `keyFragments` | `8` | Number of chunks each symmetric key is split into. |
| `cipherFragments` | `[24, 48]` | Min/max byte size of ciphertext fragments. |
| `decoys` | `2` | Number of fake `(key, salt, iter)` triples alongside the real one. |
| `nameStyle` | `'hex'` | Identifier style for generated locals. |
| `maxBytes` | `5 * 1024 * 1024` | Skip rewriting for responses larger than this. |
| `include` | `null` | Only obfuscate URLs matching this predicate / regex / substring / array. |
| `exclude` | `null` | Skip URLs matching this predicate / regex / substring / array. |
| `onError` | `null` | Hook called when obfuscation throws. The raw body is served instead. |
| `testMode` | `false` | Disable every trap. Round-trip harness only. Do not use in production. |

### Escape hatches

* **Disable everything for a debugging session.** `middleware({ ... })` reads `testMode: true` to skip traps. The example and stress server expose this via an `INSPECT=1` env flag (`INSPECT=1 node server.js`).
* **Skip specific routes.** Pass `exclude: ['/healthz', '/metrics', /\.svg$/i]` and those URLs bypass the rewriter entirely.
* **Large responses.** Anything bigger than `maxBytes` is streamed straight through. Tune up if you have legitimately large assets you want protected.

## Programmatic API

```js
const {
  middleware,
  obfuscateHtml,
  obfuscateJs,
  obfuscateCss,
  normalizeOptions,
} = require('@niko122/middleware');

const encrypted = obfuscateHtml(htmlString, { antiDebug: true });
```

All four accept the same option shape. `middleware(options)` returns a `(req, res, next) => void` handler usable with Express 4 / 5, Connect, Polka, and anything else that speaks Node's HTTP shape.

## Caveats

* Obfuscation is not encryption in the cryptographic sense. The decryption key ships with the payload. The point is to raise reverse-engineering cost, not to prevent it outright.
* Anti-debug tripping on a legitimate user is painful. In production, consider making `closeUrl` an informative page rather than a hard redirect.
* CSS served as JavaScript means it cannot be loaded via `<link rel="stylesheet">`. Keep that in mind when migrating an existing site.
* PBKDF2 at 250k iterations costs tens to low-hundreds of milliseconds on the user's CPU at page load. Lower if you need faster first paint; higher if you want to punish brute-forcers more.
* Integrity checks only work when the emitted script is readable at runtime, which means inline `<script>` contexts. External `.js` and `.css` have empty `document.currentScript.textContent` and must fall back to AES-GCM auth tags for tamper detection. The middleware handles this automatically.

## License

MIT. See [LICENSE](./LICENSE).
