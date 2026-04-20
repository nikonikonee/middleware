/**
 * @niko122/middleware - server-side response obfuscator for HTML, JS, and CSS.
 *
 * Standard usage with Express:
 *
 *   import { middleware } from '@niko122/middleware';
 *   app.use(middleware({
 *     antiDebug: true,
 *     devtoolsTrap: true,
 *     integrityChecks: true,
 *     pbkdf2Iterations: 250000,
 *     closeUrl: 'https://example.com/blocked',
 *     rewriteHtml: '<h1>Access denied.</h1>',
 *     junkRatio: 2.0,
 *   }));
 */

import type { IncomingMessage, ServerResponse } from 'http';

export type WebMiddlewareMatcher =
  | RegExp
  | string
  | ((url: string) => boolean)
  | Array<RegExp | string | ((url: string) => boolean)>;

export interface WebMiddlewareOptions {
  /**
   * Install the anti-debug loop (rotating Function('debugger') bodies with
   * random //# sourceURL values, tight trip loops, multi-signal devtools
   * detection). Defeats Chrome "Never pause here" / "Deactivate breakpoints".
   * @default true
   */
  antiDebug?: boolean;

  /**
   * Install the devtools trap: Weizman-style DefineId getter, funcToString /
   * regToString / dateToString counters, console.table and console.timeStamp
   * side-channels, size-delta check. Fires when DevTools is opened even if
   * the debugger is deactivated.
   * @default true
   */
  devtoolsTrap?: boolean;

  /**
   * Bind the outer password to a SHA-256 hash of the sentinel-guarded junk
   * region so any tampering in that region breaks key derivation. Defaults
   * to true for inline HTML (document.currentScript.textContent is
   * readable) and false for external .js / .css (textContent is empty for
   * <script src>). Pass true explicitly on JS/CSS only if you plan to
   * inline the payload.
   * @default true for HTML, false for JS/CSS
   */
  integrityChecks?: boolean;

  /**
   * Iteration count for PBKDF2-SHA256 on the outer key. Higher = slower to
   * brute-force, slower to decrypt at load time. 250k is the default
   * WebCrypto-friendly sweet spot.
   * @default 250000
   */
  pbkdf2Iterations?: number;

  /**
   * URL the anti-debug + devtools logic navigates to when a trap fires. Empty
   * string means the close sequence tries location.href='about:blank' /
   * window.close() / history.back() instead.
   * @default ''
   */
  closeUrl?: string;

  /**
   * HTML snippet to slot into document.documentElement.innerHTML before the
   * close sequence runs. Useful for leaving a visible "access denied" message
   * rather than a blank page.
   * @default ''
   */
  rewriteHtml?: string;

  /**
   * Ratio of junk statements / opaque predicates interleaved with the real
   * decryption code. Higher = larger output but harder static analysis.
   * 2.0 means roughly 2 junk lines per real line.
   * @default 2.0
   */
  junkRatio?: number;

  /**
   * Strip //# sourceMappingURL=... and /*# sourceMappingURL=... *\/ comments
   * from the source before obfuscating, so attackers can't pivot from the
   * payload to the original source.
   * @default true
   */
  stripSourceMaps?: boolean;

  /**
   * Number of chunks each symmetric key is split into. Chunks are stored in
   * Object.create(null) dictionaries with numeric string keys and reassembled
   * at runtime in sort order.
   * @default 8
   */
  keyFragments?: number;

  /**
   * Min/max byte-chunk sizes used when shuffling the ciphertext into scattered
   * [idx, bytes] pairs. Reordered and spread through the output.
   * @default [24, 48]
   */
  cipherFragments?: [number, number];

  /**
   * Number of decoy (key, salt, iter) triples mixed in with the real one.
   * Only the real index is used at runtime; decoys exist to multiply the work
   * of a naive brute-force that tries every triple.
   * @default 2
   */
  decoys?: number;

  /**
   * Identifier style for generated locals. Currently only 'hex' is supported;
   * pickName() produces _0x<random> identifiers.
   * @default 'hex'
   */
  nameStyle?: 'hex';

  /**
   * Maximum body size (in bytes) the middleware will buffer for obfuscation.
   * Responses larger than this are streamed straight through untouched so
   * downloads and media don't end up in RAM.
   * @default 5_242_880 (5 MiB)
   */
  maxBytes?: number;

  /**
   * If provided, only URLs matching this predicate / regex / substring /
   * array-of-those are obfuscated. Everything else passes through.
   * @default null (all URLs eligible)
   */
  include?: WebMiddlewareMatcher | null;

  /**
   * URLs matching this predicate / regex / substring / array-of-those are
   * skipped. Evaluated after include.
   * @default null
   */
  exclude?: WebMiddlewareMatcher | null;

  /**
   * Called when obfuscation throws. The middleware falls back to serving the
   * raw body in that case; the hook is just for logging / telemetry.
   */
  onError?: ((err: Error, ctx: { url: string; kind: 'html' | 'js' | 'css' }) => void) | null;

  /**
   * When true, skips the anti-debug / devtools / env guard traps. Only meant
   * for the round-trip verify harness. Do not enable in production.
   * @default false
   */
  testMode?: boolean;
}

export type WebMiddlewareRequest = IncomingMessage & { originalUrl?: string };
export type WebMiddlewareHandler = (
  req: WebMiddlewareRequest,
  res: ServerResponse,
  next?: (err?: any) => void
) => void;

export function middleware(options?: WebMiddlewareOptions): WebMiddlewareHandler;
export function obfuscateHtml(html: string, options?: WebMiddlewareOptions): string;
export function obfuscateJs(js: string, options?: WebMiddlewareOptions): string;
export function obfuscateCss(css: string, options?: WebMiddlewareOptions): string;
export function normalizeOptions(options?: WebMiddlewareOptions): Required<WebMiddlewareOptions> & Record<string, unknown>;
