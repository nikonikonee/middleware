'use strict';

const { obfuscateHtml } = require('./obfuscators/html');
const { obfuscateJs } = require('./obfuscators/js');
const { obfuscateCss } = require('./obfuscators/css');
const { normalizeOptions } = require('./options');

const HTML_TYPE_RE = /text\/html/i;
const JS_TYPE_RE = /(?:application|text)\/(?:x-)?(?:javascript|ecmascript)/i;
const CSS_TYPE_RE = /text\/css/i;

const HTML_URL_RE = /\.html?(?:\?|$)/i;
const JS_URL_RE = /\.m?js(?:\?|$)/i;
const CSS_URL_RE = /\.css(?:\?|$)/i;

function classify(type, url) {
  if (HTML_TYPE_RE.test(type) || HTML_URL_RE.test(url)) return 'html';
  if (JS_TYPE_RE.test(type) || JS_URL_RE.test(url)) return 'js';
  if (CSS_TYPE_RE.test(type) || CSS_URL_RE.test(url)) return 'css';
  return null;
}

/**
 * Express-style middleware. Intercepts res.write / res.end, buffers the body,
 * dispatches .html / .js / .css responses through the matching obfuscator,
 * writes the result back, and fixes up Content-Length / Content-Type / ETag.
 *
 * Options are documented in src/options.js and index.d.ts. The defaults match
 * production-sane values, so `middleware()` alone is a reasonable call.
 */
function middleware(options = {}) {
  const normalized = normalizeOptions(options);
  const { _includeMatcher: includeMatcher, _excludeMatcher: excludeMatcher, maxBytes, onError } = normalized;

  return function webMiddleware(req, res, next) {
    const method = (req.method || 'GET').toUpperCase();
    // HEAD/OPTIONS never carry a body worth rewriting; let everything else
    // flow because POST/PUT handlers can still return HTML.
    if (method === 'HEAD' || method === 'OPTIONS') return next && next();

    const url = req.url || req.originalUrl || '';
    if (includeMatcher && !includeMatcher(url)) return next && next();
    if (excludeMatcher && excludeMatcher(url)) return next && next();

    const origEnd = res.end.bind(res);
    const origWrite = res.write.bind(res);
    let size = 0;
    let skipped = false;
    const chunks = [];

    res.write = function (chunk, encoding, cb) {
      if (skipped) return origWrite(chunk, encoding, cb);
      if (chunk) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
        size += buf.length;
        if (size > maxBytes) {
          // Bail and flush raw. Huge responses (videos, downloads) should not
          // land in RAM twice just to be skipped.
          skipped = true;
          for (const prior of chunks) origWrite(prior);
          chunks.length = 0;
          return origWrite(buf, undefined, cb);
        }
        chunks.push(buf);
      }
      if (typeof cb === 'function') cb();
      return true;
    };

    res.end = function (chunk, encoding, cb) {
      if (skipped) return origEnd(chunk, encoding, cb);
      if (chunk) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
        size += buf.length;
        if (size > maxBytes) {
          for (const prior of chunks) origWrite(prior);
          chunks.length = 0;
          return origEnd(buf, undefined, cb);
        }
        chunks.push(buf);
      }

      const status = res.statusCode || 200;
      if (status === 204 || status === 205 || status === 304) {
        return origEnd(undefined, undefined, cb);
      }

      // Respect upstream encodings. If something already compressed the body
      // (gzip/br/etc), reading it as utf8 would corrupt it, so bail.
      const encodingHeader = (res.getHeader && res.getHeader('Content-Encoding')) || '';
      if (encodingHeader && !/identity/i.test(String(encodingHeader))) {
        for (const prior of chunks) origWrite(prior);
        return origEnd(undefined, undefined, cb);
      }

      const type = (res.getHeader && res.getHeader('Content-Type')) || '';
      const kind = classify(String(type), url);
      if (!kind) {
        for (const prior of chunks) origWrite(prior);
        return origEnd(undefined, undefined, cb);
      }

      const body = Buffer.concat(chunks).toString('utf8');
      let out = body;
      let dispatched = null;
      try {
        if (kind === 'html') {
          out = obfuscateHtml(body, normalized); dispatched = 'html';
        } else if (kind === 'js') {
          // External .js has empty document.currentScript.textContent, so the
          // sentinel-region hash can never succeed at runtime. Force integrity
          // off for the middleware-served JS path no matter what the caller
          // passed; AES-GCM auth tags still cover ciphertext integrity.
          // Override BOTH spellings because normalizeOptions re-runs inside the
          // obfuscator and the public name (integrityChecks) beats the internal
          // one (useIntegrity) during re-normalization.
          out = obfuscateJs(body, { ...normalized, integrityChecks: false, useIntegrity: false });
          dispatched = 'js';
        } else if (kind === 'css') {
          // Same reason: CSS mode emits an external script, no textContent.
          out = obfuscateCss(body, { ...normalized, integrityChecks: false, useIntegrity: false });
          dispatched = 'css';
        }
      } catch (e) {
        if (typeof onError === 'function') {
          try { onError(e, { url, kind }); } catch (_) {}
        }
        out = body;
        dispatched = null;
      }

      if (res.setHeader) {
        if (dispatched === 'css') {
          // CSS requests come back as JS; the browser will refuse text/css with
          // script bodies. Flip the Content-Type so <script src=...> works.
          res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        }
        res.setHeader('Content-Length', Buffer.byteLength(out));
        res.removeHeader && res.removeHeader('ETag');
      }
      return origEnd(out, undefined, cb);
    };

    next && next();
  };
}

module.exports = {
  middleware,
  obfuscateHtml,
  obfuscateJs,
  obfuscateCss,
  normalizeOptions,
};
