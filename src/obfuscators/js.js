'use strict';

const { buildObfuscatedScript } = require('./core');
const { normalizeOptions } = require('../options');

/**
 * Obfuscate a standalone .js file so it can be served as application/javascript.
 *
 * Pipeline is identical to obfuscateHtml (double AES-GCM, PBKDF2, XOR+ROT+XOR,
 * key splitting, fragment scattering, decoys, string pool, anti-debug, env
 * guard, self-wipe). The one difference: the bootstrap runs the decrypted
 * plaintext via indirect eval instead of document.write, so the original JS
 * executes in global scope with full side effects intact.
 *
 * Integrity note: the sentinel-region hash check relies on
 * document.currentScript.textContent, which only returns the script body for
 * inline scripts. External .js files loaded via <script src=...> return an
 * empty textContent, so integrityChecks defaults to false here. Ciphertext
 * tampering is still caught by the two AES-GCM auth tags. Pass
 * { integrityChecks: true } explicitly if you are inlining the output inside
 * a <script> tag on a page you control.
 *
 * Caveat on async: the decryption pipeline is async (Web Crypto Subtle is
 * async-only). The original script runs one microtask later than it would if
 * served raw. Scripts that depend on strict synchronous load order with other
 * scripts on the page need to be audited.
 */
function obfuscateJs(js, options = {}) {
  const opts = normalizeOptions(options);
  let source = js;
  if (opts.stripSourceMaps !== false) {
    source = source.replace(/\/[\/\*]#\s*sourceMappingURL=[^\s*]+\s*\*?\/?/g, '');
  }

  const useIntegrity = opts.useIntegrity === undefined ? false : opts.useIntegrity;

  // Indirect eval via window[P('eval')]: property access keeps the identifier
  // "eval" out of the plaintext token stream and forces global-scope eval,
  // preserving top-level var/let/const bindings exactly as if the original
  // script had been loaded directly.
  const script = buildObfuscatedScript(source, { ...opts, useIntegrity }, (plain, P) => `
    try{window[${P('eval')}](${plain});}catch(_){}
  `);

  return script;
}

module.exports = { obfuscateJs };
