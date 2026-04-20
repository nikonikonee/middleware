'use strict';

const { buildObfuscatedScript } = require('./core');
const { normalizeOptions } = require('../options');

/**
 * Obfuscate a standalone .css file.
 *
 * The output is JavaScript, not CSS. CSS itself has no way to decrypt anything,
 * so the obfuscator emits a JS bootstrap that, when executed, decrypts the
 * original stylesheet and injects it via a <style> tag. Pipeline otherwise
 * matches obfuscateJs / obfuscateHtml.
 *
 * Because the output is JS, the page must load it via <script> rather than
 * <link rel="stylesheet">:
 *
 *   <!-- instead of: <link rel="stylesheet" href="/styles.css"> -->
 *   <script src="/styles.css"></script>
 *
 * The Express middleware rewrites the outgoing Content-Type to
 * application/javascript automatically so the browser treats the response as a
 * script. CSS as CSS cannot carry its own decrypter, so there is no link-tag
 * option.
 *
 * Integrity note: same caveat as obfuscateJs. External scripts have no
 * document.currentScript.textContent, so integrityChecks defaults to false.
 * AES-GCM auth tags still catch ciphertext tampering.
 */
function obfuscateCss(css, options = {}) {
  const opts = normalizeOptions(options);
  let source = css;
  if (opts.stripSourceMaps !== false) {
    // /*# sourceMappingURL=... */ is the CSS variant.
    source = source.replace(/\/\*#\s*sourceMappingURL=[^*]+\*\//g, '');
  }

  const useIntegrity = opts.useIntegrity === undefined ? false : opts.useIntegrity;

  const script = buildObfuscatedScript(source, { ...opts, useIntegrity }, (plain, P) => `
    try{var _0xsty=document[${P('createElement')}](${P('style')});_0xsty[${P('textContent')}]=${plain};(document[${P('head')}]||document[${P('documentElement')}])[${P('appendChild')}](_0xsty);}catch(_){}
  `);

  return script;
}

module.exports = { obfuscateCss };
