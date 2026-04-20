'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { obfuscateHtml } = require('../src');

const original = fs.readFileSync(path.join(__dirname, 'sample.html'), 'utf8');
const obfHtml = obfuscateHtml(original, { testMode: true, pbkdf2Iterations: 10000 });

fs.writeFileSync(path.join(__dirname, 'sample.obfuscated.html'), obfHtml, 'utf8');

const m = obfHtml.match(/<script>([\s\S]*)<\/script>/);
if (!m) { console.error('No script'); process.exit(1); }
const scriptSrc = m[1];

// The new HTML bootstrap tries DOMParser first and falls back to
// documentElement.innerHTML = plain. Our sandbox has no DOMParser, so the
// fallback fires. Capture writes there.
let captured = '';
const documentElement = {};
Object.defineProperty(documentElement, 'innerHTML', {
  set(v) { captured = String(v); },
  get() { return captured; },
});

const fakeDocument = {
  open() {},
  close() {},
  // If some path still calls document.write, fold it into `captured` too.
  write(s) { captured += s; },
  documentElement,
  getElementsByTagName() { return [{ textContent: scriptSrc }]; },
};
fakeDocument.currentScript = { textContent: scriptSrc };

const fakeWindow = {
  outerWidth: 1024, innerWidth: 1024, outerHeight: 768, innerHeight: 768,
  stop() {},
  console: { log() {}, clear() {} },
  crypto: globalThis.crypto,
  TextEncoder: globalThis.TextEncoder,
  TextDecoder: globalThis.TextDecoder,
};

const sandbox = {
  document: fakeDocument,
  window: fakeWindow,
  navigator: { userAgent: 'test' },
  console,
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  TextDecoder: globalThis.TextDecoder,
  TextEncoder: globalThis.TextEncoder,
  Uint8Array, Math, Date, Array, Object, Function, parseInt, Error, JSON, Promise,
  setInterval: () => 0,
  setTimeout: (fn, ms) => { if (typeof fn === 'function') fn(); return 0; },
};
sandbox.self = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

(async () => {
  try {
    vm.runInContext(scriptSrc, sandbox, { timeout: 30000 });
  } catch (e) {
    console.error('Execution error:', e.message);
    process.exit(1);
  }

  const deadline = Date.now() + 20000;
  while (captured.length === 0 && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 50));
  }

  if (captured === original) {
    console.log('PASS: AES-GCM 3-layer decryption matches original exactly.');
    process.exit(0);
  } else if (captured.length > 0) {
    console.log('PARTIAL: wrote ' + captured.length + ' bytes, differs from original.');
    for (let i = 0; i < Math.min(captured.length, original.length); i++) {
      if (captured[i] !== original[i]) { console.log('diff at', i); break; }
    }
    process.exit(1);
  } else {
    console.log('FAIL: nothing written.');
    process.exit(1);
  }
})();
