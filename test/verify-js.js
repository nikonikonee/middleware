'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { obfuscateJs } = require('../src');

const original = fs.readFileSync(path.join(__dirname, 'sample.js'), 'utf8');
const obfJs = obfuscateJs(original, { testMode: true, pbkdf2Iterations: 10000 });

fs.writeFileSync(path.join(__dirname, 'sample.obfuscated.js'), obfJs, 'utf8');

// Set up a fake browser-like sandbox so the obfuscated script thinks it is
// running on a real page. window[eval] must be a working indirect-eval
// function that evaluates the decrypted source into the sandbox scope.
const sandbox = {
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

// Build a window object that shares identity with the sandbox so that
// window.__NC_OUT written by the decrypted code lands on the sandbox itself.
sandbox.window = sandbox;
sandbox.document = {
  currentScript: { textContent: obfJs },
  getElementsByTagName() { return [{ textContent: obfJs }]; },
  documentElement: { innerHTML: '' },
};
sandbox.navigator = { userAgent: 'test' };
sandbox.crypto = globalThis.crypto;

// window[P('eval')] must evaluate into the sandbox's global scope. vm.runInContext
// against the same sandbox achieves exactly that.
sandbox.eval = function (code) {
  return vm.runInContext(code, sandbox);
};

vm.createContext(sandbox);

(async () => {
  try {
    vm.runInContext(obfJs, sandbox, { timeout: 30000 });
  } catch (e) {
    console.error('Execution error:', e.message);
    process.exit(1);
  }

  const deadline = Date.now() + 20000;
  while (!sandbox.__NC_OUT && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 50));
  }

  const expected = 'Hello from web-middleware JS obfuscator count=10';
  if (sandbox.__NC_OUT === expected) {
    console.log('PASS: JS obfuscator round-trip executed original code in global scope.');
    process.exit(0);
  } else {
    console.log('FAIL: __NC_OUT =', JSON.stringify(sandbox.__NC_OUT));
    process.exit(1);
  }
})();
