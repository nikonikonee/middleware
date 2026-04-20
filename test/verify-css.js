'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { obfuscateCss } = require('../src');

const original = fs.readFileSync(path.join(__dirname, 'sample.css'), 'utf8');
const obfCss = obfuscateCss(original, { testMode: true, pbkdf2Iterations: 10000 });

fs.writeFileSync(path.join(__dirname, 'sample.obfuscated.css.js'), obfCss, 'utf8');

// Tiny DOM stand-in. createElement returns a plain object with writable
// textContent and a parent-tracking appendChild. The verifier watches the
// head element for a style child and asserts its textContent.
function makeEl(tag) {
  return {
    tagName: tag,
    textContent: '',
    children: [],
    appendChild(child) { this.children.push(child); return child; },
  };
}

const head = makeEl('head');
const documentElement = makeEl('html');

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
sandbox.window = sandbox;
sandbox.document = {
  currentScript: { textContent: obfCss },
  getElementsByTagName() { return [{ textContent: obfCss }]; },
  documentElement,
  head,
  createElement: makeEl,
};
sandbox.navigator = { userAgent: 'test' };
sandbox.crypto = globalThis.crypto;
sandbox.eval = function (code) { return vm.runInContext(code, sandbox); };

vm.createContext(sandbox);

(async () => {
  try {
    vm.runInContext(obfCss, sandbox, { timeout: 30000 });
  } catch (e) {
    console.error('Execution error:', e.message);
    process.exit(1);
  }

  const deadline = Date.now() + 20000;
  while (head.children.length === 0 && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 50));
  }

  const styleEl = head.children[0];
  if (!styleEl) {
    console.log('FAIL: no <style> element was appended to <head>.');
    process.exit(1);
  }
  if (styleEl.tagName !== 'style') {
    console.log('FAIL: appended element was <' + styleEl.tagName + '>, expected <style>.');
    process.exit(1);
  }
  if (styleEl.textContent === original) {
    console.log('PASS: CSS obfuscator round-trip injected original stylesheet into <style> tag.');
    process.exit(0);
  }
  console.log('FAIL: style.textContent did not match original.');
  console.log('  got length     :', styleEl.textContent.length);
  console.log('  expected length:', original.length);
  process.exit(1);
})();
