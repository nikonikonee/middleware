'use strict';

const fs = require('fs');
const path = require('path');
const { obfuscateHtml } = require('../src');

const input = fs.readFileSync(path.join(__dirname, 'sample.html'), 'utf8');
const out = obfuscateHtml(input);

const outPath = path.join(__dirname, 'sample.obfuscated.html');
fs.writeFileSync(outPath, out, 'utf8');

console.log('Input bytes: ', input.length);
console.log('Output bytes:', out.length);
console.log('Ratio:       ', (out.length / input.length).toFixed(2) + 'x');
console.log('Wrote:       ', outPath);

const plaintextMarkers = ['Secret Page', 'Hello, visitor', 'system-ui', 'alert('];
const leaks = plaintextMarkers.filter(m => out.includes(m));
if (leaks.length) {
  console.error('LEAKS detected:', leaks);
  process.exit(1);
}
console.log('No plaintext markers leaked.');

const requiredShape = ['<!doctype html', '<script>', '(function', 'document.write'];
for (const r of requiredShape) {
  if (!out.includes(r)) {
    console.error('Missing required shape:', r);
    process.exit(1);
  }
}
console.log('Output shape OK.');
