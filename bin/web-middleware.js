#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { obfuscateHtml, obfuscateJs, obfuscateCss } = require('../src');

function usage() {
  console.log('Usage: web-middleware <input.html|input.js|input.css> [-o output]');
  console.log('       Dispatch is by file extension: .html/.htm -> HTML obfuscator,');
  console.log('       .js/.mjs -> JS obfuscator, .css -> CSS obfuscator (emits JS).');
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length === 0) usage();

let input = null;
let output = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '-o') {
    output = args[++i];
  } else {
    input = args[i];
  }
}

if (!input) usage();

const src = fs.readFileSync(path.resolve(input), 'utf8');
let obf;
if (/\.m?js$/i.test(input)) {
  obf = obfuscateJs(src);
} else if (/\.html?$/i.test(input)) {
  obf = obfuscateHtml(src);
} else if (/\.css$/i.test(input)) {
  obf = obfuscateCss(src);
} else {
  console.error('Unknown extension. Supply .html, .htm, .js, .mjs, or .css.');
  process.exit(1);
}

if (output) {
  fs.writeFileSync(path.resolve(output), obf, 'utf8');
  console.log('Wrote ' + output + ' (' + obf.length + ' bytes)');
} else {
  process.stdout.write(obf);
}
