'use strict';

const crypto = require('crypto');

function randBytes(n) {
  return crypto.randomBytes(n);
}

function randInt(min, max) {
  return min + Math.floor(Math.random() * (max - min));
}

function randHexName(len = 8) {
  const bytes = crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
  return '_0x' + bytes;
}

function randUnicodeName(len = 6) {
  const chars = 'ΟοΙӏСсΑаΡрΕеΤτΚκΝνΒβΗηΜμΧχΖζΥυΦφ';
  let s = '_';
  for (let i = 0; i < len; i++) s += chars[randInt(0, chars.length)];
  return s;
}

function pickName(style = 'hex') {
  return style === 'unicode' ? randUnicodeName() : randHexName();
}

function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = randInt(0, i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

module.exports = { randBytes, randInt, randHexName, randUnicodeName, pickName, shuffle };
