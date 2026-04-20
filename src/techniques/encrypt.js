'use strict';

const { randBytes, randInt } = require('../util/rand');

/**
 * Polymorphic inner cipher.
 *
 * Instead of a fixed pipeline (XOR K1 -> ADD shift -> XOR K2), the build picks
 * a random recipe of 3 to 6 operations drawn from a 6-op set. Each op is
 * parameterised with build-fresh random values:
 *
 *   OP_XOR  (0) : XOR with a random-size key (24 to 96 bytes per step)
 *   OP_ADD  (1) : add a scalar modulo 256
 *   OP_SUB  (2) : subtract a scalar modulo 256
 *   OP_ROTL (3) : rotate each byte left by 1 to 7 bits
 *   OP_ROTR (4) : rotate each byte right by 1 to 7 bits
 *   OP_NOT  (5) : bitwise complement (takes no param)
 *
 * The recipe, all key blobs, and the scalars are emitted into the bootstrap
 * alongside a tiny interpreter that walks the recipe in reverse, applying each
 * op's inverse. Because the shape of the recipe changes per build, a hand
 * transliteration of one build's decrypt algorithm does not work on any other
 * build. That is the polymorphism property.
 */

const OP_XOR = 0;
const OP_ADD = 1;
const OP_SUB = 2;
const OP_ROTL = 3;
const OP_ROTR = 4;
const OP_NOT = 5;

const MIN_STEPS = 3;
const MAX_STEPS = 6;
const MIN_XOR_KEY = 24;
const MAX_XOR_KEY = 96;

function xorInPlace(buf, key) {
  for (let i = 0; i < buf.length; i++) buf[i] ^= key[i % key.length];
}
function addInPlace(buf, n) {
  for (let i = 0; i < buf.length; i++) buf[i] = (buf[i] + n) & 0xff;
}
function subInPlace(buf, n) {
  for (let i = 0; i < buf.length; i++) buf[i] = (buf[i] - n + 256) & 0xff;
}
function rotlInPlace(buf, b) {
  for (let i = 0; i < buf.length; i++) buf[i] = ((buf[i] << b) | (buf[i] >>> (8 - b))) & 0xff;
}
function rotrInPlace(buf, b) {
  for (let i = 0; i < buf.length; i++) buf[i] = ((buf[i] >>> b) | (buf[i] << (8 - b))) & 0xff;
}
function notInPlace(buf) {
  for (let i = 0; i < buf.length; i++) buf[i] = (~buf[i]) & 0xff;
}

function encryptPolymorphic(plaintext) {
  const data = Buffer.from(Buffer.from(plaintext, 'utf8'));
  const steps = randInt(MIN_STEPS, MAX_STEPS + 1);
  const recipe = [];
  const xorKeys = {};
  const scalars = {};
  const rotates = {};

  // Avoid two consecutive identical XOR keys collapsing (unlikely but just in
  // case) and avoid emitting a pure-NOT recipe that is trivially invertible
  // without any data. If all ops come out OP_NOT we rebuild.
  let safety = 0;
  while (safety++ < 10) {
    recipe.length = 0;
    for (let i = 0; i < steps; i++) recipe.push(randInt(0, 5 + 1));
    if (recipe.some(o => o !== OP_NOT)) break;
  }

  for (let i = 0; i < steps; i++) {
    const op = recipe[i];
    if (op === OP_XOR) {
      const key = randBytes(randInt(MIN_XOR_KEY, MAX_XOR_KEY + 1));
      xorKeys[i] = key;
      xorInPlace(data, key);
    } else if (op === OP_ADD) {
      const n = randInt(1, 255);
      scalars[i] = n;
      addInPlace(data, n);
    } else if (op === OP_SUB) {
      const n = randInt(1, 255);
      scalars[i] = n;
      subInPlace(data, n);
    } else if (op === OP_ROTL) {
      const b = randInt(1, 8);
      rotates[i] = b;
      rotlInPlace(data, b);
    } else if (op === OP_ROTR) {
      const b = randInt(1, 8);
      rotates[i] = b;
      rotrInPlace(data, b);
    } else if (op === OP_NOT) {
      notInPlace(data);
    }
  }

  return {
    cipher: data,
    recipe,
    xorKeys,
    scalars,
    rotates,
  };
}

// Back-compat shim, in case anything external still imports encryptLayered.
function encryptLayered(plaintext) {
  const r = encryptPolymorphic(plaintext);
  return { cipher: r.cipher, k1: Buffer.alloc(0), k2: Buffer.alloc(0), shift: 0, _poly: r };
}

module.exports = {
  encryptPolymorphic,
  encryptLayered,
  OP_XOR, OP_ADD, OP_SUB, OP_ROTL, OP_ROTR, OP_NOT,
};
