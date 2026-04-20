'use strict';

const crypto = require('crypto');
const { pickName } = require('../util/rand');

function pbkdf2Build(password, iterations = 250000, saltLen = 16, keyLen = 32) {
  const salt = crypto.randomBytes(saltLen);
  const key = crypto.pbkdf2Sync(
    Buffer.isBuffer(password) ? password : Buffer.from(password),
    salt,
    iterations,
    keyLen,
    'sha256'
  );
  return { key, salt, iterations };
}

function buildPbkdf2RuntimeSnippet(fnName, argNames, pool) {
  const { PASS, SALT, ITER } = argNames;
  const P = s => pool.add(s);
  const vBase = pickName();
  const vParams = pickName();
  const vBits = pickName();
  return `
async function ${fnName}(${PASS},${SALT},${ITER}){
  var ${vBase}=await window[${P('crypto')}][${P('subtle')}][${P('importKey')}](${P('raw')},${PASS},${P('PBKDF2')},false,[${P('deriveBits')}]);
  var ${vParams}={};${vParams}[${P('name')}]=${P('PBKDF2')};${vParams}[${P('salt')}]=${SALT};${vParams}[${P('iterations')}]=${ITER};${vParams}[${P('hash')}]=${P('SHA-256')};
  var ${vBits}=await window[${P('crypto')}][${P('subtle')}][${P('deriveBits')}](${vParams},${vBase},256);
  return new Uint8Array(${vBits});
}`;
}

module.exports = { pbkdf2Build, buildPbkdf2RuntimeSnippet };
