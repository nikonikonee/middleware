'use strict';

const crypto = require('crypto');
const { pickName } = require('../util/rand');

function aesGcmEncrypt(plaintext) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { key, iv, ct, tag };
}

function buildAesGcmDecryptSnippet(fnName, argNames, pool) {
  const { KEY, IV, CT_TAG } = argNames;
  const P = s => pool.add(s);
  const vAlgo = pickName();
  const vIvObj = pickName();
  const vKey = pickName();
  const vPt = pickName();
  return `
async function ${fnName}(${KEY},${IV},${CT_TAG}){
  var ${vAlgo}={};${vAlgo}[${P('name')}]=${P('AES-GCM')};${vAlgo}[${P('length')}]=256;
  var ${vIvObj}={};${vIvObj}[${P('name')}]=${P('AES-GCM')};${vIvObj}[${P('iv')}]=${IV};
  var ${vKey}=await window[${P('crypto')}][${P('subtle')}][${P('importKey')}](${P('raw')},${KEY},${vAlgo},false,[${P('decrypt')}]);
  var ${vPt}=await window[${P('crypto')}][${P('subtle')}][${P('decrypt')}](${vIvObj},${vKey},${CT_TAG});
  return new Uint8Array(${vPt});
}`;
}

module.exports = { aesGcmEncrypt, buildAesGcmDecryptSnippet };
