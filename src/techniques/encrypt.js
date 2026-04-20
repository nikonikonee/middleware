'use strict';

const { randBytes } = require('../util/rand');

function xorBuffers(a, key) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ key[i % key.length];
  return out;
}

function rot(buf, n) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = (buf[i] + n) & 0xff;
  return out;
}

function encryptLayered(plaintext) {
  const data = Buffer.from(plaintext, 'utf8');
  const k1 = randBytes(32);
  const k2 = randBytes(17);
  const shift = 1 + Math.floor(Math.random() * 254);

  const s1 = xorBuffers(data, k1);
  const s2 = rot(s1, shift);
  const s3 = xorBuffers(s2, k2);

  return {
    cipher: s3,
    k1,
    k2,
    shift,
  };
}

function encryptLayeredJsDecoder(varNames) {
  const { C, K1, K2, S, OUT, i, tmp } = varNames;
  return `
function ${OUT}(${C},${K1},${K2},${S}){
  var ${i}=0,${tmp}=new Uint8Array(${C}.length);
  for(${i}=0;${i}<${C}.length;${i}++)${tmp}[${i}]=${C}[${i}]^${K2}[${i}%${K2}.length];
  for(${i}=0;${i}<${tmp}.length;${i}++)${tmp}[${i}]=(${tmp}[${i}]-${S}+256)&0xff;
  for(${i}=0;${i}<${tmp}.length;${i}++)${tmp}[${i}]=${tmp}[${i}]^${K1}[${i}%${K1}.length];
  return new TextDecoder().decode(${tmp});
}`;
}

module.exports = { encryptLayered, encryptLayeredJsDecoder };
