'use strict';

const crypto = require('crypto');
const { pickName } = require('../util/rand');

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest();
}

function xorBytes(a, b) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % b.length];
  return out;
}

function buildSentinels() {
  const tag = crypto.randomBytes(4).toString('hex');
  return {
    tag,
    start: `/*NI_S_${tag}*/`,
    end: `/*NI_E_${tag}*/`,
  };
}

function maskKeyWithRegion(realKey, regionContent) {
  const h = sha256(regionContent);
  return xorBytes(realKey, h);
}

function buildIntegrityUnmaskSnippet(fnName, argNames, pool) {
  const { MASKED, START, END } = argNames;
  const P = s => pool.add(s);
  const vSc = pickName();
  const vSrc = pickName();
  const vSs = pickName();
  const vI = pickName();
  const vJ = pickName();
  const vRegion = pickName();
  const vEnc = pickName();
  const vHash = pickName();
  const vOut = pickName();
  const vK = pickName();
  return `
async function ${fnName}(${MASKED},${START},${END}){
  var ${vSc}=document[${P('currentScript')}];
  var ${vSrc}=${vSc}?${vSc}[${P('textContent')}]:"";
  if(!${vSrc}){
    var ${vSs}=document[${P('getElementsByTagName')}](${P('script')});
    ${vSrc}=${vSs}[${vSs}.length-1][${P('textContent')}]||"";
  }
  var ${vI}=${vSrc}[${P('indexOf')}](${START});
  var ${vJ}=${vSrc}[${P('indexOf')}](${END});
  if(${vI}<0||${vJ}<0||${vJ}<=${vI}){throw 0;}
  var ${vRegion}=${vSrc}[${P('substring')}](${vI}+${START}[${P('length')}],${vJ});
  var ${vEnc}=new (window[${P('TextEncoder')}])()[${P('encode')}](${vRegion});
  var ${vHash}=new Uint8Array(await window[${P('crypto')}][${P('subtle')}][${P('digest')}](${P('SHA-256')},${vEnc}));
  var ${vOut}=new Uint8Array(${MASKED}.length);
  for(var ${vK}=0;${vK}<${MASKED}.length;${vK}++)${vOut}[${vK}]=${MASKED}[${vK}]^${vHash}[${vK}%${vHash}.length];
  return ${vOut};
}`;
}

module.exports = { sha256, xorBytes, buildSentinels, maskKeyWithRegion, buildIntegrityUnmaskSnippet };
