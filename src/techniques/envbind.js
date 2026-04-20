'use strict';

const { pickName } = require('../util/rand');

function buildEnvGuard(onTamper, testMode, pool) {
  const P = s => pool.add(s);
  if (testMode) {
    return `
if(typeof window===${P('undefined')}||typeof document===${P('undefined')}){${onTamper}}
if(!(window[${P('crypto')}]&&window[${P('crypto')}][${P('subtle')}])){${onTamper}}`;
  }
  const a = pickName();
  const b = pickName();
  return `
(function ${a}(){
  try{
    if(typeof process!==${P('undefined')}&&process&&process[${P('versions')}]&&process[${P('versions')}][${P('node')}]){${onTamper}}
  }catch(_){}
  try{
    if(typeof global!==${P('undefined')}&&global&&global[${P('process')}]&&global[${P('process')}][${P('versions')}]&&global[${P('process')}][${P('versions')}][${P('node')}]){${onTamper}}
  }catch(_){}
  if(typeof window===${P('undefined')}||typeof document===${P('undefined')}){${onTamper}}
  if(typeof window[${P('navigator')}]===${P('undefined')}||!window[${P('navigator')}][${P('userAgent')}]){${onTamper}}
  if(!(window[${P('crypto')}]&&window[${P('crypto')}][${P('subtle')}]&&typeof window[${P('crypto')}][${P('subtle')}][${P('importKey')}]===${P('function')})){${onTamper}}
  if(!(window[${P('TextEncoder')}]&&window[${P('TextDecoder')}])){${onTamper}}
  try{
    var ${b}=window[${P('document')}][${P('documentElement')}];
    if(!${b}||typeof ${b}[${P('innerHTML')}]!==${P('string')}){${onTamper}}
  }catch(_){${onTamper}}
})();`;
}

module.exports = { buildEnvGuard };
