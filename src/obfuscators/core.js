'use strict';

const crypto = require('crypto');
const { randBytes, randInt, pickName } = require('../util/rand');
const { StringPool } = require('../util/stringpool');
const { encryptLayered } = require('../techniques/encrypt');
const { fragmentBuffer } = require('../techniques/fragment');
const { junkFunction, junkBlock, interleaveJunk, opaquePredicate } = require('../techniques/junk');
const { buildAntiDebug, buildDevtoolsTrap } = require('../techniques/antidebug');
const { aesGcmEncrypt, buildAesGcmDecryptSnippet } = require('../techniques/aes');
const { pbkdf2Build, buildPbkdf2RuntimeSnippet } = require('../techniques/kdf');
const { buildEnvGuard } = require('../techniques/envbind');
const { buildSentinels, maskKeyWithRegion, buildIntegrityUnmaskSnippet } = require('../techniques/integrity');

function splitBuffer(buf, parts) {
  const size = Math.ceil(buf.length / parts);
  const out = [];
  for (let i = 0; i < parts; i++) {
    out.push(buf.slice(i * size, Math.min((i + 1) * size, buf.length)));
  }
  return out;
}

function u8Lit(u8) {
  return `new Uint8Array([${Array.from(u8).join(',')}])`;
}

function minifyJs(s) {
  // Strip // line comments first; block comments (including sentinels) survive.
  s = s.replace(/(^|[\s;{}()])\/\/[^\n]*/g, '$1');
  return s.replace(/\s+/g, ' ').replace(/\s*([=+\-*/%^&|<>!?:;,(){}\[\]])\s*/g, '$1').trim();
}

function pbkdfIterationsEncode(n) {
  const a = (Math.random() * 0xffffffff) | 0;
  return { a, b: a ^ n };
}

/**
 * buildObfuscatedScript - shared pipeline used by both html and js obfuscators.
 *
 * @param {string} source  The plaintext being protected (HTML string or JS source).
 * @param {object} options All options from the middleware / cli.
 * @param {function} buildOutput  (plainVarName, P) => string. Returns the code that
 *        runs once the plaintext is decrypted. For HTML this is document.write(plain);
 *        for JS this is (0,eval)(plain);
 * @returns {string} minified single-line script source (no wrapping <script> tag).
 */
function buildObfuscatedScript(source, options, buildOutput) {
  const {
    antiDebug = true,
    devtoolsTrap = true,
    junkRatio = 2.0,
    keyFragments = 8,
    cipherFragments = [24, 48],
    nameStyle = 'hex',
    pbkdf2Iterations = 250000,
    decoys = 2,
    testMode = false,
    closeUrl = '',
    rewriteHtml = '',
    useIntegrity = true,
  } = options;

  const pool = new StringPool(nameStyle);
  const P = s => pool.add(s);

  const scrambled = encryptLayered(source);
  const S1 = scrambled.cipher;

  const midAes = aesGcmEncrypt(S1);
  const S2 = Buffer.concat([midAes.iv, midAes.ct, midAes.tag]);
  const MID_IV_LEN = midAes.iv.length;

  const outerPassword = randBytes(32);
  const pbkdf = pbkdf2Build(outerPassword, pbkdf2Iterations);
  const outerKey = pbkdf.key;
  const outerIv = randBytes(12);
  const outerCipher = crypto.createCipheriv('aes-256-gcm', outerKey, outerIv);
  const outerCt = Buffer.concat([outerCipher.update(S2), outerCipher.final()]);
  const outerTag = outerCipher.getAuthTag();
  const S3 = Buffer.concat([outerIv, outerCt, outerTag]);
  const OUTER_IV_LEN = outerIv.length;

  const names = {
    K1_OBJ: pickName(nameStyle),
    K2_OBJ: pickName(nameStyle),
    MID_KEY_OBJ: pickName(nameStyle),
    MID_IV: pickName(nameStyle),
    MASKED_OBJ: pickName(nameStyle),
    SALT: pickName(nameStyle),
    ITER_A: pickName(nameStyle),
    ITER_B: pickName(nameStyle),
    SHIFT_A: pickName(nameStyle),
    SHIFT_B: pickName(nameStyle),
    FRAG_ARR: pickName(nameStyle),
    REAL_IDX: pickName(nameStyle),
    START_MARK: pickName(nameStyle),
    END_MARK: pickName(nameStyle),
    UNMASK: pickName(nameStyle),
    DERIVE: pickName(nameStyle),
    AES: pickName(nameStyle),
    DECRYPT_ALL: pickName(nameStyle),
    WIPE: pickName(nameStyle),
    BOOT: pickName(nameStyle),
  };

  const junkFns = [];
  for (let i = 0; i < randInt(8, 16); i++) junkFns.push(junkFunction());
  const guardedJunk = minifyJs(junkBlock(8, 16) + junkFns.join(''));

  const sentinels = buildSentinels();
  // When integrity is on, XOR the real password with SHA256(guardedJunk) so any
  // byte changed between the sentinels breaks key derivation. When off, store
  // the password as-is (the AES-GCM auth tag still protects the ciphertext).
  const maskedReal = useIntegrity
    ? maskKeyWithRegion(outerPassword, guardedJunk)
    : Buffer.from(outerPassword);

  const realIdx = randInt(0, decoys + 1);
  const maskedEntries = [];
  const saltEntries = [];
  const iterAEntries = [];
  const iterBEntries = [];
  for (let i = 0; i < decoys + 1; i++) {
    if (i === realIdx) {
      maskedEntries.push(maskedReal);
      saltEntries.push(pbkdf.salt);
      const enc = pbkdfIterationsEncode(pbkdf2Iterations);
      iterAEntries.push(enc.a);
      iterBEntries.push(enc.b);
    } else {
      maskedEntries.push(randBytes(32));
      saltEntries.push(randBytes(16));
      const enc = pbkdfIterationsEncode(pbkdf2Iterations + randInt(-50, 50) * 100);
      iterAEntries.push(enc.a);
      iterBEntries.push(enc.b);
    }
  }

  const k1Chunks = splitBuffer(scrambled.k1, keyFragments);
  const k2Chunks = splitBuffer(scrambled.k2, Math.min(keyFragments, scrambled.k2.length));
  const midKeyChunks = splitBuffer(midAes.key, keyFragments);
  const shiftA = randInt(0, 256);
  const shiftB = scrambled.shift ^ shiftA;

  const cipherFrags = fragmentBuffer(S3, cipherFragments[0], cipherFragments[1]);

  const keyDecls = [];
  keyDecls.push(`${names.K1_OBJ}=Object[${P('create')}](null)`);
  k1Chunks.forEach((c, i) => keyDecls.push(`${names.K1_OBJ}[${i}]=${u8Lit(c)}`));
  keyDecls.push(`${names.K2_OBJ}=Object[${P('create')}](null)`);
  k2Chunks.forEach((c, i) => keyDecls.push(`${names.K2_OBJ}[${i}]=${u8Lit(c)}`));
  keyDecls.push(`${names.MID_KEY_OBJ}=Object[${P('create')}](null)`);
  midKeyChunks.forEach((c, i) => keyDecls.push(`${names.MID_KEY_OBJ}[${i}]=${u8Lit(c)}`));
  keyDecls.push(`${names.MID_IV}=${u8Lit(midAes.iv)}`);
  keyDecls.push(`${names.SHIFT_A}=${shiftA}`);
  keyDecls.push(`${names.SHIFT_B}=${shiftB}`);
  keyDecls.push(`${names.MASKED_OBJ}=[${maskedEntries.map(u8Lit).join(',')}]`);
  keyDecls.push(`${names.SALT}=[${saltEntries.map(u8Lit).join(',')}]`);
  keyDecls.push(`${names.ITER_A}=[${iterAEntries.join(',')}]`);
  keyDecls.push(`${names.ITER_B}=[${iterBEntries.join(',')}]`);
  keyDecls.push(`${names.REAL_IDX}=${realIdx}`);
  keyDecls.push(`${names.START_MARK}=${P(sentinels.start)}`);
  keyDecls.push(`${names.END_MARK}=${P(sentinels.end)}`);

  const fragInserts = [];
  const chunkSize = Math.max(1, Math.ceil(cipherFrags.length / randInt(6, 12)));
  for (let i = 0; i < cipherFrags.length; i += chunkSize) {
    const slice = cipherFrags.slice(i, i + chunkSize);
    const entries = slice.map(f => {
      const bytes = Buffer.from(f.b64, 'base64');
      return `[${f.idx},[${Array.from(bytes).join(',')}]]`;
    }).join(',');
    if (i === 0) fragInserts.push(`${names.FRAG_ARR}=[${entries}]`);
    else fragInserts.push(`Array[${P('prototype')}][${P('push')}][${P('apply')}](${names.FRAG_ARR},[${entries}])`);
  }

  const varDecl = `var ${names.K1_OBJ},${names.K2_OBJ},${names.MID_KEY_OBJ},${names.MID_IV},${names.SHIFT_A},${names.SHIFT_B},${names.MASKED_OBJ},${names.SALT},${names.ITER_A},${names.ITER_B},${names.REAL_IDX},${names.FRAG_ARR},${names.START_MARK},${names.END_MARK}`;
  const allDecls = [varDecl, ...keyDecls, ...fragInserts];
  const scatteredDecls = interleaveJunk(allDecls, junkRatio);

  const deriveFn = buildPbkdf2RuntimeSnippet(names.DERIVE, {
    PASS: pickName(nameStyle), SALT: pickName(nameStyle), ITER: pickName(nameStyle),
  }, pool);

  const aesFn = buildAesGcmDecryptSnippet(names.AES, {
    KEY: pickName(nameStyle), IV: pickName(nameStyle), CT_TAG: pickName(nameStyle),
  }, pool);

  // Integrity unmask: if disabled, emit a pass-through (returns masked unchanged).
  let unmaskFn;
  const UPARAMS = { MASKED: pickName(nameStyle), START: pickName(nameStyle), END: pickName(nameStyle) };
  if (useIntegrity) {
    unmaskFn = buildIntegrityUnmaskSnippet(names.UNMASK, UPARAMS, pool);
  } else {
    unmaskFn = `async function ${names.UNMASK}(${UPARAMS.MASKED},${UPARAMS.START},${UPARAMS.END}){return new Uint8Array(${UPARAMS.MASKED});}`;
  }

  const L = {
    idx: pickName(nameStyle), masked: pickName(nameStyle), salt: pickName(nameStyle),
    iterations: pickName(nameStyle), password: pickName(nameStyle), outerKey: pickName(nameStyle),
    pwLoop: pickName(nameStyle), sortedFrags: pickName(nameStyle), parts: pickName(nameStyle),
    total: pickName(nameStyle), fragLoop: pickName(nameStyle), fragBuf: pickName(nameStyle),
    S3: pickName(nameStyle), off: pickName(nameStyle), s3Loop: pickName(nameStyle),
    outerIv: pickName(nameStyle), outerBody: pickName(nameStyle), S2: pickName(nameStyle),
    okLoop: pickName(nameStyle), wipeS3: pickName(nameStyle), midIv: pickName(nameStyle),
    midBody: pickName(nameStyle), mkKeys: pickName(nameStyle), midKeyTotal: pickName(nameStyle),
    midKeyLoop1: pickName(nameStyle), midKey: pickName(nameStyle), midKeyLoop2: pickName(nameStyle),
    S1: pickName(nameStyle), midKeyLoop3: pickName(nameStyle), wipeS2: pickName(nameStyle),
    k1Keys: pickName(nameStyle), k1Total: pickName(nameStyle), k1Loop1: pickName(nameStyle),
    K1: pickName(nameStyle), k1Loop2: pickName(nameStyle), k2Keys: pickName(nameStyle),
    k2Total: pickName(nameStyle), k2Loop1: pickName(nameStyle), K2: pickName(nameStyle),
    k2Loop2: pickName(nameStyle), S: pickName(nameStyle), T: pickName(nameStyle),
    tLoop1: pickName(nameStyle), tLoop2: pickName(nameStyle), tLoop3: pickName(nameStyle),
    plain: pickName(nameStyle), wipeK1: pickName(nameStyle), wipeK2: pickName(nameStyle),
    wipeT: pickName(nameStyle), wipeS1: pickName(nameStyle), sortX: pickName(nameStyle),
    sortY: pickName(nameStyle),
  };

  const W = {
    k1: pickName(nameStyle), k2: pickName(nameStyle), k3: pickName(nameStyle),
    fi: pickName(nameStyle), mi: pickName(nameStyle), si: pickName(nameStyle),
  };

  const decryptAll = `
async function ${names.DECRYPT_ALL}(){
  var ${L.idx}=${names.REAL_IDX};
  var ${L.masked}=${names.MASKED_OBJ}[${L.idx}];
  var ${L.salt}=${names.SALT}[${L.idx}];
  var ${L.iterations}=${names.ITER_A}[${L.idx}]^${names.ITER_B}[${L.idx}];
  var ${L.password}=await ${names.UNMASK}(${L.masked},${names.START_MARK},${names.END_MARK});
  var ${L.outerKey}=await ${names.DERIVE}(${L.password},${L.salt},${L.iterations});
  for(var ${L.pwLoop}=0;${L.pwLoop}<${L.password}.length;${L.pwLoop}++)${L.password}[${L.pwLoop}]=0;
  var ${L.sortedFrags}=${names.FRAG_ARR}[${P('slice')}]()[${P('sort')}](function(${L.sortX},${L.sortY}){return ${L.sortX}[0]-${L.sortY}[0];});
  var ${L.parts}=[];var ${L.total}=0;
  for(var ${L.fragLoop}=0;${L.fragLoop}<${L.sortedFrags}.length;${L.fragLoop}++){
    var ${L.fragBuf}=new Uint8Array(${L.sortedFrags}[${L.fragLoop}][1]);
    ${L.parts}.push(${L.fragBuf});${L.total}+=${L.fragBuf}.length;
  }
  var ${L.S3}=new Uint8Array(${L.total});var ${L.off}=0;
  for(var ${L.s3Loop}=0;${L.s3Loop}<${L.parts}.length;${L.s3Loop}++){${L.S3}.set(${L.parts}[${L.s3Loop}],${L.off});${L.off}+=${L.parts}[${L.s3Loop}].length;}
  var ${L.outerIv}=${L.S3}[${P('slice')}](0,${OUTER_IV_LEN});
  var ${L.outerBody}=${L.S3}[${P('slice')}](${OUTER_IV_LEN});
  var ${L.S2}=await ${names.AES}(${L.outerKey},${L.outerIv},${L.outerBody});
  for(var ${L.okLoop}=0;${L.okLoop}<${L.outerKey}.length;${L.okLoop}++)${L.outerKey}[${L.okLoop}]=0;
  for(var ${L.wipeS3}=0;${L.wipeS3}<${L.S3}.length;${L.wipeS3}++)${L.S3}[${L.wipeS3}]=0;
  var ${L.midIv}=${names.MID_IV};
  var ${L.midBody}=${L.S2}[${P('slice')}](${MID_IV_LEN});
  var ${L.mkKeys}=Object[${P('keys')}](${names.MID_KEY_OBJ})[${P('sort')}](function(${L.sortX},${L.sortY}){return (${L.sortX}-0)-(${L.sortY}-0);});
  var ${L.midKeyTotal}=0;
  for(var ${L.midKeyLoop1}=0;${L.midKeyLoop1}<${L.mkKeys}.length;${L.midKeyLoop1}++)${L.midKeyTotal}+=${names.MID_KEY_OBJ}[${L.mkKeys}[${L.midKeyLoop1}]].length;
  var ${L.midKey}=new Uint8Array(${L.midKeyTotal});${L.off}=0;
  for(var ${L.midKeyLoop2}=0;${L.midKeyLoop2}<${L.mkKeys}.length;${L.midKeyLoop2}++){${L.midKey}.set(${names.MID_KEY_OBJ}[${L.mkKeys}[${L.midKeyLoop2}]],${L.off});${L.off}+=${names.MID_KEY_OBJ}[${L.mkKeys}[${L.midKeyLoop2}]].length;}
  var ${L.S1}=await ${names.AES}(${L.midKey},${L.midIv},${L.midBody});
  for(var ${L.midKeyLoop3}=0;${L.midKeyLoop3}<${L.midKey}.length;${L.midKeyLoop3}++)${L.midKey}[${L.midKeyLoop3}]=0;
  for(var ${L.wipeS2}=0;${L.wipeS2}<${L.S2}.length;${L.wipeS2}++)${L.S2}[${L.wipeS2}]=0;
  var ${L.k1Keys}=Object[${P('keys')}](${names.K1_OBJ})[${P('sort')}](function(${L.sortX},${L.sortY}){return (${L.sortX}-0)-(${L.sortY}-0);});
  var ${L.k1Total}=0;
  for(var ${L.k1Loop1}=0;${L.k1Loop1}<${L.k1Keys}.length;${L.k1Loop1}++)${L.k1Total}+=${names.K1_OBJ}[${L.k1Keys}[${L.k1Loop1}]].length;
  var ${L.K1}=new Uint8Array(${L.k1Total});${L.off}=0;
  for(var ${L.k1Loop2}=0;${L.k1Loop2}<${L.k1Keys}.length;${L.k1Loop2}++){${L.K1}.set(${names.K1_OBJ}[${L.k1Keys}[${L.k1Loop2}]],${L.off});${L.off}+=${names.K1_OBJ}[${L.k1Keys}[${L.k1Loop2}]].length;}
  var ${L.k2Keys}=Object[${P('keys')}](${names.K2_OBJ})[${P('sort')}](function(${L.sortX},${L.sortY}){return (${L.sortX}-0)-(${L.sortY}-0);});
  var ${L.k2Total}=0;
  for(var ${L.k2Loop1}=0;${L.k2Loop1}<${L.k2Keys}.length;${L.k2Loop1}++)${L.k2Total}+=${names.K2_OBJ}[${L.k2Keys}[${L.k2Loop1}]].length;
  var ${L.K2}=new Uint8Array(${L.k2Total});${L.off}=0;
  for(var ${L.k2Loop2}=0;${L.k2Loop2}<${L.k2Keys}.length;${L.k2Loop2}++){${L.K2}.set(${names.K2_OBJ}[${L.k2Keys}[${L.k2Loop2}]],${L.off});${L.off}+=${names.K2_OBJ}[${L.k2Keys}[${L.k2Loop2}]].length;}
  var ${L.S}=${names.SHIFT_A}^${names.SHIFT_B};
  var ${L.T}=new Uint8Array(${L.S1}.length);
  for(var ${L.tLoop1}=0;${L.tLoop1}<${L.S1}.length;${L.tLoop1}++)${L.T}[${L.tLoop1}]=${L.S1}[${L.tLoop1}]^${L.K2}[${L.tLoop1}%${L.K2}.length];
  for(var ${L.tLoop2}=0;${L.tLoop2}<${L.T}.length;${L.tLoop2}++)${L.T}[${L.tLoop2}]=(${L.T}[${L.tLoop2}]-${L.S}+256)&0xff;
  for(var ${L.tLoop3}=0;${L.tLoop3}<${L.T}.length;${L.tLoop3}++)${L.T}[${L.tLoop3}]=${L.T}[${L.tLoop3}]^${L.K1}[${L.tLoop3}%${L.K1}.length];
  var ${L.plain}=new (window[${P('TextDecoder')}])(${P('utf-8')})[${P('decode')}](${L.T});
  for(var ${L.wipeK1}=0;${L.wipeK1}<${L.K1}.length;${L.wipeK1}++)${L.K1}[${L.wipeK1}]=0;
  for(var ${L.wipeK2}=0;${L.wipeK2}<${L.K2}.length;${L.wipeK2}++)${L.K2}[${L.wipeK2}]=0;
  for(var ${L.wipeT}=0;${L.wipeT}<${L.T}.length;${L.wipeT}++)${L.T}[${L.wipeT}]=0;
  for(var ${L.wipeS1}=0;${L.wipeS1}<${L.S1}.length;${L.wipeS1}++)${L.S1}[${L.wipeS1}]=0;
  return ${L.plain};
}
function ${names.WIPE}(){
  try{
    for(var ${W.k1} in ${names.K1_OBJ}){if(${names.K1_OBJ}[${W.k1}]&&${names.K1_OBJ}[${W.k1}][${P('fill')}])${names.K1_OBJ}[${W.k1}][${P('fill')}](0);${names.K1_OBJ}[${W.k1}]=null;}
    for(var ${W.k2} in ${names.K2_OBJ}){if(${names.K2_OBJ}[${W.k2}]&&${names.K2_OBJ}[${W.k2}][${P('fill')}])${names.K2_OBJ}[${W.k2}][${P('fill')}](0);${names.K2_OBJ}[${W.k2}]=null;}
    for(var ${W.k3} in ${names.MID_KEY_OBJ}){if(${names.MID_KEY_OBJ}[${W.k3}]&&${names.MID_KEY_OBJ}[${W.k3}][${P('fill')}])${names.MID_KEY_OBJ}[${W.k3}][${P('fill')}](0);${names.MID_KEY_OBJ}[${W.k3}]=null;}
    if(${names.MID_IV}&&${names.MID_IV}[${P('fill')}])${names.MID_IV}[${P('fill')}](0);
    for(var ${W.fi}=0;${W.fi}<${names.FRAG_ARR}.length;${W.fi}++){${names.FRAG_ARR}[${W.fi}][1]=[];${names.FRAG_ARR}[${W.fi}]=null;}
    ${names.FRAG_ARR}.length=0;
    for(var ${W.mi}=0;${W.mi}<${names.MASKED_OBJ}.length;${W.mi}++){if(${names.MASKED_OBJ}[${W.mi}][${P('fill')}])${names.MASKED_OBJ}[${W.mi}][${P('fill')}](0);}
    for(var ${W.si}=0;${W.si}<${names.SALT}.length;${W.si}++){if(${names.SALT}[${W.si}][${P('fill')}])${names.SALT}[${W.si}][${P('fill')}](0);}
    ${names.ITER_A}.length=0;${names.ITER_B}.length=0;
    ${names.SHIFT_A}=0;${names.SHIFT_B}=0;
  }catch(_){}
}`;

  const onTamper = `try{document[${P('documentElement')}][${P('innerHTML')}]="";}catch(_){}try{window[${P('stop')}]&&window[${P('stop')}]();}catch(_){}throw 0;`;

  const envGuardCode = buildEnvGuard(onTamper, testMode, pool);
  const antiDebugCode = antiDebug && !testMode ? buildAntiDebug(onTamper, pool, { closeUrl, rewriteHtml }) : '';
  const devtoolsCode = devtoolsTrap && !testMode ? buildDevtoolsTrap(onTamper, pool) : '';

  const bPlain = pickName(nameStyle);
  const bErr = pickName(nameStyle);
  const outputCode = buildOutput(bPlain, P);
  const bootstrap = `
(async function(){
  try{
    var ${bPlain}=await ${names.DECRYPT_ALL}();
    ${names.WIPE}();
    ${outputCode}
    ${bPlain}=null;
  }catch(${bErr}){
    ${onTamper}
  }
})();`;

  const opaqueGuard = `if(${opaquePredicate(false)}){${onTamper}}`;
  const poolEmit = pool.emit();

  const script = `
(function ${names.BOOT}(){
  "use strict";
  ${poolEmit}
  ${envGuardCode}
  ${opaqueGuard}
  ${sentinels.start}${guardedJunk}${sentinels.end}
  ${scatteredDecls}
  ${unmaskFn}
  ${deriveFn}
  ${aesFn}
  ${decryptAll}
  ${antiDebugCode}
  ${devtoolsCode}
  ${bootstrap}
})();`;

  return minifyJs(script);
}

module.exports = { buildObfuscatedScript, minifyJs };
