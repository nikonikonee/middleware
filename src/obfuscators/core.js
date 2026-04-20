'use strict';

const crypto = require('crypto');
const { randBytes, randInt, pickName } = require('../util/rand');
const { StringPool } = require('../util/stringpool');
const { encryptPolymorphic } = require('../techniques/encrypt');
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
    debugRewriteHtml = '',
    integrityRewriteHtml = '',
    useIntegrity = true,
  } = options;

  const pool = new StringPool(nameStyle);
  const P = s => pool.add(s);

  const scrambled = encryptPolymorphic(source);
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
    XOR_KEYS: pickName(nameStyle),
    SCALARS: pickName(nameStyle),
    ROTATES: pickName(nameStyle),
    RECIPE: pickName(nameStyle),
    MID_KEY_OBJ: pickName(nameStyle),
    MID_IV: pickName(nameStyle),
    MASKED_OBJ: pickName(nameStyle),
    SALT: pickName(nameStyle),
    ITER_A: pickName(nameStyle),
    ITER_B: pickName(nameStyle),
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

  const midKeyChunks = splitBuffer(midAes.key, keyFragments);

  // Per-step XOR keys: emit as a dictionary of step-index -> scattered-chunk
  // subdictionaries. At runtime each XOR step reassembles its own key via
  // Object.keys().sort() on its subdictionary. Scalars and rotates are small
  // integers; emit them as sparse arrays indexed by step.
  const recipe = scrambled.recipe;
  const recipeLen = recipe.length;
  const scalarsArr = new Array(recipeLen).fill(0);
  const rotatesArr = new Array(recipeLen).fill(0);
  for (let i = 0; i < recipeLen; i++) {
    if (scrambled.scalars[i] !== undefined) scalarsArr[i] = scrambled.scalars[i];
    if (scrambled.rotates[i] !== undefined) rotatesArr[i] = scrambled.rotates[i];
  }

  // Inject a few fake-scalar / fake-rotate entries for non-matching ops, so an
  // attacker can't tell at a glance which op uses which array. Op dispatch at
  // runtime ignores these for ops that don't need them.
  for (let i = 0; i < recipeLen; i++) {
    if (scalarsArr[i] === 0) scalarsArr[i] = randInt(1, 255);
    if (rotatesArr[i] === 0) rotatesArr[i] = randInt(1, 7);
  }

  const cipherFrags = fragmentBuffer(S3, cipherFragments[0], cipherFragments[1]);

  const keyDecls = [];
  // Top-level XOR keys dict, parented by step index; each child is a scattered
  // chunk dict with numeric-string keys, same shape as the middle-AES-key dict.
  keyDecls.push(`${names.XOR_KEYS}=Object[${P('create')}](null)`);
  for (const stepStr of Object.keys(scrambled.xorKeys)) {
    const step = Number(stepStr);
    const key = scrambled.xorKeys[step];
    const parts = Math.min(keyFragments, Math.max(1, key.length));
    const chunks = splitBuffer(key, parts);
    keyDecls.push(`${names.XOR_KEYS}[${step}]=Object[${P('create')}](null)`);
    chunks.forEach((c, i) => keyDecls.push(`${names.XOR_KEYS}[${step}][${i}]=${u8Lit(c)}`));
  }
  keyDecls.push(`${names.SCALARS}=[${scalarsArr.join(',')}]`);
  keyDecls.push(`${names.ROTATES}=[${rotatesArr.join(',')}]`);
  keyDecls.push(`${names.RECIPE}=[${recipe.join(',')}]`);
  keyDecls.push(`${names.MID_KEY_OBJ}=Object[${P('create')}](null)`);
  midKeyChunks.forEach((c, i) => keyDecls.push(`${names.MID_KEY_OBJ}[${i}]=${u8Lit(c)}`));
  keyDecls.push(`${names.MID_IV}=${u8Lit(midAes.iv)}`);
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

  const varDecl = `var ${names.XOR_KEYS},${names.SCALARS},${names.ROTATES},${names.RECIPE},${names.MID_KEY_OBJ},${names.MID_IV},${names.MASKED_OBJ},${names.SALT},${names.ITER_A},${names.ITER_B},${names.REAL_IDX},${names.FRAG_ARR},${names.START_MARK},${names.END_MARK}`;
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
    unmaskFn = buildIntegrityUnmaskSnippet(names.UNMASK, UPARAMS, pool, {
      rewriteHtml: integrityRewriteHtml || rewriteHtml || '',
    });
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
    step: pickName(nameStyle), op: pickName(nameStyle), subKeys: pickName(nameStyle),
    subTotal: pickName(nameStyle), subLoop1: pickName(nameStyle), xk: pickName(nameStyle),
    subLoop2: pickName(nameStyle), byteLoop: pickName(nameStyle), T: pickName(nameStyle),
    rot: pickName(nameStyle),
    plain: pickName(nameStyle), wipeT: pickName(nameStyle), wipeS1: pickName(nameStyle),
    sortX: pickName(nameStyle), sortY: pickName(nameStyle), sc: pickName(nameStyle),
  };

  const W = {
    xs: pickName(nameStyle), xsub: pickName(nameStyle),
    k3: pickName(nameStyle),
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
  // Polymorphic inner decrypt: walk the recipe in reverse, applying each
  // operation's inverse. Op codes: 0=XOR (self-inverse), 1=ADD (inverse SUB),
  // 2=SUB (inverse ADD), 3=ROTL (inverse ROTR), 4=ROTR (inverse ROTL), 5=NOT
  // (self-inverse). Every step reads its XOR key (if any) out of the scattered
  // XOR_KEYS dict, rebuilding via Object.keys().sort() per step.
  var ${L.T}=new Uint8Array(${L.S1});
  for(var ${L.step}=${names.RECIPE}.length-1;${L.step}>=0;${L.step}--){
    var ${L.op}=${names.RECIPE}[${L.step}];
    if(${L.op}===0){
      var ${L.subKeys}=Object[${P('keys')}](${names.XOR_KEYS}[${L.step}])[${P('sort')}](function(${L.sortX},${L.sortY}){return (${L.sortX}-0)-(${L.sortY}-0);});
      var ${L.subTotal}=0;
      for(var ${L.subLoop1}=0;${L.subLoop1}<${L.subKeys}.length;${L.subLoop1}++)${L.subTotal}+=${names.XOR_KEYS}[${L.step}][${L.subKeys}[${L.subLoop1}]].length;
      var ${L.xk}=new Uint8Array(${L.subTotal});${L.off}=0;
      for(var ${L.subLoop2}=0;${L.subLoop2}<${L.subKeys}.length;${L.subLoop2}++){${L.xk}.set(${names.XOR_KEYS}[${L.step}][${L.subKeys}[${L.subLoop2}]],${L.off});${L.off}+=${names.XOR_KEYS}[${L.step}][${L.subKeys}[${L.subLoop2}]].length;}
      for(var ${L.byteLoop}=0;${L.byteLoop}<${L.T}.length;${L.byteLoop}++)${L.T}[${L.byteLoop}]=${L.T}[${L.byteLoop}]^${L.xk}[${L.byteLoop}%${L.xk}.length];
      for(var ${L.subLoop1}=0;${L.subLoop1}<${L.xk}.length;${L.subLoop1}++)${L.xk}[${L.subLoop1}]=0;
    }else if(${L.op}===1){
      var ${L.sc}=${names.SCALARS}[${L.step}];
      for(var ${L.byteLoop}=0;${L.byteLoop}<${L.T}.length;${L.byteLoop}++)${L.T}[${L.byteLoop}]=(${L.T}[${L.byteLoop}]-${L.sc}+256)&0xff;
    }else if(${L.op}===2){
      var ${L.sc}=${names.SCALARS}[${L.step}];
      for(var ${L.byteLoop}=0;${L.byteLoop}<${L.T}.length;${L.byteLoop}++)${L.T}[${L.byteLoop}]=(${L.T}[${L.byteLoop}]+${L.sc})&0xff;
    }else if(${L.op}===3){
      var ${L.rot}=${names.ROTATES}[${L.step}];
      for(var ${L.byteLoop}=0;${L.byteLoop}<${L.T}.length;${L.byteLoop}++)${L.T}[${L.byteLoop}]=((${L.T}[${L.byteLoop}]>>>${L.rot})|(${L.T}[${L.byteLoop}]<<(8-${L.rot})))&0xff;
    }else if(${L.op}===4){
      var ${L.rot}=${names.ROTATES}[${L.step}];
      for(var ${L.byteLoop}=0;${L.byteLoop}<${L.T}.length;${L.byteLoop}++)${L.T}[${L.byteLoop}]=((${L.T}[${L.byteLoop}]<<${L.rot})|(${L.T}[${L.byteLoop}]>>>(8-${L.rot})))&0xff;
    }else if(${L.op}===5){
      for(var ${L.byteLoop}=0;${L.byteLoop}<${L.T}.length;${L.byteLoop}++)${L.T}[${L.byteLoop}]=(~${L.T}[${L.byteLoop}])&0xff;
    }
  }
  var ${L.plain}=new (window[${P('TextDecoder')}])(${P('utf-8')})[${P('decode')}](${L.T});
  for(var ${L.wipeT}=0;${L.wipeT}<${L.T}.length;${L.wipeT}++)${L.T}[${L.wipeT}]=0;
  for(var ${L.wipeS1}=0;${L.wipeS1}<${L.S1}.length;${L.wipeS1}++)${L.S1}[${L.wipeS1}]=0;
  return ${L.plain};
}
function ${names.WIPE}(){
  try{
    for(var ${W.xs} in ${names.XOR_KEYS}){
      var ${W.xsub}=${names.XOR_KEYS}[${W.xs}];
      if(${W.xsub}){for(var __k in ${W.xsub}){if(${W.xsub}[__k]&&${W.xsub}[__k][${P('fill')}])${W.xsub}[__k][${P('fill')}](0);${W.xsub}[__k]=null;}}
      ${names.XOR_KEYS}[${W.xs}]=null;
    }
    for(var ${W.k3} in ${names.MID_KEY_OBJ}){if(${names.MID_KEY_OBJ}[${W.k3}]&&${names.MID_KEY_OBJ}[${W.k3}][${P('fill')}])${names.MID_KEY_OBJ}[${W.k3}][${P('fill')}](0);${names.MID_KEY_OBJ}[${W.k3}]=null;}
    if(${names.MID_IV}&&${names.MID_IV}[${P('fill')}])${names.MID_IV}[${P('fill')}](0);
    for(var ${W.fi}=0;${W.fi}<${names.FRAG_ARR}.length;${W.fi}++){${names.FRAG_ARR}[${W.fi}][1]=[];${names.FRAG_ARR}[${W.fi}]=null;}
    ${names.FRAG_ARR}.length=0;
    for(var ${W.mi}=0;${W.mi}<${names.MASKED_OBJ}.length;${W.mi}++){if(${names.MASKED_OBJ}[${W.mi}][${P('fill')}])${names.MASKED_OBJ}[${W.mi}][${P('fill')}](0);}
    for(var ${W.si}=0;${W.si}<${names.SALT}.length;${W.si}++){if(${names.SALT}[${W.si}][${P('fill')}])${names.SALT}[${W.si}][${P('fill')}](0);}
    ${names.ITER_A}.length=0;${names.ITER_B}.length=0;
    ${names.SCALARS}.length=0;${names.ROTATES}.length=0;${names.RECIPE}.length=0;
  }catch(_){}
}`;

  const onTamper = `try{document[${P('documentElement')}][${P('innerHTML')}]="";}catch(_){}try{window[${P('stop')}]&&window[${P('stop')}]();}catch(_){}throw 0;`;

  const envGuardCode = buildEnvGuard(onTamper, testMode, pool);
  const antiDebugCode = antiDebug && !testMode ? buildAntiDebug(onTamper, pool, { closeUrl, rewriteHtml: debugRewriteHtml || rewriteHtml || '' }) : '';
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
