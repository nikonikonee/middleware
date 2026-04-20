'use strict';

const { randInt, shuffle, pickName } = require('./rand');

function unicodeEscape(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    out += '\\u' + s.charCodeAt(i).toString(16).padStart(4, '0');
  }
  return out;
}

function charCodes(s) {
  const codes = [];
  for (let i = 0; i < s.length; i++) codes.push(s.charCodeAt(i));
  return codes;
}

class StringPool {
  constructor(nameStyle = 'hex') {
    this.strings = [];
    this.map = new Map();
    this.getter = pickName(nameStyle);
    this.arr = pickName(nameStyle);
    this.lookup = pickName(nameStyle);
    this.sRef = pickName(nameStyle);
    this.fRef = pickName(nameStyle);
    this.rot = randInt(7, 73);
    this.nameStyle = nameStyle;
  }

  add(s) {
    if (typeof s !== 'string') throw new Error('StringPool.add: not a string');
    if (this.map.has(s)) return `${this.getter}(${this.map.get(s)})`;
    const idx = this.strings.length;
    this.strings.push(s);
    this.map.set(s, idx);
    return `${this.getter}(${idx})`;
  }

  emit() {
    const tagged = this.strings.map((s, originalIdx) => ({
      originalIdx,
      codes: charCodes(s),
    }));
    const shuffled = shuffle(tagged);

    const positionMap = new Array(this.strings.length);
    shuffled.forEach((p, newIdx) => { positionMap[p.originalIdx] = newIdx; });

    const rotated = shuffled.map(p => p.codes);
    for (let r = 0; r < this.rot; r++) rotated.unshift(rotated.pop());

    const invMap = new Array(this.strings.length);
    positionMap.forEach((pos, orig) => {
      invMap[orig] = (pos + this.rot) % this.strings.length;
    });

    const arrLit =
      `var ${this.arr}=[` +
      rotated.map(codes => '[' + codes.join(',') + ']').join(',') +
      '];';

    const lookupLit = `var ${this.lookup}=[${invMap.join(',')}];`;

    const sEsc = unicodeEscape('String');
    const fccEsc = unicodeEscape('fromCharCode');
    const bootstrap =
      `var ${this.sRef}=${sEsc};` +
      `var ${this.fRef}=${this.sRef}.${fccEsc};`;

    const tmp = pickName(this.nameStyle);
    const codesVar = pickName(this.nameStyle);
    const outVar = pickName(this.nameStyle);
    const jVar = pickName(this.nameStyle);
    const getter =
      `function ${this.getter}(${tmp}){` +
      `var ${codesVar}=${this.arr}[${this.lookup}[${tmp}]];` +
      `var ${outVar}="";` +
      `for(var ${jVar}=0;${jVar}<${codesVar}.length;${jVar}++)` +
      `${outVar}+=${this.fRef}(${codesVar}[${jVar}]);` +
      `return ${outVar};` +
      `}`;

    return arrLit + lookupLit + bootstrap + getter;
  }
}

module.exports = { StringPool };
