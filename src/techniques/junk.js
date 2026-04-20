'use strict';

const { randInt, pickName, shuffle } = require('../util/rand');

function junkExpr() {
  const patterns = [
    () => `${randInt(0, 9999)}^${randInt(0, 9999)}`,
    () => `Math.sin(${randInt(0, 999)})*${randInt(1, 99)}`,
    () => `(${randInt(0, 255)}&${randInt(0, 255)})|${randInt(0, 255)}`,
    () => `"${Math.random().toString(36).slice(2, 10)}".length`,
    () => `parseInt("${randInt(16, 255).toString(16)}",16)`,
    () => `Array(${randInt(2, 9)}).join("${Math.random().toString(36).slice(2, 4)}")`,
    () => `Date.now()%${randInt(2, 9999)}`,
    () => `(function(){return ${randInt(0, 99)};})()`,
  ];
  return patterns[randInt(0, patterns.length)]();
}

function junkStatement() {
  const v = pickName();
  const patterns = [
    () => `var ${v}=${junkExpr()};if(${v}>${randInt(-9999, 9999)}){${v}+=${junkExpr()};}`,
    () => `try{var ${v}=${junkExpr()};}catch(${pickName()}){}`,
    () => `for(var ${v}=0;${v}<${randInt(0, 3)};${v}++){void ${junkExpr()};}`,
    () => `(function(){var ${v}=${junkExpr()};return ${v};})();`,
    () => `var ${v}=[${junkExpr()},${junkExpr()},${junkExpr()}];${v}.sort();`,
    () => `if(typeof ${pickName()}==="undefined"){var ${v}=${junkExpr()};}`,
  ];
  return patterns[randInt(0, patterns.length)]();
}

function junkFunction() {
  const name = pickName();
  const arg = pickName();
  const body = [];
  const depth = randInt(2, 6);
  for (let i = 0; i < depth; i++) body.push(junkStatement());
  body.push(`return ${arg}^${junkExpr()};`);
  return `function ${name}(${arg}){${body.join('')}}`;
}

function junkBlock(min = 3, max = 8) {
  const n = randInt(min, max + 1);
  const parts = [];
  for (let i = 0; i < n; i++) {
    parts.push(Math.random() < 0.3 ? junkFunction() : junkStatement());
  }
  return parts.join('');
}

function term(s) {
  const t = s.trimEnd();
  if (!t) return '';
  const last = t[t.length - 1];
  if (last === ';' || last === '}') return t;
  return t + ';';
}

function interleaveJunk(realStatements, ratio = 1.0) {
  const out = [];
  for (const s of realStatements) {
    const count = Math.floor(ratio) + (Math.random() < (ratio - Math.floor(ratio)) ? 1 : 0);
    for (let i = 0; i < count; i++) out.push(term(junkStatement()));
    out.push(term(s));
  }
  for (let i = 0; i < randInt(2, 5); i++) out.push(term(junkStatement()));
  return out.join('');
}

function opaquePredicate(truthy = true) {
  const a = randInt(1, 99);
  const b = randInt(1, 99);
  const expr = `((${a}*${b})%${a}===0)`;
  return truthy ? expr : `!${expr}`;
}

module.exports = { junkExpr, junkStatement, junkFunction, junkBlock, interleaveJunk, opaquePredicate };
