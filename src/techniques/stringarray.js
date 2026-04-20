'use strict';

const { randInt, shuffle, pickName } = require('../util/rand');

function buildStringArray(strings, nameStyle = 'hex') {
  const rotation = randInt(3, 29);
  const rotated = [];
  const indexMap = {};
  const shuffledPairs = shuffle(strings.map((s, i) => ({ s, i })));

  shuffledPairs.forEach((p, newIdx) => {
    const encoded = Buffer.from(p.s, 'utf8').toString('base64');
    rotated.push(encoded);
    indexMap[p.i] = newIdx;
  });

  for (let r = 0; r < rotation; r++) rotated.unshift(rotated.pop());

  const arrName = pickName(nameStyle);
  const getterName = pickName(nameStyle);
  const tmpA = pickName(nameStyle);
  const tmpB = pickName(nameStyle);

  const literal = 'var ' + arrName + '=[' + rotated.map(s => '"' + s + '"').join(',') + '];';

  const getter = `
function ${getterName}(${tmpA}){
  ${tmpA}=${tmpA}-0;
  var ${tmpB}=${arrName}[${tmpA}+${rotation}>=${arrName}.length?${tmpA}+${rotation}-${arrName}.length:${tmpA}+${rotation}];
  try{
    return decodeURIComponent(escape(atob(${tmpB})));
  }catch(e){
    return atob(${tmpB});
  }
}`;

  function ref(originalIdx) {
    return `${getterName}(${indexMap[originalIdx]})`;
  }

  return { code: literal + getter, ref, arrName, getterName };
}

module.exports = { buildStringArray };
