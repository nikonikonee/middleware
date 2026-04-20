'use strict';

const { randInt, shuffle, pickName } = require('../util/rand');

function flattenStatements(statements) {
  const states = statements.map((_, i) => randInt(1000, 99999));
  const uniqueStates = Array.from(new Set(states));
  while (uniqueStates.length < statements.length) {
    uniqueStates.push(randInt(1000, 99999));
  }
  const stateOrder = uniqueStates.slice(0, statements.length);

  const stateVar = pickName();
  const nextMap = {};
  for (let i = 0; i < stateOrder.length; i++) {
    nextMap[stateOrder[i]] = stateOrder[i + 1] !== undefined ? stateOrder[i + 1] : -1;
  }

  const cases = shuffle(stateOrder.map((s, i) => ({ state: s, body: statements[i] })));

  const caseCode = cases.map(c =>
    `case ${c.state}:{${c.body};${stateVar}=${nextMap[c.state]};break;}`
  ).join('');

  return `
(function(){
  var ${stateVar}=${stateOrder[0]};
  while(${stateVar}!==-1){
    switch(${stateVar}){
      ${caseCode}
      default:${stateVar}=-1;
    }
  }
})();`;
}

module.exports = { flattenStatements };
