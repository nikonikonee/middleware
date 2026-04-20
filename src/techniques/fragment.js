'use strict';

const { randInt, shuffle } = require('../util/rand');

function fragmentBuffer(buf, minChunks = 12, maxChunks = 32) {
  const n = randInt(minChunks, maxChunks + 1);
  const len = buf.length;
  if (len === 0) return [{ idx: 0, b64: '' }];
  const cuts = new Set();
  while (cuts.size < Math.min(n - 1, Math.max(0, len - 1))) {
    cuts.add(randInt(1, len));
  }
  const sorted = [...cuts].sort((a, b) => a - b);
  const pieces = [];
  let prev = 0;
  for (const c of sorted) {
    pieces.push(buf.slice(prev, c));
    prev = c;
  }
  pieces.push(buf.slice(prev));

  const tagged = pieces.map((p, idx) => ({ idx, b64: p.toString('base64') }));
  return shuffle(tagged);
}

function fragmentsToJs(fragments, arrName, indexName) {
  const entries = fragments.map(f => `[${f.idx},"${f.b64}"]`).join(',');
  return `var ${arrName}=[${entries}];`;
}

function reassembleFragmentsJs(arrName, outName, tmpBytes) {
  return `
var ${outName}=(function(){
  var a=${arrName}.slice().sort(function(x,y){return x[0]-y[0];});
  var parts=a.map(function(p){
    var s=atob(p[1]);
    var b=new Uint8Array(s.length);
    for(var i=0;i<s.length;i++)b[i]=s.charCodeAt(i);
    return b;
  });
  var total=0;for(var k=0;k<parts.length;k++)total+=parts[k].length;
  var ${tmpBytes}=new Uint8Array(total);var off=0;
  for(var j=0;j<parts.length;j++){${tmpBytes}.set(parts[j],off);off+=parts[j].length;}
  for(var m=0;m<${arrName}.length;m++){${arrName}[m][1]="";${arrName}[m]=null;}
  ${arrName}.length=0;
  return ${tmpBytes};
})();`;
}

module.exports = { fragmentBuffer, fragmentsToJs, reassembleFragmentsJs };
