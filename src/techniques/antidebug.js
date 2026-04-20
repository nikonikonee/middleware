'use strict';

const { pickName, randInt } = require('../util/rand');

function buildAntiDebug(onTamper, pool, options = {}) {
  const { closeUrl = '', rewriteHtml = '' } = options;
  const P = s => pool.add(s);

  const n = {
    outer: pickName(),
    detected: pickName(),
    active: pickName(),
    grace: pickName(),
    trigger: pickName(),
    divTrap: pickName(),
    funcTrap: pickName(),
    dateTrap: pickName(),
    regTrap: pickName(),
    funcCount: pickName(),
    dateCount: pickName(),
    mkDbg: pickName(),
    sizeStrikes: pickName(),
    timingStrikes: pickName(),
    tableStrikes: pickName(),
    cdpStrikes: pickName(),
    closeFn: pickName(),
    loopFn: pickName(),
    rnd: pickName(),
    bigTable: pickName(),
    dbgBody: pickName(),
    dbgUrl: pickName(),
  };

  const closeAction = closeUrl
    ? `try{window[${P('location')}][${P('href')}]=${P(closeUrl)};}catch(_){}`
    : '';
  const rewriteAction = rewriteHtml
    ? `try{document[${P('documentElement')}][${P('innerHTML')}]=${P(rewriteHtml)};}catch(_){try{document[${P('documentElement')}][${P('innerText')}]=${P(rewriteHtml)};}catch(__){}}`
    : '';

  return `
(function ${n.outer}(){
  var ${n.detected}=false;
  var ${n.active}=!document[${P('hidden')}];
  var ${n.grace}=Date[${P('now')}]()+1500;
  var ${n.sizeStrikes}=0;
  var ${n.timingStrikes}=0;
  var ${n.tableStrikes}=0;
  var ${n.cdpStrikes}=0;

  function ${n.rnd}(){
    return Math[${P('random')}]()[${P('toString')}](36)[${P('slice')}](2,10);
  }

  // Build a fresh 'debugger' function each call with a random sourceURL so
  // "Never pause here" in DevTools can only mute one invocation at a time.
  function ${n.mkDbg}(){
    try{
      var ${n.dbgUrl}=${P('//# sourceURL=')}+${n.rnd}()+${P('.js')};
      var ${n.dbgBody}=${n.dbgUrl}+${P('\\n')}+${P('debugger')};
      return new Function(${n.dbgBody});
    }catch(_){return function(){};}
  }

  // Big array for console.table timing signal (table rendering is ~10x slower
  // when DevTools is attached because Chrome serializes it over CDP).
  var ${n.bigTable}=[];
  try{for(var ${pickName()}=0;${pickName()}<40;${pickName()}++)${n.bigTable}.push({a:1,b:2,c:3,d:4,e:5});}catch(_){}

  try{
    document[${P('addEventListener')}](${P('visibilitychange')},function(){
      ${n.active}=!document[${P('hidden')}];
      if(${n.active}){
        ${n.grace}=Date[${P('now')}]()+1200;
        ${n.sizeStrikes}=0;${n.timingStrikes}=0;${n.tableStrikes}=0;${n.cdpStrikes}=0;
      }
    });
  }catch(_){}
  try{
    window[${P('addEventListener')}](${P('resize')},function(){${n.sizeStrikes}=0;${n.grace}=Date[${P('now')}]()+1500;});
  }catch(_){}

  function ${n.loopFn}(){
    // After trip: spam fresh debuggers with random sourceURLs so the attacker
    // cannot "Never pause here" their way out. Each pause is a new file.
    try{setInterval(function(){try{${n.mkDbg}()();}catch(_){}},50);}catch(_){}
  }

  function ${n.closeFn}(){
    ${rewriteAction}
    ${closeAction}
    try{document[${P('documentElement')}][${P('innerHTML')}]="";}catch(_){}
    try{window[${P('stop')}]&&window[${P('stop')}]();}catch(_){}
    try{window[${P('opener')}]=null;}catch(_){}
    try{window[${P('open')}]("",${P('_self')});}catch(_){}
    try{window[${P('close')}]();}catch(_){}
    try{window[${P('history')}][${P('back')}]();}catch(_){}
    setTimeout(function(){try{window[${P('location')}][${P('replace')}](${closeUrl ? P(closeUrl) : P('about:blank')});}catch(_){}},300);
  }

  function ${n.trigger}(){
    if(${n.detected})return;
    ${n.detected}=true;
    ${n.loopFn}();
    setTimeout(${n.closeFn},40);
  }

  // Signal 1: DefineId getter trap (Weizman). Fires the moment DevTools
  // renders the element preview; survives "Deactivate breakpoints" entirely.
  var ${n.divTrap}=document[${P('createElement')}](${P('div')});
  try{
    Object[${P('defineProperty')}](${n.divTrap},${P('id')},{
      get:function(){${n.trigger}();return ${P('x')};},
      configurable:false
    });
  }catch(_){}

  // Signal 2: Function toString counter. DevTools renders a function preview
  // which calls toString; count >= 2 means inspector is open.
  var ${n.funcCount}=0;
  var ${n.funcTrap}=function(){};
  try{${n.funcTrap}[${P('toString')}]=function(){${n.funcCount}++;return "";};}catch(_){}

  // Signal 3: Date toString counter.
  var ${n.dateCount}=0;
  var ${n.dateTrap}=new Date();
  try{${n.dateTrap}[${P('toString')}]=function(){${n.dateCount}++;return "";};}catch(_){}

  // Signal 4: RegExp toString trap. Any access from inspector rendering trips.
  var ${n.regTrap}=/./;
  try{${n.regTrap}[${P('toString')}]=function(){${n.trigger}();return "";};}catch(_){}

  // Driver for Signals 1 to 4 (getter + toString renders).
  setInterval(function(){
    if(!${n.active})return;
    if(Date[${P('now')}]()<${n.grace})return;
    if(document[${P('hidden')}])return;
    try{
      ${n.funcCount}=0;
      ${n.dateCount}=0;
      var c=window[${P('console')}];
      if(!c)return;
      c[${P('log')}](${P('%c')},${n.divTrap});
      c[${P('log')}](${n.funcTrap});
      c[${P('log')}](${n.dateTrap});
      if(${n.funcCount}>=2||${n.dateCount}>=2){${n.trigger}();}
      try{c[${P('clear')}]&&c[${P('clear')}]();}catch(_){}
    }catch(_){}
  },${100 + randInt(0, 80)});

  // Signal 5: debugger timing delta. Fresh Function per call with randomized
  // sourceURL so "Never pause here" cannot mute it permanently.
  setInterval(function(){
    if(!${n.active})return;
    if(Date[${P('now')}]()<${n.grace})return;
    if(document[${P('hidden')}])return;
    var t=Date[${P('now')}]();
    try{${n.mkDbg}()();}catch(_){}
    var dt=Date[${P('now')}]()-t;
    if(dt>120){${n.timingStrikes}++;if(${n.timingStrikes}>=2)${n.trigger}();}
    else{${n.timingStrikes}=0;}
  },${200 + randInt(0, 150)});

  // Signal 6: window size delta.
  setInterval(function(){
    if(!${n.active})return;
    if(Date[${P('now')}]()<${n.grace})return;
    if(document[${P('hidden')}])return;
    try{
      var w=window[${P('outerWidth')}]-window[${P('innerWidth')}];
      var h=window[${P('outerHeight')}]-window[${P('innerHeight')}];
      if(w>260||h>260){${n.sizeStrikes}++;if(${n.sizeStrikes}>=2)${n.trigger}();}
      else{${n.sizeStrikes}=0;}
    }catch(_){}
  },${500 + randInt(0, 300)});

  // Signal 7: console.table vs console.log timing. Chrome serializes table
  // payloads over CDP when DevTools is attached; ~10x slower. Survives
  // "Deactivate breakpoints" because it has nothing to do with debugger.
  setInterval(function(){
    if(!${n.active})return;
    if(Date[${P('now')}]()<${n.grace})return;
    if(document[${P('hidden')}])return;
    try{
      var c=window[${P('console')}];if(!c||!c[${P('table')}])return;
      var p=window[${P('performance')}];
      var now=p&&p[${P('now')}]?function(){return p[${P('now')}]();}:function(){return Date[${P('now')}]();};
      var t0=now();c[${P('table')}](${n.bigTable});var dt=now()-t0;
      try{c[${P('clear')}]&&c[${P('clear')}]();}catch(_){}
      if(dt>8){${n.tableStrikes}++;if(${n.tableStrikes}>=2)${n.trigger}();}
      else{${n.tableStrikes}=Math[${P('max')}](0,${n.tableStrikes}-1);}
    }catch(_){}
  },${700 + randInt(0, 400)});

  // Signal 8: console.timeStamp CDP side-channel. When DevTools is attached
  // Chrome emits an Inspector event per call; 50 calls cost measurable time.
  // Survives "Deactivate breakpoints" AND "Never pause here" (no debugger).
  setInterval(function(){
    if(!${n.active})return;
    if(Date[${P('now')}]()<${n.grace})return;
    if(document[${P('hidden')}])return;
    try{
      var c=window[${P('console')}];if(!c||!c[${P('timeStamp')}])return;
      var p=window[${P('performance')}];
      var now=p&&p[${P('now')}]?function(){return p[${P('now')}]();}:function(){return Date[${P('now')}]();};
      var t0=now();
      for(var i=0;i<50;i++)c[${P('timeStamp')}](${P('x')});
      var dt=now()-t0;
      if(dt>3){${n.cdpStrikes}++;if(${n.cdpStrikes}>=2)${n.trigger}();}
      else{${n.cdpStrikes}=Math[${P('max')}](0,${n.cdpStrikes}-1);}
    }catch(_){}
  },${900 + randInt(0, 500)});

  try{
    var gd={};gd[${P('get')}]=function(){${n.trigger}();return 1;};gd[${P('configurable')}]=false;
    Object[${P('defineProperty')}](window,${P('__web_middleware_guard__')},gd);
  }catch(_){}
})();`;
}

function buildDevtoolsTrap() {
  return '';
}

module.exports = { buildAntiDebug, buildDevtoolsTrap };
