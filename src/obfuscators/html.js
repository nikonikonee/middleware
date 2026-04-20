'use strict';

const { buildObfuscatedScript } = require('./core');
const { normalizeOptions } = require('../options');

function obfuscateHtml(html, options = {}) {
  const opts = normalizeOptions(options);
  let source = html;
  if (opts.stripSourceMaps !== false) {
    source = source.replace(/\/[\/\*]#\s*sourceMappingURL=[^\s*]+\s*\*?\/?/g, '');
  }

  // HTML payloads use full integrity by default. The inline <script> has a
  // readable document.currentScript.textContent, so the sentinel-region hash
  // actually verifies at runtime. Caller can force it off with
  // integrityChecks: false.
  const useIntegrity = opts.useIntegrity === undefined ? true : opts.useIntegrity;

  // Bootstrap: parse the decrypted HTML with DOMParser, swap head/body into
  // the current document, and re-clone every <script> so they actually run
  // (innerHTML-inserted scripts are parsed but never executed by spec).
  //
  // We originally used document.open() + document.write() + document.close(),
  // but Chrome silently drops document.write() calls made from an async
  // callback after the parser has finished -- and our decrypt pipeline is
  // async because WebCrypto is async. That left the page blank. DOMParser +
  // manual script cloning is post-load-safe and works identically in every
  // evergreen browser.
  const script = buildObfuscatedScript(source, { ...opts, useIntegrity }, (plain, P) => `
    try{
      var _0xdp=new (window[${P('DOMParser')}])();
      var _0xdoc=_0xdp[${P('parseFromString')}](${plain},${P('text/html')});
      try{document[${P('title')}]=_0xdoc[${P('title')}];}catch(_){}
      try{
        var _0xhead=document[${P('head')}];
        while(_0xhead&&_0xhead[${P('firstChild')}])_0xhead[${P('removeChild')}](_0xhead[${P('firstChild')}]);
        var _0xsrcHead=_0xdoc[${P('head')}];
        if(_0xhead&&_0xsrcHead){
          var _0xhKids=_0xsrcHead[${P('childNodes')}];
          for(var _0xi=0;_0xi<_0xhKids[${P('length')}];_0xi++){
            _0xhead[${P('appendChild')}](document[${P('importNode')}](_0xhKids[_0xi],true));
          }
        }
      }catch(_){}
      try{
        var _0xbody=document[${P('body')}];
        var _0xsrcBody=_0xdoc[${P('body')}];
        if(_0xbody&&_0xsrcBody){
          _0xbody[${P('innerHTML')}]=_0xsrcBody[${P('innerHTML')}];
          var _0xattrs=_0xsrcBody[${P('attributes')}];
          for(var _0xj=0;_0xj<_0xattrs[${P('length')}];_0xj++){
            _0xbody[${P('setAttribute')}](_0xattrs[_0xj][${P('name')}],_0xattrs[_0xj][${P('value')}]);
          }
        }
      }catch(_){}
      // Scripts inserted via innerHTML never execute. Clone each one into a
      // fresh <script> element so the browser actually runs it.
      try{
        var _0xscripts=document[${P('querySelectorAll')}](${P('script')});
        for(var _0xk=0;_0xk<_0xscripts[${P('length')}];_0xk++){
          var _0xold=_0xscripts[_0xk];
          var _0xnew=document[${P('createElement')}](${P('script')});
          var _0xas=_0xold[${P('attributes')}];
          for(var _0xl=0;_0xl<_0xas[${P('length')}];_0xl++){
            _0xnew[${P('setAttribute')}](_0xas[_0xl][${P('name')}],_0xas[_0xl][${P('value')}]);
          }
          var _0xtc=_0xold[${P('textContent')}];
          if(_0xtc)_0xnew[${P('textContent')}]=_0xtc;
          _0xold[${P('parentNode')}][${P('replaceChild')}](_0xnew,_0xold);
        }
      }catch(_){}
    }catch(_){
      // Last-ditch fallback: replace documentElement.innerHTML wholesale.
      // Scripts still will not run, but at least static content renders.
      try{document[${P('documentElement')}][${P('innerHTML')}]=${plain};}catch(__){}
    }
  `);

  return '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title></title></head><body><script>' +
    script +
    '</script></body></html>';
}

module.exports = { obfuscateHtml };
