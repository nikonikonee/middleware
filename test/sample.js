'use strict';
// sample.js — tiny program used to exercise the JS obfuscator end to end.
// The verify harness sets window.__NC_OUT so we can detect that indirect eval
// actually ran and the original top-level code executed in global scope.
var greeting = 'Hello from web-middleware JS obfuscator';
var counter = 0;
for (var i = 0; i < 5; i++) counter += i;
window.__NC_OUT = greeting + ' count=' + counter;
