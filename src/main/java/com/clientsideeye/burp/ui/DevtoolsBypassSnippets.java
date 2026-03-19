package com.clientsideeye.burp.ui;

final class DevtoolsBypassSnippets {
    private DevtoolsBypassSnippets() {
    }

    static String script() {
        return """
            (function(){
              const hasDebugger = (fn) => {
                try {
                  if (typeof fn === 'string') return fn.includes('debugger');
                  if (typeof fn === 'function') return /debugger/.test(Function.prototype.toString.call(fn));
                } catch (e) {}
                return false;
              };
              const stripDebugger = (code) => typeof code === 'string' ? code.replace(/\bdebugger\b/g,'') : code;
              const wrapFn = (fn) => {
                if (typeof fn !== 'function') return fn;
                try {
                  const src = Function.prototype.toString.call(fn);
                  if (/\bdebugger\b/.test(src)) return function(){};
                } catch (e) {}
                return fn;
              };
              const patchTimer = (name) => {
                const orig = window[name];
                window[name] = function(fn, t, ...args){
                  if (typeof fn === 'string') fn = stripDebugger(fn);
                  else fn = wrapFn(fn);
                  if (hasDebugger(fn)) return 0;
                  return orig.call(this, fn, t, ...args);
                };
              };
              patchTimer('setInterval');
              patchTimer('setTimeout');
              try { window.eval = (orig => function(code){ return orig.call(this, stripDebugger(code)); })(window.eval); } catch (e) {}
              try {
                const OrigFunction = Function;
                window.Function = function(...args){
                  if (args.length) args[args.length-1] = stripDebugger(args[args.length-1]);
                  return OrigFunction.apply(this, args);
                };
                window.Function.prototype = OrigFunction.prototype;
              } catch (e) {}
              try { console.clear = function(){}; } catch (e) {}
              try { console.profile = function(){}; } catch (e) {}
              const forceOuterInner = () => {
                const define = (obj, prop, getter) => {
                  try { Object.defineProperty(obj, prop, {get: getter, configurable: true}); return true; } catch (e) { return false; }
                };
                define(window, 'outerWidth', () => window.innerWidth);
                define(window, 'outerHeight', () => window.innerHeight);
                if (window.Window && Window.prototype) {
                  define(Window.prototype, 'outerWidth', () => window.innerWidth);
                  define(Window.prototype, 'outerHeight', () => window.innerHeight);
                }
              };
              try { forceOuterInner(); } catch (e) {}
              try { window.addEventListener('resize', forceOuterInner); } catch (e) {}
              try { setInterval(forceOuterInner, 1000); } catch (e) {}
              try { Object.defineProperty(window,'devtools',{get(){return {isOpen:false,orientation:undefined}}}); } catch (e) {}
              try { Object.defineProperty(window,'__REACT_DEVTOOLS_GLOBAL_HOOK__',{get(){return {isDisabled:true}}}); } catch (e) {}
              try { window.__clientsideeye_devtools_bypass = true; } catch (e) {}
            })();
            """;
    }
}
