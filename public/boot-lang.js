/*
 * hiccup - boot-lang.js
 *
 * Resolves the UI language before any markup is parsed and pulls in the
 * matching catalogue, because _t() and its data must both exist before the
 * first render. document.write gives a blocking load with no fetch race and
 * no build step, and still works from an external file precisely because this
 * is parser-blocking (no async/defer).
 *
 * Lifted out of each page's <head> for the CSP, same reason as boot-theme.js.
 */
(function(){try{var L=localStorage.getItem('hiccup-lang');if(!/^(en|fr|es|de)$/.test(L||''))L=String(navigator.language||'en').slice(0,2).toLowerCase();if(!/^(en|fr|es|de)$/.test(L))L='en';document.documentElement.lang=L;if(L!=='en')document.write('<script src="/i18n/'+L+'.js"><\/script>');}catch(e){}})();
