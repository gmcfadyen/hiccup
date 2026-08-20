/*
 * hiccup - boot-theme.js
 *
 * Applies the saved theme BEFORE any markup is parsed, so a dark-mode user
 * never sees a white flash. Lifted out of every page's <head> so the site can
 * run under a Content-Security-Policy with script-src 'self' and no
 * 'unsafe-inline' -- an inline block would have forced exactly the escape
 * hatch that makes a CSP decorative.
 *
 * Must stay a plain parser-blocking <script src> in <head>: async/defer would
 * let the page paint first, which is the flash this exists to prevent.
 */
(function(){try{var t=localStorage.getItem('hiccup-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);}catch(e){}})();
