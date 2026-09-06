/* Runs synchronously in <head> so a saved theme applies before first paint.
   No attribute = follow the system preference (see site.css). */
(function () {
  try {
    var t = localStorage.getItem('groovable-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* storage unavailable: system preference decides */ }
})();
