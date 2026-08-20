/* hiccup - index-auth.js (lifted from index.html so the site can run under a CSP with no 'unsafe-inline'). */
(function () {
  'use strict';

  // i18n.js defines _t globally; fall back to identity so a missing catalogue
  // degrades this page to English instead of breaking sign-in entirely.
  var _t = (window && window._t) || function (s) { return s; };

  function $(id) { return document.getElementById(id); }

  function validEmail(v) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  }

  function setError(el, msg) { el.textContent = msg || ''; }

  /**
   * POST a JSON body to an auth endpoint. On 2xx → /app.
   * On failure, writes the server's {error} (or a fallback) into errEl.
   */
  async function postAuth(url, body, errEl, btn) {
    setError(errEl, '');
    if (btn) btn.disabled = true;
    try {
      var r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      var data = {};
      try { data = await r.json(); } catch (e) { /* non-JSON body */ }
      if (r.ok) { location = '/app'; return; }
      setError(errEl, (data && data.error) || (_t('request failed') + ' (' + r.status + ')'));
    } catch (e) {
      setError(errEl, _t('could not reach the server'));
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  $('signup-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var errEl = $('signup-error');
    var email = $('su-email').value.trim().toLowerCase();
    var password = $('su-password').value;
    if (!validEmail(email)) { setError(errEl, _t('enter a valid email address')); return; }
    if (password.length < 8) { setError(errEl, _t('password must be at least 8 characters')); return; }
    postAuth('/api/auth/signup', { email: email, password: password }, errEl, $('signup-btn'));
  });

  $('login-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var errEl = $('login-error');
    var email = $('li-email').value.trim().toLowerCase();
    var password = $('li-password').value;
    if (!validEmail(email)) { setError(errEl, _t('enter a valid email address')); return; }
    if (!password) { setError(errEl, _t('enter your password')); return; }
    postAuth('/api/auth/login', { email: email, password: password }, errEl, $('login-btn'));
  });

  /** GIS callback: exchange the Google ID token for a hiccup session. */
  function onGoogleCredential(resp) {
    var errEl = $('google-error');
    if (!resp || !resp.credential) {
      setError(errEl, _t('google sign-in returned no credential'));
      return;
    }
    postAuth('/api/auth/google', { credential: resp.credential }, errEl, null);
  }

  /**
   * Inject the GIS script and render the Google button.
   * Only ever called when /api/config/public reports a googleClientId —
   * no external requests are made otherwise.
   */
  function initGoogle(clientId) {
    var s = document.createElement('script');
    s.src = 'https://accounts.google.com/gsi/client';
    s.async = true;
    s.defer = true;
    s.onload = function () {
      if (!(window.google && google.accounts && google.accounts.id)) return;
      google.accounts.id.initialize({
        client_id: clientId,
        callback: onGoogleCredential
      });
      $('google-wrap').hidden = false;
      google.accounts.id.renderButton($('google-btn'), {
        theme: 'filled_black',
        size: 'large',
        text: 'continue_with',
        width: 280
      });
    };
    document.head.appendChild(s);
  }

  (async function boot() {
    // Already signed in? Swap the auth forms for an "Open app" button.
    var signedIn = false;
    try {
      var me = await fetch('/api/me');
      signedIn = me.ok;
    } catch (e) { /* server unreachable — leave the forms up */ }
    if (signedIn) {
      $('auth-body').hidden = true;
      $('open-app').hidden = false;
      return;
    }
    // Google sign-in, only when the server has a client id configured.
    try {
      var r = await fetch('/api/config/public');
      if (r.ok) {
        var cfg = await r.json();
        if (cfg && cfg.googleClientId) initGoogle(cfg.googleClientId);
      }
    } catch (e) { /* no config → no Google button; forms still work */ }
  })();
})();
