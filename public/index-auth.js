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

  /** The SSO reveal/submit pair — same shape as the Google button's reveal,
   * but the destination is a top-level navigation, not a fetch. See
   * ssoContinue()'s own comment for why that matters. Idempotent: a failed
   * round trip and a successful availability check can each call this, and
   * binding the same listeners twice would double-fire every click. */
  var _ssoInited = false;
  function initSso() {
    if (_ssoInited) { $('sso-wrap').hidden = false; return; }
    _ssoInited = true;
    $('sso-wrap').hidden = false;
    $('sso-reveal-btn').addEventListener('click', function () {
      var row = $('sso-row');
      row.hidden = !row.hidden;
      if (!row.hidden) $('sso-email').focus();
    });
    $('sso-continue-btn').addEventListener('click', ssoContinue);
    $('sso-email').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); ssoContinue(); }
    });
  }

  function ssoContinue() {
    var errEl = $('sso-error');
    var email = $('sso-email').value.trim();
    if (!validEmail(email)) { setError(errEl, _t('enter a valid email address')); return; }
    setError(errEl, '');
    var btn = $('sso-continue-btn');
    btn.disabled = true;
    // A plain top-level navigation, not fetch() — the IdP round trip (an
    // external https:// redirect and a 300ms+ round trip at their login
    // page) never has to touch this page's fetch/CSP at all this way, and
    // the browser handles third-party cookies/storage exactly as it would
    // for any other cross-site login redirect.
    location.href = '/api/auth/sso/start?email=' + encodeURIComponent(email) +
      '&next=' + encodeURIComponent('/team');
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
    // An SSO round trip that failed bounces back here with ?sso_error=...
    // rather than a JSON response, because /api/auth/sso/start and
    // /callback are top-level navigations, not fetch calls (see
    // ssoContinue()). Surface it in the same error slot a JS-driven
    // attempt would have used.
    var params = new URLSearchParams(location.search);
    if (params.has('sso_error')) {
      initSso();
      $('sso-row').hidden = false;
      setError($('sso-error'), params.get('sso_error'));
    }
    // Google sign-in, only when the server has a client id configured.
    try {
      var r = await fetch('/api/config/public');
      if (r.ok) {
        var cfg = await r.json();
        if (cfg && cfg.googleClientId) initGoogle(cfg.googleClientId);
      }
    } catch (e) { /* no config → no Google button; forms still work */ }
    // SSO, only when at least one team has it turned on somewhere on this
    // server. Reveals nothing about which team or which domains — see
    // GET /api/auth/sso/available's own comment.
    try {
      var r2 = await fetch('/api/auth/sso/available');
      if (r2.ok) {
        var d = await r2.json();
        if (d && d.enabled) initSso();
      }
    } catch (e) { /* no SSO button; forms still work */ }
  })();
})();
