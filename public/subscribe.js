/*
 * hiccup — subscribe.js
 * The subscribe/pricing page (public/subscribe.html).
 *
 * Split out of subscribe.html's <script> so this page's runtime text goes
 * through the same _t() / i18n-extraction pipeline every other user-facing
 * page uses — an inline <script> block is invisible to lib/i18n.js's
 * scanHtml() by design (see ARCHITECTURE.md Wave 8). That is fine for the
 * admin-only pages (nobody but the site operator ever sees them), but this
 * page is meant to be reached from the public marketing site.
 */
(function () {
  'use strict';
  var _t = (window && window._t) || function (s) { return s; };

  // Best-effort personalisation only — this page must work fine for a
  // signed-out visitor, which is most of its traffic (it is meant to be
  // reachable from the marketing landing page before anyone has an account).
  fetch('/api/me').then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
    var user = d && d.user;
    var box = document.getElementById('sub-status');
    if (!user) return;
    box.hidden = false;
    if (user.plan === 'paid') {
      box.className = 'is-paid';
      box.textContent = _t('You are already on the paid plan — head to your team page to create or join one.');
    } else {
      box.className = 'is-free';
      box.textContent = _t('Signed in as ') + user.email + _t(' — currently on the free plan.');
    }
  }).catch(function () { /* signed-out visitor, or offline — the page still works */ });
})();
