/*
 * hiccup — subscribe.js
 *
 * The page has two modes and picks one from /api/config/public:
 *
 *   cardPayments true  -> Stripe Checkout. The buttons POST to
 *                         /api/billing/checkout and follow the returned URL.
 *   cardPayments false -> the manual Buy Me a Coffee flow, which is what
 *                         shipped first and stays as the fallback.
 *
 * The server sends BOOLEANS, never a key or a price id: which prices exist is
 * server-side config precisely so a browser cannot choose one. All this file
 * sends is a tier name and a billing interval.
 *
 * The monthly/annual switch itself is pure CSS (see subscribe.html) -- this
 * file only READS which radio is checked, at the moment a buy button is
 * clicked, so the price shown and the price charged cannot drift apart.
 *
 * Split out of subscribe.html's <script> so its strings go through the same
 * _t() extraction as every other page, and so the site can run under a CSP
 * with script-src 'self' and no 'unsafe-inline'.
 */
(function () {
  'use strict';

  var _t = (window && window._t) || function (s) { return s; };
  function $(id) { return document.getElementById(id); }

  function show(el, cls, msg) {
    if (!el) return;
    el.hidden = false;
    el.className = cls;
    el.textContent = msg;
  }

  /** Which billing period the page is currently showing. */
  function currentInterval() {
    var annual = $('period-annual');
    return (annual && annual.checked) ? 'annual' : 'monthly';
  }

  /* ---------------------------------------------------------------- status */

  function renderPlan(user) {
    var box = $('sub-status');
    if (!user) return;
    if (user.plan === 'team') {
      show(box, 'is-paid', _t('You are on the Team plan — head to your team page to create or join one.'));
    } else if (user.plan === 'pro') {
      show(box, 'is-paid', _t('You are on the Pro plan. Upgrading to Team adds the shared library and invites.'));
    } else {
      show(box, 'is-free', _t('Signed in as ') + user.email + _t(' — currently on the free plan.'));
    }
  }

  /** Has this account already bought something? */
  function isPaid(user) {
    return !!(user && (user.plan === 'pro' || user.plan === 'team'));
  }

  function me() {
    return fetch('/api/me').then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { return (d && d.user) || null; })
      .catch(function () { return null; });
  }

  /* -------------------------------------------------- return from Checkout */

  // Stripe redirects back the moment payment succeeds, but the upgrade happens
  // on a webhook that can land a second or two later. Polling briefly avoids
  // telling someone who has just paid that they are on the free plan.
  function awaitUpgrade(tries) {
    return me().then(function (user) {
      if (isPaid(user)) { renderPlan(user); return; }
      if (tries <= 0) {
        show($('sub-status'), 'is-free',
          _t('Payment received. Your account will switch over in a moment — reload this page shortly.'));
        return;
      }
      return new Promise(function (r) { setTimeout(r, 1200); }).then(function () {
        return awaitUpgrade(tries - 1);
      });
    });
  }

  /* -------------------------------------------------------------- checkout */

  function startCheckout(tier, btn) {
    var err = $('sub-error');
    if (err) err.textContent = '';
    btn.disabled = true;
    var was = btn.textContent;
    btn.textContent = _t('Opening checkout…');
    fetch('/api/billing/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tier: tier, interval: currentInterval() })
    }).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (d) {
        if (r.status === 401) { location.href = '/'; return; }
        if (!r.ok || !d || !d.url) {
          throw new Error((d && d.error) || _t('Could not start checkout.'));
        }
        location.href = d.url;          // hosted by Stripe; no card touches hiccup
      });
    }).catch(function (e) {
      if (err) err.textContent = e.message || _t('Could not start checkout.');
      btn.disabled = false;
      btn.textContent = was;
    });
  }

  function enableCardMode(cfg) {
    document.body.setAttribute('data-pay', 'card');
    // Only advertise Pro once the server confirms both Pro prices exist.
    // Otherwise the card stays hidden by CSS and Team is the only paid option.
    if (cfg && cfg.proPlan) document.body.setAttribute('data-pro', 'on');

    [['sub-pro', 'pro'], ['sub-team', 'team']].forEach(function (pair) {
      var btn = $(pair[0]);
      if (!btn) return;
      btn.removeAttribute('href');
      btn.removeAttribute('target');
      btn.removeAttribute('rel');
      btn.setAttribute('role', 'button');
      btn.addEventListener('click', function (ev) {
        ev.preventDefault();
        startCheckout(pair[1], btn);
      });
    });
  }

  /* ------------------------------------------------------------------ boot */

  fetch('/api/config/public').then(function (r) { return r.ok ? r.json() : null; })
    .then(function (cfg) {
      if (cfg && cfg.cardPayments) enableCardMode(cfg);
      // In the manual flow there is no Stripe price to be missing, so Pro is
      // still worth showing -- the upgrade is done by hand either way.
      else document.body.setAttribute('data-pro', 'on');
    })
    .catch(function () { /* no config -> stay in Buy Me a Coffee mode */ })
    .then(function () {
      var q = String(location.search || '');
      if (q.indexOf('checkout=success') !== -1) return awaitUpgrade(8);
      if (q.indexOf('checkout=cancelled') !== -1) {
        show($('sub-status'), 'is-free', _t('Checkout cancelled — nothing has been charged.'));
        return;
      }
      return me().then(renderPlan);
    });
})();
