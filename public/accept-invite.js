/*
 * hiccup — accept-invite.js
 * The public invite-accept page (public/accept-invite.html).
 *
 * Reads ?token=, calls GET /api/team/invite-info/:token (404 -> invalid/expired
 * state), then GET /api/me to see whether the visitor is already authenticated
 * as the invited address, and renders exactly one of the three branches
 * lib/teams.js's acceptInvite() expects (ARCHITECTURE.md "Wave 3"):
 *   (a) already signed in as the invited email -> a single "Join" button
 *   (b) invited email belongs to an existing account, caller is someone else
 *       (or no one) -> a password field ("sign in first" note instead, for a
 *       Google-only account with no password to check against)
 *   (c) brand-new email -> name + password fields, creates the account
 * POSTs to /api/team/accept with the matching body shape, redirects to /app
 * on success.
 *
 * This page is reached by a signed-out visitor from an emailed/copied link,
 * so a 401 from GET /api/me is an expected, normal response here -- never a
 * reason to redirect away. All DOM building is vanilla createElement; every
 * string that came from the server or a form field goes through textContent
 * — never innerHTML.
 */
(function () {
  'use strict';
  // public/i18n.js publishes window._t from a blocking <head> script. The local
  // alias keeps this file working — in English — if that script is ever missing,
  // rather than throwing a ReferenceError out of every render.
  var _t = (window && window._t) || function (s) { return s; };

  // ---------------------------------------------------------------- helpers

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

  function isStr(v) { return typeof v === 'string' && v.length > 0; }

  // Server errors are English sentences with no code field; the catalogue is keyed
  // on the source text, so _t() localises them without touching server.js.
  function errMsg(payload, fallback) {
    return _t((payload && (payload.error || payload.userMessage)) || '') || fallback;
  }

  // ------------------------------------------------------------------ state

  var state = {
    token: '',
    info: null,     // { email, teamName, emailExists, hasPassword }
    me: null,       // { name, email, ... } or null (401 / not signed in)
    branch: null    // 'silent' | 'password' | 'create'
  };

  // ------------------------------------------------------------------- boot

  function wire() {
    $('accept-retry').addEventListener('click', function () { loadInvite(); });
  }

  /** mode: 'loading' | 'invalid' | 'error' | 'ready' */
  function setTopState(mode, message) {
    $('accept-loading').hidden = mode !== 'loading';
    $('accept-invalid').hidden = mode !== 'invalid';
    $('accept-error').hidden = mode !== 'error';
    $('accept-ready').hidden = mode !== 'ready';
    if (mode === 'error') $('accept-error-text').textContent = message || _t('Something went wrong.');
  }

  function setFormError(msg) { $('accept-form-error').textContent = msg || ''; }

  async function fetchMe() {
    try {
      var r = await fetch('/api/me');
      if (!r.ok) return null; // 401 (not signed in) or anything else -> treat as signed out
      var j = await r.json();
      return (j && j.user) ? j.user : null;
    } catch (e) {
      return null;
    }
  }

  async function loadInvite() {
    setTopState('loading');

    var params = new URLSearchParams(location.search);
    state.token = params.get('token') || '';
    if (!state.token) { setTopState('invalid'); return; }

    var res = null, payload = null;
    try {
      res = await fetch('/api/team/invite-info/' + encodeURIComponent(state.token));
    } catch (e) {
      setTopState('error', _t('Could not reach the server. Check your connection and reload this page.'));
      return;
    }
    if (res.status === 404) { setTopState('invalid'); return; }
    try { payload = await res.json(); } catch (e) { payload = null; }
    if (!res.ok) {
      setTopState('error', errMsg(payload, _t('Could not load this invite (status ') + res.status + ').'));
      return;
    }
    if (!payload || !isStr(payload.email) || !isStr(payload.teamName)) {
      setTopState('error', _t('hiccup received an unexpected response for this invite.'));
      return;
    }
    state.info = payload;

    state.me = await fetchMe();

    var meEmail = state.me && isStr(state.me.email) ? state.me.email.toLowerCase() : null;
    var invitedEmail = state.info.email.toLowerCase();
    if (meEmail && meEmail === invitedEmail) state.branch = 'silent';
    else if (state.info.emailExists) state.branch = 'password';
    else state.branch = 'create';

    renderReady();
    setTopState('ready');
  }

  // ----------------------------------------------------------------- render

  function renderReady() {
    var teamName = state.info.teamName || _t('this team');
    var email = state.info.email || '';

    var introHost = $('accept-intro');
    clear(introHost);
    introHost.appendChild(el('p', 'accept-intro-text',
      _t('You have been invited to join ') + teamName + _t(' as ') + email + '.'));

    var formHost = $('accept-form-host');
    clear(formHost);
    setFormError('');

    if (state.branch === 'silent') renderSilentBranch(formHost, teamName);
    else if (state.branch === 'password') renderPasswordBranch(formHost, teamName, email);
    else renderCreateBranch(formHost, teamName, email);
  }

  /** Branch (a): already signed in as the invited email — no fields needed. */
  function renderSilentBranch(host, teamName) {
    host.appendChild(el('p', 'muted', _t('You are already signed in with the invited address.')));

    var wrap = el('div', 'accept-actions');
    var btn = el('button', 'btn btn-primary', _t('Join ') + teamName);
    btn.type = 'button';
    btn.addEventListener('click', function () {
      submitAccept({ token: state.token }, btn, _t('Join ') + teamName);
    });
    wrap.appendChild(btn);
    host.appendChild(wrap);
  }

  /**
   * Branch (b): the invited email already has a hiccup account and the
   * visitor is not currently authenticated as it. hasPassword distinguishes
   * a normal (password) account from a Google-only one — a Google-only
   * account has no password hash to check, so acceptInvite would reject any
   * password there is to submit; show a "sign in first" note instead of a
   * form that is guaranteed to fail.
   */
  function renderPasswordBranch(host, teamName, email) {
    if (!state.info.hasPassword) {
      host.appendChild(el('p', 'muted',
        email + _t(' signs in with Google. Sign in with that Google account first, then reopen ') +
        _t('this invite link to join automatically.')));
      var wrap = el('div', 'accept-actions');
      var a = el('a', 'btn', _t('Go to sign in'));
      a.href = '/';
      wrap.appendChild(a);
      host.appendChild(wrap);
      return;
    }

    host.appendChild(el('p', 'muted',
      email + _t(' already has a hiccup account. Enter its password to join ') + teamName + '.'));

    var form = document.createElement('form');
    form.setAttribute('novalidate', '');

    var label = el('label', null, _t('Password'));
    label.setAttribute('for', 'accept-password');
    form.appendChild(label);

    var pw = el('input', 'input');
    pw.type = 'password';
    pw.id = 'accept-password';
    pw.name = 'password';
    pw.autocomplete = 'current-password';
    pw.placeholder = _t('your password');
    form.appendChild(pw);

    var actions = el('div', 'accept-actions');
    var btn = el('button', 'btn btn-primary', _t('Join ') + teamName);
    btn.type = 'submit';
    actions.appendChild(btn);
    form.appendChild(actions);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var password = pw.value;
      if (!password) { setFormError(_t('Enter your password.')); return; }
      submitAccept({ token: state.token, password: password }, btn, _t('Join ') + teamName);
    });

    host.appendChild(form);
  }

  /** Branch (c): brand-new email — create the account and join in one step. */
  function renderCreateBranch(host, teamName, email) {
    host.appendChild(el('p', 'muted', _t('Create your hiccup account to join ') + teamName + '.'));

    var form = document.createElement('form');
    form.setAttribute('novalidate', '');

    var nameLabel = el('label', null, _t('Your name'));
    nameLabel.setAttribute('for', 'accept-name');
    form.appendChild(nameLabel);
    var nameInput = el('input', 'input');
    nameInput.type = 'text';
    nameInput.id = 'accept-name';
    nameInput.name = 'name';
    nameInput.autocomplete = 'name';
    nameInput.placeholder = _t('Jane Doe');
    form.appendChild(nameInput);

    var pwLabel = el('label', null, _t('Password'));
    pwLabel.setAttribute('for', 'accept-new-password');
    form.appendChild(pwLabel);
    var pw = el('input', 'input');
    pw.type = 'password';
    pw.id = 'accept-new-password';
    pw.name = 'password';
    pw.autocomplete = 'new-password';
    pw.placeholder = _t('at least 8 characters');
    pw.minLength = 8;
    form.appendChild(pw);

    var actions = el('div', 'accept-actions');
    var btn = el('button', 'btn btn-primary', _t('Create account & join'));
    btn.type = 'submit';
    actions.appendChild(btn);
    form.appendChild(actions);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var name = (nameInput.value || '').trim();
      var password = pw.value;
      if (!name) { setFormError(_t('Enter your name.')); return; }
      if (password.length < 8) { setFormError(_t('Password must be at least 8 characters.')); return; }
      submitAccept({ token: state.token, password: password, name: name }, btn, _t('Create account & join'));
    });

    host.appendChild(form);
  }

  /**
   * POST /api/team/accept with the branch-specific body. On success the
   * server sets the session cookie itself; this page only redirects.
   */
  async function submitAccept(body, btn, origLabel) {
    setFormError('');
    if (btn) { btn.disabled = true; btn.textContent = _t('Joining…'); }

    var res = null, payload = null;
    try {
      res = await fetch('/api/team/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      setFormError(_t('Could not reach the server. Check your connection and try again.'));
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
      return;
    }
    if (!res.ok) {
      setFormError(errMsg(payload, _t('Could not join (status ') + res.status + ').'));
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
      return;
    }
    location.href = '/app';
  }

  // ------------------------------------------------------------------- init

  wire();
  loadInvite();
})();
