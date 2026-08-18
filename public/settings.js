/*
 * hiccup — settings.js
 * The account settings page (public/settings.html).
 *
 * Split out of settings.html's former inline <script> so its runtime text
 * goes through the same _t() / i18n-extraction pipeline every other
 * user-facing page uses — an inline <script> block is invisible to
 * lib/i18n.js's scanHtml() by design (see ARCHITECTURE.md Wave 8), which is
 * fine for the admin-only pages but was silently leaving THIS page's status
 * messages and account facts English-only for every signed-in user.
 */
(function () {
  'use strict';
  var _t = (window && window._t) || function (s) { return s; };

  function $(id) { return document.getElementById(id); }
  function say(text, isErr) {
    var m = $('set-msg');
    m.textContent = text || '';
    m.className = 'feedback-msg' + (isErr ? ' is-err' : (text ? ' is-ok' : ''));
  }

  // --- number masking preference -------------------------------------------
  // Stored client-side and sent by app.js as X-Mask-Numbers on upload. Kept
  // local rather than on the user record deliberately: it needs no new server
  // state, and an empty value means "no opinion" so the server default still
  // decides — which is different from explicitly choosing not to mask.
  var maskSel = $('set-mask');
  try { maskSel.value = localStorage.getItem('hiccup-mask-numbers') || ''; } catch (e) { /* blocked */ }
  maskSel.addEventListener('change', function () {
    try {
      if (maskSel.value === '') localStorage.removeItem('hiccup-mask-numbers');
      else localStorage.setItem('hiccup-mask-numbers', maskSel.value);
      say(_t('Saved. This applies to captures you upload from now on.'));
    } catch (e) {
      say(_t('Could not save — this browser is blocking local storage.'), true);
    }
  });

  // --- erase-data flow -------------------------------------------------------
  // Deliberately a DIFFERENT confirm word ("ERASE") than the account-delete
  // flow's "DELETE", right below it on the same page: a mistyped confirmation
  // must not silently fall through into the OTHER irreversible action.
  var eraseWord = $('set-erase-word');
  $('set-erase-start').addEventListener('click', function () {
    $('set-erase-confirm').hidden = false;
    eraseWord.focus();
  });
  $('set-erase-cancel').addEventListener('click', function () {
    $('set-erase-confirm').hidden = true;
    eraseWord.value = '';
    $('set-erase-go').disabled = true;
  });
  eraseWord.addEventListener('input', function () {
    $('set-erase-go').disabled = eraseWord.value !== 'ERASE';
  });
  $('set-erase-go').addEventListener('click', async function () {
    $('set-erase-go').disabled = true;
    say(_t('Erasing…'));
    try {
      var r = await fetch('/api/me/data', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'ERASE' })
      });
      var d = {};
      try { d = await r.json(); } catch (e) { /* non-json */ }
      if (!r.ok) {
        say(_t((d && d.error) || '') || _t('Could not erase your data.'), true);
        $('set-erase-go').disabled = false;
        return;
      }
      var rm = d.removed || {};
      say(_t((d && d.note) || 'Your data has been erased.') + ' ' +
        _t('Removed: ') + (rm.captures || 0) + _t(' captures, ') +
        (rm.projects || 0) + _t(' projects, ') + (rm.kbDocuments || 0) + _t(' library documents.'));
      $('set-erase-confirm').hidden = true;
      eraseWord.value = '';
      refreshScopes();
    } catch (e) {
      say(_t('Could not reach the server.'), true);
      $('set-erase-go').disabled = false;
    }
  });

  // --- delete-account flow ---------------------------------------------------
  var word = $('set-delete-word');
  $('set-delete-start').addEventListener('click', function () {
    $('set-delete-confirm').hidden = false;
    word.focus();
  });
  $('set-delete-cancel').addEventListener('click', function () {
    $('set-delete-confirm').hidden = true;
    word.value = '';
    $('set-delete-go').disabled = true;
  });
  word.addEventListener('input', function () {
    $('set-delete-go').disabled = word.value !== 'DELETE';
  });
  $('set-delete-go').addEventListener('click', async function () {
    $('set-delete-go').disabled = true;
    say(_t('Deleting…'));
    try {
      var r = await fetch('/api/me', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'DELETE' })
      });
      var d = {};
      try { d = await r.json(); } catch (e) { /* non-json */ }
      if (!r.ok) { say(_t((d && d.error) || '') || _t('Could not delete the account.'), true); return; }
      document.body.innerHTML = '<main class="set-page"><h1>' + _t('Account deleted') + '</h1>' +
        '<p class="set-lede"></p></main>';
      document.querySelector('.set-lede').textContent =
        _t((d.note || 'Your account has been removed.')) +
        ' ' + _t('Captures removed: ') + ((d.removed && d.removed.captures) || 0) + '.';
    } catch (e) {
      say(_t('Could not reach the server.'), true);
      $('set-delete-go').disabled = false;
    }
  });

  // --- load account context ---------------------------------------------------

  var lastOnTeam = false;

  /** Re-render the two "what this removes" facts after a successful erase. */
  function refreshScopes() {
    renderScopes(lastOnTeam);
  }

  function renderScopes(onTeam) {
    lastOnTeam = onTeam;
    $('set-erase-scope').textContent = onTeam
      ? _t('Your account is on a shared team library, so there is nothing solely yours to erase here — leave the team to stop sharing it.')
      : _t('Every capture you have uploaded, your projects and your library documents. Your account, login and team membership are not touched.');

    // Being explicit here matters: on a team the shared library is NOT yours
    // to destroy, and someone about to delete their account deserves to know
    // that before they click, not after.
    $('set-delete-scope').textContent = onTeam
      ? _t('Your account, your membership of the team, and your personal records. The team\'s shared capture library stays with the team — deleting your account does not remove your colleagues\' data.')
      : _t('Your account, every capture you have uploaded, your projects and your library documents. Feedback you sent is kept but no longer linked to you.');
  }

  (async function load() {
    var me = null;
    try {
      var r = await fetch('/api/me');
      if (r.status === 401) { location = '/'; return; }
      me = (await r.json()).user;
    } catch (e) { say(_t('Could not reach the server.'), true); return; }

    $('set-who').textContent = _t('Signed in as ') + me.email +
      (me.createdAt ? (_t(' · member since ') + new Date(me.createdAt).toLocaleDateString()) : '');

    // Retention + sharing are facts about THIS deployment, so read them from
    // the server rather than restating a policy this page cannot verify.
    try {
      var cr = await fetch('/api/config/public');
      var cfg = cr.ok ? await cr.json() : {};
      var days = Number(cfg.captureRetentionDays || 0);
      $('set-retention').textContent = days > 0
        ? (_t('Captures are deleted automatically ') + days + _t(' days after upload.'))
        : _t('Captures are kept until you delete them. No automatic expiry is configured on this server.');
      var d = cfg.maskNumbersByDefault === false ? _t('not masked') : _t('masked');
      maskSel.options[0].textContent = _t('use the server default (') + d + ')';
    } catch (e) {
      $('set-retention').textContent = _t('Could not read the retention policy from the server.');
    }

    var onTeam = false;
    try {
      var tr = await fetch('/api/team');
      if (tr.ok) {
        var tv = await tr.json();
        onTeam = !!(tv && tv.team);
        $('set-sharing').textContent = onTeam
          ? _t('You are on the team "{0}". Captures uploaded by any member are visible to every member — the library is shared, not per-person.', tv.team.name || _t('team'))
          : _t('Only you. Your captures are not visible to any other account.');
      } else {
        $('set-sharing').textContent = _t('Only you.');
      }
    } catch (e) { $('set-sharing').textContent = _t('Only you.'); }

    renderScopes(onTeam);
  })();
})();
