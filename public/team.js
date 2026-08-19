/*
 * hiccup — team.js
 * The team management page (public/team.html).
 *
 * GET /api/team drives everything: team:null shows a "create your team" card;
 * once on a team, an invite card (visible only when myCanManage) and a member
 * list with make-admin/revoke-admin, suspend/restore and remove actions —
 * each gated client-side on myCanManage plus the same self/owner/admin-vs-admin
 * rules the API enforces server-side (ARCHITECTURE.md "Wave 3 — Teams and
 * Projects" / lib/teams.js). The UI hiding a button is a convenience only;
 * the server is the actual enforcement.
 *
 * All DOM building is vanilla createElement; every string that came from the
 * server or a form field goes through textContent — never innerHTML.
 */
(function () {
  'use strict';
  // public/i18n.js publishes window._t from a blocking <head> script. The local
  // alias keeps this file working — in English — if that script is ever missing,
  // rather than throwing a ReferenceError out of every render.
  var _t = (window && window._t) || function (s) { return s; };

  // ---------------------------------------------------------------- helpers

  function $(id) { return document.getElementById(id); }

  /** Create an element with optional class and textContent (never markup). */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

  function isStr(v) { return typeof v === 'string' && v.length > 0; }

  function p2(n) { return (n < 10 ? '0' : '') + n; }

  function fmtDateTime(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) +
      ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
  }

  /**
   * Server error shape is {error} or {userMessage} depending on the route.
   *
   * Run through _t(): server.js sends English sentences with no `code` field, and
   * because the catalogue is keyed on the source text the sentence IS its own key,
   * so these localise with no server change and no error-code refactor. An
   * untranslated sentence falls back to the English the server sent.
   */
  function errMsg(payload, fallback) {
    return _t((payload && (payload.error || payload.userMessage)) || '') || fallback;
  }

  // ------------------------------------------------------------------ state

  var state = {
    me: null,
    team: null,
    members: [],
    pendingInvites: [],
    myRole: null,
    myCanManage: false,
    lastInvite: null,       // { token, inviteUrl, email } after a successful invite
    membersBusy: {}         // userId -> true while a PATCH/DELETE is in flight
  };

  // ------------------------------------------------------------------- boot

  async function boot() {
    try {
      var r = await fetch('/api/me');
      if (r.status === 401) { location.href = '/'; return; }
      if (!r.ok) throw new Error('me ' + r.status);
      var j = await r.json();
      state.me = j && j.user ? j.user : null;
    } catch (e) {
      location.href = '/';
      return;
    }
    if (state.me) {
      $('user-name').textContent = state.me.name || state.me.email || '';
    }
    wire();
    await loadTeam();
  }

  function wire() {
    $('logout-btn').addEventListener('click', async function () {
      try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
      location.href = '/';
    });

    $('team-retry').addEventListener('click', function () { loadTeam(); });

    $('team-create-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var name = ($('team-name-input').value || '').trim();
      if (!name) { setCreateError(_t('Enter a name for your team.')); return; }
      createTeam(name);
    });

    $('team-invite-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var email = ($('team-invite-email').value || '').trim();
      if (!email) { setInviteError(_t('Enter an email address.')); return; }
      createInvite(email);
    });

    $('team-invite-url').addEventListener('click', function () { $('team-invite-url').select(); });
    $('team-invite-copy').addEventListener('click', function () { copyInviteUrl(); });

    $('team-transfer-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      var sel = $('team-transfer-select');
      if (!sel.value) return;
      transferOwnership(sel.value, sel.options[sel.selectedIndex].textContent);
    });
    $('team-leave-btn').addEventListener('click', function () { leaveTeam(); });
    $('team-claim-btn').addEventListener('click', function () { claimOwnership(); });
  }

  // -------------------------------------------------------------- top state

  /** mode: 'loading' | 'error' | 'no-team' | 'team' */
  function setTopState(mode, message) {
    $('team-loading').hidden = mode !== 'loading';
    $('team-error').hidden = mode !== 'error';
    $('team-create').hidden = mode !== 'no-team';
    $('team-view').hidden = mode !== 'team';
    if (mode === 'error') $('team-error-text').textContent = message || _t('Something went wrong.');
    if (mode === 'team') renderTeamView();
  }

  async function loadTeam() {
    setTopState('loading');
    var res = null, payload = null;
    try {
      res = await fetch('/api/team');
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      setTopState('error', _t('Could not reach the server. Is hiccup still running?'));
      return;
    }
    if (!res.ok) {
      setTopState('error', errMsg(payload, _t('Could not load your team (status ') + res.status + ').'));
      return;
    }

    state.team = payload && payload.team ? payload.team : null;
    state.members = (payload && Array.isArray(payload.members)) ? payload.members : [];
    state.pendingInvites = (payload && Array.isArray(payload.pendingInvites)) ? payload.pendingInvites : [];
    state.myRole = (payload && payload.myRole) || null;
    state.myCanManage = !!(payload && payload.myCanManage);
    state.lastInvite = null; // a fresh load has no just-created invite to show

    setTopState(state.team ? 'team' : 'no-team');
  }

  // -------------------------------------------------------------- no-team

  function setCreateError(msg) { $('team-create-error').textContent = msg || ''; }

  async function createTeam(name) {
    setCreateError('');
    var btn = $('team-create-btn');
    btn.disabled = true;
    btn.textContent = _t('Creating…');
    var res = null, payload = null;
    try {
      res = await fetch('/api/team', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      btn.disabled = false;
      btn.textContent = _t('Create team');
      setCreateError(_t('Could not reach the server.'));
      return;
    }
    btn.disabled = false;
    btn.textContent = _t('Create team');
    if (!res.ok) {
      setCreateError(errMsg(payload, _t('Could not create the team (status ') + res.status + ').'));
      return;
    }
    $('team-name-input').value = '';
    await loadTeam();
  }

  // ----------------------------------------------------------- team view

  function renderTeamView() {
    renderSummary();
    renderInviteCard();
    renderPendingInvites();
    renderMembers();
    renderExitControls();
    loadRecovery();
  }

  // ------------------------------------------------- leaving / handing over

  /**
   * An owner sees "transfer ownership"; everyone else sees "leave". They are
   * mutually exclusive on purpose: an owner leaving without appointing anyone
   * is exactly how a team ends up stranded, so the UI never offers it.
   */
  function renderExitControls() {
    var isOwner = state.myRole === 'owner';
    var others = state.members.filter(function (m) {
      return m && isStr(m.userId) && m.role !== 'owner' && !m.suspended;
    });

    $('team-leave-wrap').hidden = isOwner;
    // A sole owner has nobody to transfer to; the account-deletion path
    // dissolves that team instead, so showing an empty picker would be a
    // dead end.
    $('team-transfer-wrap').hidden = !isOwner || !others.length;

    if (isOwner && others.length) {
      var sel = $('team-transfer-select');
      clear(sel);
      others.forEach(function (m) {
        var opt = document.createElement('option');
        opt.value = m.userId;
        opt.textContent = (m.email || m.userId) + (m.role === 'admin' ? ' (' + _t('admin') + ')' : '');
        sel.appendChild(opt);
      });
    }
  }

  async function transferOwnership(userId, label) {
    if (!window.confirm(_t('Make this person the owner of the team? You will become an admin.') + '\n\n' + label)) return;
    $('team-transfer-error').textContent = '';
    var btn = $('team-transfer-btn');
    btn.disabled = true;
    try {
      var res = await fetch('/api/team/transfer-ownership', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: userId })
      });
      if (res.status === 401) { location.href = '/'; return; }
      var payload = null;
      try { payload = await res.json(); } catch (e) { payload = null; }
      if (!res.ok) {
        $('team-transfer-error').textContent = errMsg(payload, _t('Could not transfer ownership.'));
        return;
      }
      await loadTeam();
    } catch (e) {
      $('team-transfer-error').textContent = _t('Could not reach the server. Is hiccup still running?');
    } finally {
      btn.disabled = false;
    }
  }

  async function leaveTeam() {
    if (!window.confirm(_t('Leave this team? You keep your account, but you lose access to the team\'s shared captures and guides.'))) return;
    $('team-leave-error').textContent = '';
    var btn = $('team-leave-btn');
    btn.disabled = true;
    try {
      var res = await fetch('/api/team/leave', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (res.status === 401) { location.href = '/'; return; }
      var payload = null;
      try { payload = await res.json(); } catch (e) { payload = null; }
      if (!res.ok) {
        $('team-leave-error').textContent = errMsg(payload, _t('Could not leave the team.'));
        return;
      }
      await loadTeam();
    } catch (e) {
      $('team-leave-error').textContent = _t('Could not reach the server. Is hiccup still running?');
    } finally {
      btn.disabled = false;
    }
  }

  // ------------------------------------------------------------- recovery

  /**
   * Ask the server whether this member may take the team over. Eligibility is
   * decided entirely server-side (lib/teams.js getRecoveryState) so the banner
   * and the enforced rule cannot drift apart; this only renders the answer.
   */
  async function loadRecovery() {
    var card = $('team-recovery');
    card.hidden = true;
    var payload = null;
    try {
      var res = await fetch('/api/team/recovery');
      if (!res.ok) return;
      payload = await res.json();
    } catch (e) { return; }          // never block the page on this
    if (!payload || !payload.claimable) return;

    var detail;
    if (payload.reason === 'orphaned') {
      detail = _t('The account that owned this team no longer exists, so nobody can manage members. You can take ownership.');
    } else {
      // ONE sentence with placeholders, not three _t() fragments glued together.
      // Concatenating fragments freezes English word order, and the owner and
      // the day count land in different positions in French and German -- the
      // translator has to be able to move them.
      detail = _t('The owner ({owner}) has not signed in for {days} days. You can take ownership so the team can be managed again.')
        .replace('{owner}', payload.ownerEmail || _t('unknown'))
        .replace('{days}', String(payload.daysSinceOwnerActive));
    }
    $('team-recovery-detail').textContent = detail;
    $('team-recovery-error').textContent = '';
    card.hidden = false;
  }

  async function claimOwnership() {
    if (!window.confirm(_t('Take ownership of this team? The current owner, if their account still exists, becomes an admin.'))) return;
    $('team-recovery-error').textContent = '';
    var btn = $('team-claim-btn');
    btn.disabled = true;
    try {
      var res = await fetch('/api/team/claim-ownership', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (res.status === 401) { location.href = '/'; return; }
      var payload = null;
      try { payload = await res.json(); } catch (e) { payload = null; }
      if (!res.ok) {
        $('team-recovery-error').textContent = errMsg(payload, _t('Could not take ownership of this team.'));
        return;
      }
      await loadTeam();
    } catch (e) {
      $('team-recovery-error').textContent = _t('Could not reach the server. Is hiccup still running?');
    } finally {
      btn.disabled = false;
    }
  }

  function renderSummary() {
    var host = $('team-summary');
    clear(host);
    var team = state.team || {};

    var head = el('div', 'team-summary-head');
    head.appendChild(el('h2', null, team.name || _t('Your team')));
    if (isStr(state.myRole)) head.appendChild(el('span', 'chip team-role-' + state.myRole, state.myRole));
    host.appendChild(head);

    var meLabel = (state.me && (state.me.name || state.me.email)) || 'you';
    host.appendChild(el('p', 'team-summary-me',
      _t('Signed in as ') + meLabel + _t('. Every member sees every capture and guide — there is ') +
      _t('no per-project permission.')));
  }

  // -------------------------------------------------------------- invite

  function setInviteError(msg) { $('team-invite-error').textContent = msg || ''; }

  function renderInviteCard() {
    var card = $('team-invite-card');
    card.hidden = !state.myCanManage;
    if (!state.myCanManage) return;

    if (state.lastInvite) {
      $('team-invite-result').hidden = false;
      $('team-invite-result-email').textContent = state.lastInvite.email || '';
      $('team-invite-url').value = state.lastInvite.inviteUrl || '';
    } else {
      $('team-invite-result').hidden = true;
      $('team-invite-url').value = '';
      $('team-invite-copy-msg').textContent = '';
    }
  }

  async function createInvite(email) {
    setInviteError('');
    var btn = $('team-invite-btn');
    btn.disabled = true;
    btn.textContent = _t('Creating…');
    var res = null, payload = null;
    try {
      res = await fetch('/api/team/invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      btn.disabled = false;
      btn.textContent = _t('Create invite link');
      setInviteError(_t('Could not reach the server.'));
      return;
    }
    btn.disabled = false;
    btn.textContent = _t('Create invite link');
    if (!res.ok) {
      setInviteError(errMsg(payload, _t('Could not create an invite (status ') + res.status + ').'));
      return;
    }
    state.lastInvite = payload || null;
    $('team-invite-email').value = '';
    renderInviteCard();
    // A new invite may also have changed the pending list — refresh from the
    // server rather than guessing the shape of a merged local list.
    reloadPendingInvitesOnly();
  }

  /** Re-fetch just to pick up the new pending invite, without disturbing the
   *  just-created inviteUrl box (a full loadTeam() would clear it). */
  async function reloadPendingInvitesOnly() {
    try {
      var r = await fetch('/api/team');
      if (!r.ok) return;
      var j = await r.json();
      if (j && Array.isArray(j.pendingInvites)) {
        state.pendingInvites = j.pendingInvites;
        renderPendingInvites();
      }
    } catch (e) { /* the invite link itself is already shown; this is best-effort */ }
  }

  function renderPendingInvites() {
    var host = $('team-pending-invites');
    clear(host);
    if (!state.myCanManage || !state.pendingInvites.length) return;

    var wrap = el('div', 'team-pending');
    wrap.appendChild(el('div', 'team-pending-title', _t('Pending invites')));
    for (var i = 0; i < state.pendingInvites.length; i++) {
      var inv = state.pendingInvites[i];
      if (!inv || typeof inv !== 'object' || !isStr(inv.email)) continue;
      var row = el('div', 'team-pending-row');
      row.appendChild(el('span', 'mono', inv.email));
      if (inv.expiresAt) row.appendChild(el('span', 'muted team-pending-exp', _t('expires ') + fmtDateTime(inv.expiresAt)));
      wrap.appendChild(row);
    }
    if (wrap.children.length > 1) host.appendChild(wrap);
  }

  function copyInviteUrl() {
    var input = $('team-invite-url');
    var msg = $('team-invite-copy-msg');
    var text = input.value || '';
    if (!text) return;
    copyText(text).then(function () {
      var btn = $('team-invite-copy');
      btn.textContent = _t('Copied');
      btn.classList.add('is-copied');
      msg.textContent = '';
      setTimeout(function () {
        btn.textContent = _t('Copy');
        btn.classList.remove('is-copied');
      }, 1600);
    }, function () {
      msg.textContent = _t('Copy blocked by the browser — the link is selected, press Ctrl/Cmd+C.');
      input.select();
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand && document.execCommand('copy');
        document.body.removeChild(ta);
        if (ok) resolve(); else reject(new Error('copy blocked'));
      } catch (e) { reject(e); }
    });
  }

  // -------------------------------------------------------------- members

  function setMembersMsg(text, isError) {
    var m = $('team-members-msg');
    m.textContent = text || '';
    m.classList.toggle('err', !!isError);
  }

  /**
   * Client-side mirror of lib/teams.js's server-enforced rules (see
   * ARCHITECTURE.md "Wave 3"). Hiding a button here is a convenience only —
   * the API re-checks every one of these on the actual PATCH/DELETE.
   *
   * One rule is stricter than the documented minimum on purpose: suspend is
   * never offered on your OWN row, even though the spec's literal text
   * ("not on the owner or, if acting is admin, another admin") does not
   * explicitly forbid self-suspend for an admin. Self-suspending would trip
   * the "suspension clears your session immediately" rule on your own next
   * request, which is not a useful action to expose as a one-click button.
   */
  function memberActions(member) {
    var out = { canRole: false, roleTo: null, canSuspend: false, suspendTo: false, canRemove: false };
    if (!state.myCanManage || !member || !isStr(member.userId)) return out;

    var myEmail = state.me && isStr(state.me.email) ? state.me.email.toLowerCase() : null;
    var self = !!myEmail && isStr(member.email) && member.email.toLowerCase() === myEmail;
    var isOwner = member.role === 'owner';
    var isAdmin = member.role === 'admin';
    var actingIsAdminOnly = state.myRole === 'admin'; // owner has the superset of admin's rights

    // setMemberRole: owner-only, never targets the owner's own row.
    if (state.myRole === 'owner' && !isOwner) {
      out.canRole = true;
      out.roleTo = isAdmin ? 'member' : 'admin';
    }

    // setMemberSuspended: owner/admin; never the owner; an admin cannot act
    // on another admin; never self (see doc comment above).
    if (!isOwner && !self && !(actingIsAdminOnly && isAdmin)) {
      out.canSuspend = true;
      out.suspendTo = !member.suspended;
    }

    // removeMember: owner/admin; never self; never the owner; an admin
    // cannot remove another admin.
    if (!self && !isOwner && !(actingIsAdminOnly && isAdmin)) {
      out.canRemove = true;
    }

    return out;
  }

  function renderMembers() {
    var host = $('team-members');
    clear(host);

    if (!state.members.length) {
      var empty = el('div', 'team-empty');
      empty.appendChild(el('p', null, _t('No members yet.')));
      host.appendChild(empty);
      return;
    }

    var table = el('table', 'table-dense team-table');
    var thead = el('thead');
    var hrow = el('tr');
    ['Name', _t('Email'), _t('Role'), _t('Status'), _t('Actions')].forEach(function (h) {
      hrow.appendChild(el('th', null, h));
    });
    thead.appendChild(hrow);
    table.appendChild(thead);

    var tbody = el('tbody');
    var myEmail = state.me && isStr(state.me.email) ? state.me.email.toLowerCase() : null;

    for (var i = 0; i < state.members.length; i++) {
      (function (member) {
        if (!member || typeof member !== 'object' || !isStr(member.userId)) return;
        var self = !!myEmail && isStr(member.email) && member.email.toLowerCase() === myEmail;
        var row = el('tr');

        var tdName = el('td');
        tdName.appendChild(document.createTextNode(member.name || member.email || member.userId));
        if (self) tdName.appendChild(el('span', 'team-you-tag', _t('(you)')));
        row.appendChild(tdName);

        row.appendChild(el('td', 'mono', member.email || ''));

        var role = isStr(member.role) ? member.role : 'member';
        row.appendChild((function () {
          var td = el('td');
          td.appendChild(el('span', 'chip team-role-' + role, role));
          return td;
        })());

        var tdStatus = el('td');
        if (member.suspended) tdStatus.appendChild(el('span', 'chip sev-warn', 'suspended'));
        row.appendChild(tdStatus);

        var tdActions = el('td');
        var actions = el('div', 'team-actions');
        var perms = memberActions(member);
        var name = member.name || member.email || _t('this member');
        var busy = !!state.membersBusy[member.userId];

        if (perms.canRole) {
          var roleBtn = el('button', 'btn', perms.roleTo === 'admin' ? _t('Make admin') : _t('Revoke admin'));
          roleBtn.type = 'button';
          roleBtn.disabled = busy;
          roleBtn.addEventListener('click', function () {
            patchMember(member.userId, { role: perms.roleTo }, _t('Updated ') + name + '.');
          });
          actions.appendChild(roleBtn);
        }

        if (perms.canSuspend) {
          var susBtn = el('button', 'btn', perms.suspendTo ? _t('Suspend') : _t('Restore'));
          susBtn.type = 'button';
          susBtn.disabled = busy;
          susBtn.addEventListener('click', function () {
            patchMember(member.userId, { suspended: perms.suspendTo },
              (perms.suspendTo ? _t('Suspended ') : _t('Restored ')) + name + '.');
          });
          actions.appendChild(susBtn);
        }

        if (perms.canRemove) {
          var rmBtn = el('button', 'btn', _t('Remove'));
          rmBtn.type = 'button';
          rmBtn.disabled = busy;
          rmBtn.addEventListener('click', function () { removeMember(member.userId, name); });
          actions.appendChild(rmBtn);
        }

        if (!actions.firstChild && !self) actions.appendChild(el('span', 'muted', '—'));
        tdActions.appendChild(actions);
        row.appendChild(tdActions);

        tbody.appendChild(row);
      })(state.members[i]);
    }
    table.appendChild(tbody);
    host.appendChild(table);
  }

  async function patchMember(userId, body, successMsg) {
    if (state.membersBusy[userId]) return;
    state.membersBusy[userId] = true;
    setMembersMsg(_t('Updating…'));
    renderMembers();

    var res = null, payload = null;
    try {
      res = await fetch('/api/team/members/' + encodeURIComponent(userId), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.membersBusy[userId] = false;
      setMembersMsg(_t('Could not reach the server.'), true);
      renderMembers();
      return;
    }
    state.membersBusy[userId] = false;
    if (!res.ok) {
      setMembersMsg(errMsg(payload, _t('That action failed (status ') + res.status + ').'), true);
      renderMembers();
      return;
    }
    setMembersMsg(successMsg || _t('Updated.'));
    await loadTeam();
  }

  async function removeMember(userId, name) {
    if (state.membersBusy[userId]) return;
    if (!confirm(_t('Remove ') + name + _t(' from the team? They will lose access to every ') +
      _t('shared capture and guide.'))) return;

    state.membersBusy[userId] = true;
    setMembersMsg(_t('Removing…'));
    renderMembers();

    var res = null, payload = null;
    try {
      res = await fetch('/api/team/members/' + encodeURIComponent(userId), { method: 'DELETE' });
      if (res.status === 401) { location.href = '/'; return; }
      try { payload = await res.json(); } catch (e) { payload = null; }
    } catch (e) {
      state.membersBusy[userId] = false;
      setMembersMsg(_t('Could not reach the server.'), true);
      renderMembers();
      return;
    }
    state.membersBusy[userId] = false;
    if (!res.ok) {
      setMembersMsg(errMsg(payload, _t('Remove failed (status ') + res.status + ').'), true);
      renderMembers();
      return;
    }
    setMembersMsg(_t('Removed ') + name + '.');
    await loadTeam();
  }

  // ------------------------------------------------------------------- init

  boot();
})();
