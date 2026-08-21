/* hiccup - admin-status.js (lifted from admin-status.html so the site can run under a CSP with no 'unsafe-inline'). */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function card(title, rows) {
    var c = el('section', 'card st-card');
    c.appendChild(el('h2', null, title));
    var dl = el('dl');
    rows.forEach(function (r) {
      if (r[1] == null) return;
      var row = el('div', 'st-row');
      row.appendChild(el('dt', null, r[0]));
      var dd = el('dd', r[2] || null, String(r[1]));
      row.appendChild(dd);
      dl.appendChild(row);
    });
    c.appendChild(dl);
    return c;
  }

  function dur(s) {
    if (s == null) return null;
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return d + 'd ' + h + 'h';
    if (h) return h + 'h ' + m + 'm';
    return m + 'm';
  }

  /**
   * Big-number tiles. KPIs get more weight than the process/LLM cards below
   * because they answer a different question: those say "is it running", these
   * say "is it working".
   */
  function kpiStrip(tiles) {
    var wrap = el('div', 'st-kpis');
    tiles.forEach(function (t) {
      var tile = el('div', 'st-kpi' + (t.tone ? ' ' + t.tone : ''));
      tile.appendChild(el('div', 'st-kpi-n', t.value == null ? '—' : String(t.value)));
      tile.appendChild(el('div', 'st-kpi-l', t.label));
      if (t.sub) tile.appendChild(el('div', 'st-kpi-s', t.sub));
      wrap.appendChild(tile);
    });
    return wrap;
  }

  function renderKpis(host, k) {
    if (!k) return;
    if (k.error) {
      host.appendChild(card('KPIs', [['error', k.error, 'st-bad']]));
      return;
    }
    var tr = k.traffic || {};
    var u = k.users || {}, act = k.activation || {}, paid = k.paid || {};

    var head = el('h2', 'st-kpi-head', 'Last 7 days');
    host.appendChild(head);

    host.appendChild(kpiStrip([
      { value: tr.human, label: 'human requests',
        sub: tr.botShare == null ? null : tr.botShare + '% of all traffic was bots' },
      { value: tr.pageViews, label: 'page views',
        sub: tr.cssRatio == null ? 'no data' : tr.cssRatio + '% also fetched CSS',
        tone: tr.cssRatio != null && tr.cssRatio < 40 ? 'st-kpi-warn' : null },
      { value: tr.networks, label: 'distinct networks', sub: 'non-bot, /24 or /48' },
      { value: u.signups7d, label: 'signups', sub: u.total + ' accounts in total' },
      { value: act.rate == null ? null : act.rate + '%', label: 'activation',
        sub: act.uploaded + ' of ' + u.total + ' ever uploaded a trace',
        tone: act.rate != null && act.rate < 40 ? 'st-kpi-warn' : null },
      { value: paid.accounts, label: 'paid accounts',
        sub: paid.conversionRate == null ? null : paid.conversionRate + '% of signups' },
    ]));

    // The honest caveats, shown rather than buried.
    (k.signals || []).forEach(function (msg) {
      host.appendChild(el('p', 'st-kpi-signal', msg));
    });

    host.appendChild(card('Traffic (7 days)', [
      ['requests', tr.requests],
      ['human', tr.human],
      ['automated', tr.bot == null ? null : tr.bot + (tr.botShare != null ? ' (' + tr.botShare + '%)' : '')],
      ['vulnerability probes', tr.probes],
      ['page views', tr.pageViews],
      ['stylesheet fetches', tr.cssHits],
      ['CSS ratio', tr.cssRatio == null ? null : tr.cssRatio + '%',
        tr.cssRatio != null && tr.cssRatio < 40 ? 'st-bad' : 'st-ok'],
      ['networks', tr.networks == null ? null : tr.networks + ' human / ' + tr.botNetworks + ' bot'],
      ['pre-v0.3.2 lines skipped', tr.legacyLines || 0]
    ]));

    var top = (tr.topPaths || []).slice(0, 6).map(function (p) {
      return [p.path, p.views];
    });
    if (top.length) host.appendChild(card('Most-viewed pages (non-bot)', top));

    host.appendChild(card('Product', [
      ['accounts', u.total],
      ['signups, 7d', u.signups7d],
      ['signups, 30d', u.signups30d],
      ['signed in, 7d', u.activeLast7d],
      ['uploaded a trace', act.uploaded == null ? null : act.uploaded + (act.rate != null ? ' (' + act.rate + '%)' : '')],
      ['captures, 7d', k.captures && k.captures.last7d],
      ['captures, total', k.captures && k.captures.total],
      ['teams', k.teams && k.teams.total]
    ]));
  }

  function render(s) {
    var host = $('st-body');
    host.textContent = '';

    $('st-summary').textContent = 'hiccup v' + s.version + ' · up ' + dur(s.uptimeSeconds) +
      ' · signed in as ' + (s.you && s.you.email);

    renderKpis(host, s.kpis);

    host.appendChild(card('Process', [
      ['version', s.version],
      ['node', s.node],
      ['platform', s.platform],
      ['pid', s.pid],
      ['uptime', dur(s.uptimeSeconds)],
      ['memory', s.memoryMb + ' MB'],
      ['analysis engine', s.engine && s.engine.analysis ? 'loaded' : 'MISSING',
        s.engine && s.engine.analysis ? 'st-ok' : 'st-bad']
    ]));

    var llm = s.llm || {};
    host.appendChild(card('LLM', [
      ['state', llm.state || llm.status || 'unknown'],
      ['model', llm.model || null],
      ['reachable', llm.ok === undefined ? null : (llm.ok ? 'yes' : 'no'),
        llm.ok ? 'st-ok' : 'st-bad'],
      ['note', llm.note || llm.detail || null]
    ]));

    host.appendChild(card('Data', [
      ['users', s.users],
      ['capture accounts', s.captures && s.captures.accounts],
      ['captures', s.captures && s.captures.total],
      ['disk used', s.disk ? (s.disk.mb + ' MB') : null],
      ['files', s.disk && s.disk.files],
      ['data dir', s.dataDir]
    ]));

    var f = s.feedback || {};
    host.appendChild(card('Feedback', [
      ['total', f.total],
      ['unread', f.unread, f.unread ? 'st-warn' : null],
      ['last 7 days', f.last7d],
      ['digest due now', f.dueNow === undefined ? null : (f.dueNow ? 'yes' : 'no')],
      ['digest last sent', (f.digest && f.digest.lastSentWeek) || 'never'],
      ['mail', s.mail && s.mail.configured ? 'configured' : 'NOT configured',
        s.mail && s.mail.configured ? 'st-ok' : 'st-warn']
    ]));

    var c = s.config || {};
    host.appendChild(card('Config', [
      ['baseUrl', c.baseUrl],
      ['listen', c.host + ':' + c.port],
      ['max upload', c.maxUploadMb + ' MB'],
      ['google sign-in', c.googleSignIn,
        c.googleSignIn === 'configured' ? 'st-ok' : null],
      ['digest recipient', c.digestRecipient || 'none', c.digestRecipient ? null : 'st-warn'],
      ['admins', (c.adminEmails || []).join(', ') || 'first user only']
    ]));

    host.appendChild(card('Models (preferred order)',
      (c.preferredModels || []).map(function (m, i) { return [String(i + 1), m]; })));
  }

  async function load() {
    $('st-msg').textContent = '';
    try {
      var r = await fetch('/api/admin/status', { cache: 'no-store' });
      if (r.status === 401) { location = '/'; return; }
      if (r.status === 403) {
        $('st-summary').textContent = 'You are not a site admin.';
        $('st-msg').textContent = 'This page is only useful to the site administrator.';
        return;
      }
      if (!r.ok) {
        $('st-msg').textContent = 'could not load status (' + r.status + ')';
        $('st-msg').className = 'feedback-msg is-err';
        return;
      }
      render(await r.json());
      loadUsers();
    } catch (e) {
      $('st-msg').textContent = 'could not reach the server';
      $('st-msg').className = 'feedback-msg is-err';
    }
  }

  // ------------------------------------------------------------------ users

  function usersMsg(text, isErr) {
    var m = $('st-users-msg');
    m.textContent = text || '';
    m.classList.toggle('err', !!isErr);
  }

  function fmtDate(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' +
      String(d.getDate()).padStart(2, '0');
  }

  function renderUsers(list) {
    var host = $('st-users');
    host.textContent = '';
    if (!list.length) {
      host.appendChild(el('p', 'muted', 'No user accounts yet.'));
      return;
    }

    var table = el('table', 'table-dense st-users-table');
    var thead = el('thead');
    var hrow = el('tr');
    ['Email', 'Name', 'Team role', 'Created', 'Last login', 'Plan', 'Superuser', ''].forEach(function (h) {
      hrow.appendChild(el('th', null, h));
    });
    thead.appendChild(hrow);
    table.appendChild(thead);

    var tbody = el('tbody');
    list.forEach(function (u) {
      var row = el('tr');

      var tdEmail = el('td', null, u.email);
      if (u.isYou) tdEmail.appendChild(el('span', 'st-you', '(you)'));
      row.appendChild(tdEmail);

      row.appendChild(el('td', null, u.name || '—'));
      row.appendChild(el('td', 'muted', (u.team && u.team.role) || '—'));
      row.appendChild(el('td', 'muted', fmtDate(u.createdAt)));
      row.appendChild(el('td', 'muted', fmtDate(u.lastLoginAt)));
      row.appendChild(el('td', u.plan === 'paid' ? 'st-superuser-yes' : 'st-superuser-no',
        u.plan === 'paid' ? 'paid' : 'free'));
      row.appendChild(el('td', u.isSuperuser ? 'st-superuser-yes' : 'st-superuser-no',
        u.isSuperuser ? 'yes' : 'no'));

      var tdAction = el('td');
      var planBtn = el('button', 'btn', u.plan === 'paid' ? 'Set free' : 'Set paid');
      planBtn.type = 'button';
      planBtn.addEventListener('click', function () { togglePlan(u, planBtn); });
      tdAction.appendChild(planBtn);

      var suBtn = el('button', 'btn', u.isSuperuser ? 'Revoke superuser' : 'Make superuser');
      suBtn.type = 'button';
      suBtn.addEventListener('click', function () { toggleSuperuser(u, suBtn); });
      tdAction.appendChild(suBtn);
      row.appendChild(tdAction);

      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    host.appendChild(table);
  }

  async function togglePlan(u, btn) {
    var wantPlan = u.plan === 'paid' ? 'free' : 'paid';
    var question = wantPlan === 'paid'
      ? ('Mark "' + u.email + '" as paid? They will be able to create or join a team.')
      : ('Set "' + u.email + '" back to free? If they own a team, the team itself is untouched — ' +
         'this only blocks creating or joining a NEW one.');
    if (!confirm(question)) return;

    btn.disabled = true;
    usersMsg('Saving…');
    try {
      var r = await fetch('/api/admin/users/' + encodeURIComponent(u.id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: wantPlan })
      });
      var d = null;
      try { d = await r.json(); } catch (e2) { /* non-json */ }
      if (!r.ok) {
        usersMsg((d && d.error) || ('request failed (' + r.status + ')'), true);
        btn.disabled = false;
        return;
      }
      usersMsg('"' + u.email + '" is now on the ' + wantPlan + ' plan.');
      loadUsers();
    } catch (e) {
      usersMsg('could not reach the server', true);
      btn.disabled = false;
    }
  }

  async function toggleSuperuser(u, btn) {
    var wantSuperuser = !u.isSuperuser;
    var question = wantSuperuser
      ? ('Make "' + u.email + '" a superuser? They will be able to see this page, restart ' +
         'the service, and manage other users.')
      : ('Revoke superuser access for "' + u.email + '"?');
    if (!confirm(question)) return;

    btn.disabled = true;
    usersMsg(wantSuperuser ? 'Granting…' : 'Revoking…');
    try {
      var r = await fetch('/api/admin/users/' + encodeURIComponent(u.id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ superuser: wantSuperuser })
      });
      var d = null;
      try { d = await r.json(); } catch (e2) { /* non-json */ }
      if (!r.ok) {
        usersMsg((d && d.error) || ('request failed (' + r.status + ')'), true);
        btn.disabled = false;
        return;
      }
      usersMsg(wantSuperuser
        ? ('"' + u.email + '" is now a superuser.')
        : ('Superuser access revoked for "' + u.email + '".'));
      loadUsers();
    } catch (e) {
      usersMsg('could not reach the server', true);
      btn.disabled = false;
    }
  }

  async function loadUsers() {
    try {
      var r = await fetch('/api/admin/users', { cache: 'no-store' });
      if (r.status === 401) { location = '/'; return; }
      if (r.status === 403) { return; } // not a site admin — the main card already said so
      if (!r.ok) { usersMsg('could not load users (' + r.status + ')', true); return; }
      var d = await r.json();
      renderUsers(Array.isArray(d.users) ? d.users : []);
    } catch (e) {
      usersMsg('could not reach the server', true);
    }
  }

  // Restart is destructive-ish and easy to hit by accident next to refresh,
  // so it confirms first and then polls until the new process answers —
  // otherwise the page just sits on a dead socket looking broken.
  $('st-restart').addEventListener('click', async function () {
    if (!confirm(_t('Restart the hiccup service now?\n\nIn-flight requests are dropped and the app is unreachable for a few seconds.'))) return;
    $('st-restart').disabled = true;
    say('asking the server to restart…');
    try {
      var r = await fetch('/api/admin/server/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'restart' })
      });
      var d = await r.json();
      if (!r.ok) {
        say(d.error || ('restart refused (' + r.status + ')'), true);
        $('st-restart').disabled = false;
        return;
      }
      say(d.msg || "restarting…");
      waitForServer(0);
    } catch (e) {
      say('could not reach the server', true);
      $('st-restart').disabled = false;
    }
  });

  /** Poll /api/status until the relaunched process answers, then reload. */
  function waitForServer(attempt) {
    if (attempt > 30) {
      say('the server has not come back after ~30s — check the service', true);
      $('st-restart').disabled = false;
      return;
    }
    setTimeout(function () {
      fetch('/api/status', { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (s) {
          // A LOW uptime is the proof it actually restarted; the old process
          // answering on its way out would report a high one.
          if (s && typeof s.uptime === "number" && s.uptime < 60) { location.reload(); return; }
          waitForServer(attempt + 1);
        })
        .catch(function () { waitForServer(attempt + 1); });
    }, 1000);
  }
  $('st-refresh').addEventListener('click', load);
  load();
})();
