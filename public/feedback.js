/* feedback.js — the in-app feedback widget.
 *
 * Loaded by app.html, hmr.html, kb.html and team.html. Self-contained: it
 * builds its own modal, so a page only needs the <script> tag and (optionally)
 * a #feedback-open button in its topbar — if that button is absent the widget
 * creates its own floating launcher.
 *
 * PRIVACY — the reason this file is written the way it is. See ARCHITECTURE.md
 * "Wave 6". collectContext() gathers STRUCTURAL facts only: counts, scope ids,
 * SIP method/status verbs, protocol lamp names, advice rule ids, viewport.
 * It never reads message bodies, headers, phone numbers, IPs, the capture
 * filename or the search box. The modal shows the user the exact JSON that
 * will be posted, and they can send without it. lib/feedback.js re-sanitises
 * server-side regardless, so this file is a courtesy, not the enforcement.
 */
(function () {
  'use strict';

  var KINDS = [
    { key: 'bug', label: 'Something is broken' },
    { key: 'confusing', label: 'Something is confusing' },
    { key: 'idea', label: 'I have an idea' },
    { key: 'praise', label: 'Something works well' },
    { key: 'other', label: 'Other' }
  ];

  var appVersion = '';
  var els = {};

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  // ------------------------------------------------------------- context

  /**
   * Structural context only. Every value here is either hiccup's own
   * vocabulary (rule ids, lamp keys, internal call/leg ids) or a count.
   * Nothing derived from message content is read.
   */
  function collectContext() {
    var ctx = {
      page: location.pathname,
      appVersion: appVersion,
      theme: document.documentElement.getAttribute('data-theme') ||
        ((window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light'),
      userAgent: navigator.userAgent,
      viewport: { w: window.innerWidth, h: window.innerHeight }
    };

    // The workbench exposes a small read-only probe for exactly this purpose.
    // Other pages have no capture, so they simply contribute nothing here.
    var probe = window.hiccupContextProbe;
    if (typeof probe === 'function') {
      try {
        var extra = probe();
        if (extra && typeof extra === 'object') {
          for (var k in extra) {
            if (Object.prototype.hasOwnProperty.call(extra, k)) ctx[k] = extra[k];
          }
        }
      } catch (e) { /* a broken probe must never block feedback */ }
    }
    return ctx;
  }

  // --------------------------------------------------------------- modal

  function buildModal() {
    var overlay = el('div', 'overlay');
    overlay.id = 'feedback-modal';
    overlay.hidden = true;

    var backdrop = el('div', 'overlay-backdrop');
    backdrop.id = 'feedback-backdrop';
    overlay.appendChild(backdrop);

    var panel = el('div', 'overlay-panel feedback-panel');
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-labelledby', 'feedback-title');

    var head = el('div', 'feedback-head');
    var h2 = el('h2', null, 'Send feedback');
    h2.id = 'feedback-title';
    head.appendChild(h2);
    var closeBtn = el('button', 'btn icon-btn', '×');
    closeBtn.type = 'button';
    closeBtn.id = 'feedback-close';
    closeBtn.setAttribute('aria-label', 'close');
    head.appendChild(closeBtn);
    panel.appendChild(head);

    var form = el('form', 'feedback-form');
    form.id = 'feedback-form';

    var kindLabel = el('label', 'feedback-label', 'What kind of feedback?');
    kindLabel.setAttribute('for', 'feedback-kind');
    form.appendChild(kindLabel);
    var kind = el('select', 'input');
    kind.id = 'feedback-kind';
    for (var i = 0; i < KINDS.length; i++) {
      var opt = el('option', null, KINDS[i].label);
      opt.value = KINDS[i].key;
      kind.appendChild(opt);
    }
    form.appendChild(kind);

    var cLabel = el('label', 'feedback-label', 'Your comment');
    cLabel.setAttribute('for', 'feedback-comment');
    form.appendChild(cLabel);
    var comment = el('textarea', 'input feedback-comment');
    comment.id = 'feedback-comment';
    comment.rows = 5;
    comment.maxLength = 4000;
    comment.required = true;
    comment.placeholder = 'What happened, or what would you like to see?';
    form.appendChild(comment);

    var rLabel = el('label', 'feedback-label', 'Rate this page (optional)');
    rLabel.setAttribute('for', 'feedback-rating');
    form.appendChild(rLabel);
    var rating = el('select', 'input');
    rating.id = 'feedback-rating';
    var none = el('option', null, 'no rating');
    none.value = '';
    rating.appendChild(none);
    for (var r = 1; r <= 5; r++) {
      var ro = el('option', null, r + ' / 5');
      ro.value = String(r);
      rating.appendChild(ro);
    }
    form.appendChild(rating);

    // --- the consent block: what will be sent, verbatim ---
    var ctxWrap = el('div', 'feedback-context');

    var incLabel = el('label', 'feedback-check');
    var inc = el('input');
    inc.type = 'checkbox';
    inc.id = 'feedback-include-context';
    inc.checked = true;
    incLabel.appendChild(inc);
    incLabel.appendChild(el('span', null,
      ' Include what I was looking at (helps a lot with reproducing bugs)'));
    ctxWrap.appendChild(incLabel);

    var toggle = el('button', 'feedback-context-toggle');
    toggle.type = 'button';
    toggle.id = 'feedback-context-toggle';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.textContent = 'show exactly what will be sent';
    ctxWrap.appendChild(toggle);

    var pre = el('pre', 'feedback-context-pre mono');
    pre.id = 'feedback-context-pre';
    pre.hidden = true;
    ctxWrap.appendChild(pre);

    ctxWrap.appendChild(el('p', 'feedback-note',
      'Never included: your capture file, message contents, phone numbers, ' +
      'IP addresses, the capture filename, or anything typed in the search box.'));

    form.appendChild(ctxWrap);

    var msg = el('p', 'feedback-msg');
    msg.id = 'feedback-msg';
    msg.setAttribute('role', 'status');
    msg.setAttribute('aria-live', 'polite');
    form.appendChild(msg);

    var foot = el('div', 'feedback-foot');
    var cancel = el('button', 'btn', 'Cancel');
    cancel.type = 'button';
    cancel.id = 'feedback-cancel';
    foot.appendChild(cancel);
    var submit = el('button', 'btn btn-primary', 'Send feedback');
    submit.type = 'submit';
    submit.id = 'feedback-submit';
    foot.appendChild(submit);
    form.appendChild(foot);

    panel.appendChild(form);
    overlay.appendChild(panel);
    document.body.appendChild(overlay);

    els = {
      overlay: overlay, panel: panel, form: form, kind: kind, comment: comment,
      rating: rating, include: inc, toggle: toggle, pre: pre, msg: msg,
      submit: submit, close: closeBtn, cancel: cancel, backdrop: backdrop
    };
    return overlay;
  }

  // ------------------------------------------------------- open / close

  var lastFocused = null;
  var currentContext = null;

  function open() {
    lastFocused = document.activeElement;
    currentContext = collectContext();
    els.pre.textContent = JSON.stringify(currentContext, null, 2);
    els.msg.textContent = '';
    els.msg.className = 'feedback-msg';
    els.submit.disabled = false;
    els.overlay.hidden = false;
    els.comment.focus();
    document.addEventListener('keydown', onKeydown, true);
  }

  function close() {
    els.overlay.hidden = true;
    document.removeEventListener('keydown', onKeydown, true);
    if (lastFocused && typeof lastFocused.focus === 'function') lastFocused.focus();
  }

  function onKeydown(ev) {
    if (els.overlay.hidden) return;
    if (ev.key === 'Escape') { ev.preventDefault(); close(); return; }
    if (ev.key !== 'Tab') return;
    // Focus trap: this dialog genuinely covers the page, so focus must not
    // wander behind it. Same approach as the Wave-5A overlays.
    var f = els.panel.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])');
    if (!f.length) return;
    var first = f[0];
    var last = f[f.length - 1];
    if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
  }

  // -------------------------------------------------------------- submit

  async function submit(ev) {
    ev.preventDefault();
    var comment = els.comment.value.trim();
    if (!comment) {
      els.msg.textContent = 'Please write a comment first.';
      els.msg.className = 'feedback-msg is-err';
      els.comment.focus();
      return;
    }
    els.submit.disabled = true;
    els.msg.textContent = 'Sending…';
    els.msg.className = 'feedback-msg';

    var payload = {
      kind: els.kind.value,
      comment: comment,
      rating: els.rating.value ? Number(els.rating.value) : null,
      context: els.include.checked ? currentContext : null
    };

    try {
      var r = await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      var data = {};
      try { data = await r.json(); } catch (e) { /* non-JSON body */ }
      if (r.ok) {
        els.msg.textContent = 'Thank you — that has been sent.';
        els.msg.className = 'feedback-msg is-ok';
        els.comment.value = '';
        setTimeout(close, 1200);
        return;
      }
      els.msg.textContent = (data && data.error) || ('Could not send (' + r.status + ')');
      els.msg.className = 'feedback-msg is-err';
    } catch (e) {
      els.msg.textContent = 'Could not reach the server.';
      els.msg.className = 'feedback-msg is-err';
    }
    els.submit.disabled = false;
  }

  // ---------------------------------------------------------------- boot

  function makeLauncher() {
    var existing = document.getElementById('feedback-open');
    if (existing) return existing;
    var b = el('button', 'btn feedback-launcher', 'feedback');
    b.type = 'button';
    b.id = 'feedback-open';
    b.title = 'Send feedback about hiccup';
    document.body.appendChild(b);
    return b;
  }

  function boot() {
    buildModal();
    var launcher = makeLauncher();
    launcher.addEventListener('click', open);
    els.close.addEventListener('click', close);
    els.cancel.addEventListener('click', close);
    els.backdrop.addEventListener('click', close);
    els.form.addEventListener('submit', submit);
    els.toggle.addEventListener('click', function () {
      var showing = !els.pre.hidden;
      els.pre.hidden = showing;
      els.toggle.setAttribute('aria-expanded', showing ? 'false' : 'true');
      els.toggle.textContent = showing ? 'show exactly what will be sent' : 'hide';
    });
    els.include.addEventListener('change', function () {
      els.pre.style.opacity = els.include.checked ? '' : '0.45';
    });

    fetch('/api/status')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { if (s && s.version) appVersion = String(s.version); })
      .catch(function () { /* version is a nicety, not a requirement */ });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
