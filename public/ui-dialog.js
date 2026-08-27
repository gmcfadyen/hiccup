/* hiccup - ui-dialog.js
 *
 * The focus trap (lifted out of app.js, where it was workbench-only) plus the
 * in-page confirmation it exists to serve. Loaded by every signed-in page.
 *
 * WHY THIS FILE EXISTS
 *
 * Nine consequential actions across /team, /kb and /admin/status were gated by
 * window.confirm(): transfer ownership, leave team, enforce SSO, remove a
 * member, delete a guide, change a plan, grant superuser. A browser told to
 * block dialogs for an origin returns false from confirm() WITHOUT showing
 * anything, which is indistinguishable from the user clicking Cancel — the
 * action silently does not happen and the button looks dead. That is not a
 * theory: it is exactly what made the /admin/status restart button do nothing
 * (see the note above the restart handler in admin-status.js).
 *
 * Fail-safe, but a control the browser can quietly disable is not a control.
 * So: an in-page dialog that cannot be suppressed, and — because a real modal
 * needs real focus handling — the trap comes with it rather than being
 * reimplemented per page.
 *
 * The trap code is moved verbatim from app.js (Wave 5A), keeping its API so
 * the workbench's existing surfaces (command palette, shortcuts overlay,
 * projects panel, chat drawer) behave exactly as before. app.js now delegates
 * here instead of carrying its own copy.
 *
 * Key handling: app.js owns exactly ONE document keydown listener on purpose,
 * so it calls handleTrapKey() from inside its own handler and sets
 * hostHandlesKeys = true. Pages with no keyboard layer get a listener
 * installed here while a trap is active, and removed when the stack empties.
 */
(function () {
  'use strict';

  var FOCUSABLE_SEL = 'a[href], button:not([disabled]), input:not([disabled]), ' +
    'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  /** Active traps, innermost last. Only the top of the stack handles keys. */
  var trapStack = [];

  function topTrap() { return trapStack.length ? trapStack[trapStack.length - 1] : null; }

  function isRendered(node) {
    if (!node) return false;
    if (node.offsetWidth || node.offsetHeight) return true;
    return !!(node.getClientRects && node.getClientRects().length);
  }

  /** Tabbable descendants of `container`, in DOM order, visible ones only. */
  function focusablesIn(container) {
    var out = [];
    if (!container || !container.querySelectorAll) return out;
    var nodes = container.querySelectorAll(FOCUSABLE_SEL);
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].hasAttribute('hidden')) continue;
      if (!isRendered(nodes[i])) continue;
      out.push(nodes[i]);
    }
    return out;
  }

  function focusQuietly(node) {
    if (!node || !node.focus) return;
    try { node.focus({ preventScroll: true }); } catch (e) { node.focus(); }
  }

  /**
   * The one focus trap, shared by every modal surface in the app.
   * (Moved from app.js; see that file's Wave 5A section for the original
   * design notes. API unchanged.)
   *
   * @param {HTMLElement} container the element focus may not leave
   * @param {{onEscape?:function, onOutsideClick?:function, dialog?:boolean}} opts
   * @returns {{activate:function, release:function, active:function,
   *            container:HTMLElement}}
   */
  function createFocusTrap(container, opts) {
    var o = opts || {};
    var trap = {
      container: container,
      returnTo: null,
      isActive: false,
      hadRole: null,
      hadModal: null,
      onDown: null
    };

    trap.active = function () { return trap.isActive; };
    trap.escape = function () { if (typeof o.onEscape === 'function') o.onEscape(); };

    /** True for the element the surface was opened from — never an outside click. */
    trap.isTrigger = function (node) {
      var rt = trap.returnTo;
      if (!rt || !node) return false;
      if (rt === document.body || rt === document.documentElement) return false;
      return rt === node || (rt.contains && rt.contains(node));
    };

    trap.activate = function (arg) {
      if (trap.isActive || !container) return;
      var a = arg || {};
      trap.returnTo = a.returnTo || document.activeElement || null;
      trap.isActive = true;
      trapStack.push(trap);
      ensureKeyListener();

      if (o.dialog) {
        trap.hadRole = container.getAttribute('role');
        trap.hadModal = container.getAttribute('aria-modal');
        container.setAttribute('role', 'dialog');
        container.setAttribute('aria-modal', 'true');
      }

      if (typeof o.onOutsideClick === 'function') {
        trap.onDown = function (ev) {
          if (topTrap() !== trap) return;
          var t = ev.target;
          if (container.contains && container.contains(t)) return;
          if (trap.isTrigger(t)) return;   // else the trigger's click re-opens it
          o.onOutsideClick();
        };
        document.addEventListener('pointerdown', trap.onDown, true);
      }

      var first = a.initialFocus || focusablesIn(container)[0] || container;
      if (first === container && !container.hasAttribute('tabindex')) {
        container.setAttribute('tabindex', '-1');
      }
      focusQuietly(first);
    };

    /**
     * @param {{restoreFocus?:boolean}} [arg] restoreFocus defaults to true; pass
     *   false when the surface is staying open and merely stopped being modal.
     */
    trap.release = function (arg) {
      if (!trap.isActive) return;
      var a = arg || {};
      trap.isActive = false;
      for (var i = trapStack.length - 1; i >= 0; i--) {
        if (trapStack[i] === trap) { trapStack.splice(i, 1); break; }
      }
      if (trap.onDown) {
        document.removeEventListener('pointerdown', trap.onDown, true);
        trap.onDown = null;
      }
      if (o.dialog && container) {
        if (trap.hadRole == null) container.removeAttribute('role');
        else container.setAttribute('role', trap.hadRole);
        if (trap.hadModal == null) container.removeAttribute('aria-modal');
        else container.setAttribute('aria-modal', trap.hadModal);
      }
      releaseKeyListener();
      var back = trap.returnTo;
      trap.returnTo = null;
      if (a.restoreFocus === false) return;
      if (back && back.focus && document.contains(back) && isRendered(back)) focusQuietly(back);
    };

    return trap;
  }

  /** Tab / Shift+Tab, confined to the top trap's container. */
  function trapTab(trap, ev) {
    var items = focusablesIn(trap.container);
    ev.preventDefault();
    if (!items.length) { focusQuietly(trap.container); return; }
    var first = items[0], last = items[items.length - 1];
    var at = document.activeElement;
    if (!trap.container.contains || !trap.container.contains(at)) {
      focusQuietly(ev.shiftKey ? last : first);
      return;
    }
    var i = -1;
    for (var k = 0; k < items.length; k++) { if (items[k] === at) { i = k; break; } }
    if (i === -1) { focusQuietly(ev.shiftKey ? last : first); return; }
    focusQuietly(ev.shiftKey ? (i === 0 ? last : items[i - 1]) : (i === items.length - 1 ? first : items[i + 1]));
  }

  /**
   * Tab/Escape against the top trap. Returns true when the event was consumed,
   * so a host keyboard layer knows to stop processing it.
   * @param {KeyboardEvent} ev
   * @returns {boolean}
   */
  function handleTrapKey(ev) {
    var trap = topTrap();
    if (!trap) return false;
    var key = ev && ev.key;
    if (key === 'Tab') { trapTab(trap, ev); return true; }
    if (key === 'Escape' || key === 'Esc') { ev.preventDefault(); trap.escape(); return true; }
    return true;   // no page-level shortcut fires behind an open dialog
  }

  /** Focus arriving from outside a trapped surface is pulled straight back. */
  function onGlobalFocusIn(ev) {
    var trap = topTrap();
    if (!trap || !trap.container) return;
    var t = ev.target;
    if (t === trap.container || (trap.container.contains && trap.container.contains(t))) return;
    var items = focusablesIn(trap.container);
    focusQuietly(items[0] || trap.container);
  }
  document.addEventListener('focusin', onGlobalFocusIn);

  // On pages with no keyboard layer of their own, this module owns the keydown
  // listener — but only while a trap is up, so it costs nothing the rest of the
  // time. app.js sets hostHandlesKeys and calls handleTrapKey() itself, keeping
  // its deliberate one-listener rule intact.
  var keyListenerOn = false;
  function ownKeyDown(ev) {
    if (!ev || ev.altKey || ev.ctrlKey || ev.metaKey || ev.isComposing) return;
    handleTrapKey(ev);
  }
  function ensureKeyListener() {
    if (keyListenerOn || api.hostHandlesKeys) return;
    document.addEventListener('keydown', ownKeyDown, true);
    keyListenerOn = true;
  }
  function releaseKeyListener() {
    if (!keyListenerOn || trapStack.length) return;
    document.removeEventListener('keydown', ownKeyDown, true);
    keyListenerOn = false;
  }

  // ------------------------------------------------------------- confirm

  function t(s) { return (typeof window._t === 'function') ? window._t(s) : s; }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /**
   * An in-page replacement for window.confirm() that a browser cannot suppress.
   *
   * Resolves true only on an explicit confirm click; Escape, the Cancel button,
   * and a click outside all resolve false — the same fail-safe direction as the
   * native dialog, so a caller written for confirm() keeps its meaning.
   *
   * @param {{title:string, body?:string, confirmLabel?:string,
   *          cancelLabel?:string, danger?:boolean}} opts
   * @returns {Promise<boolean>}
   */
  function confirmDialog(opts) {
    var o = opts || {};
    return new Promise(function (resolve) {
      var back = el('div', 'ui-modal-backdrop');
      var box = el('div', 'ui-modal');
      var titleId = 'ui-modal-title-' + Date.now();

      var h = el('h2', 'ui-modal-title', o.title || t('Are you sure?'));
      h.id = titleId;
      box.setAttribute('aria-labelledby', titleId);
      box.appendChild(h);

      if (o.body) {
        // Blank-line-separated paragraphs, matching how the confirm() strings
        // these replace were written (\n\n between the ask and its caveat).
        String(o.body).split(/\n\s*\n/).forEach(function (para) {
          if (para.trim()) box.appendChild(el('p', 'ui-modal-body', para.trim()));
        });
      }

      var actions = el('div', 'ui-modal-actions');
      var okBtn = el('button', 'btn ' + (o.danger ? 'btn-danger' : 'btn-primary'),
        o.confirmLabel || t('Confirm'));
      okBtn.type = 'button';
      var noBtn = el('button', 'btn', o.cancelLabel || t('Cancel'));
      noBtn.type = 'button';
      // Cancel first in the DOM so it takes initial focus: the safe choice is
      // the one a stray Enter or Space should land on.
      actions.appendChild(noBtn);
      actions.appendChild(okBtn);
      box.appendChild(actions);
      back.appendChild(box);
      document.body.appendChild(back);

      var done = false;
      function finish(v) {
        if (done) return;
        done = true;
        trap.release();
        if (back.parentNode) back.parentNode.removeChild(back);
        resolve(v);
      }

      var trap = createFocusTrap(box, {
        dialog: true,
        onEscape: function () { finish(false); },
        onOutsideClick: function () { finish(false); }
      });

      noBtn.addEventListener('click', function () { finish(false); });
      okBtn.addEventListener('click', function () { finish(true); });
      trap.activate({ initialFocus: noBtn });
    });
  }

  var api = {
    createFocusTrap: createFocusTrap,
    handleTrapKey: handleTrapKey,
    topTrap: topTrap,
    focusablesIn: focusablesIn,
    confirm: confirmDialog,
    /** Set by a page that runs its own document keydown listener (app.js). */
    hostHandlesKeys: false
  };
  window.hiccupUi = api;
})();
