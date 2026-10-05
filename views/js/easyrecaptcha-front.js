/**
 * EasyRecaptcha - front office script (ES5, no dependencies).
 *
 * Finds the login / registration / contact / personal-information forms by the hidden or
 * submit field PrestaShop always posts (submitLogin, submitCreate, submitMessage), so no
 * theme template has to be edited, then:
 *   v2 -> renders the "I'm not a robot" checkbox before the submit button;
 *   v3 -> keeps a fresh invisible token in a hidden field.
 * The token is posted as "g-recaptcha-response" and verified server-side.
 */
(function () {
  'use strict';

  var cfg = window.easyRecaptchaConfig;
  if (!cfg || !cfg.siteKey || !cfg.forms || !cfg.forms.length) {
    return;
  }

  var V3 = cfg.version === 'v3';
  var TOKEN_FIELD = 'g-recaptcha-response';
  var REFRESH_MS = 90 * 1000; // v3 tokens expire after 2 minutes

  var FIELDS = [
    { name: 'submitLogin', key: 'login' },
    { name: 'submitCreate', key: cfg.page === 'identity' ? 'identity' : 'register' },
    { name: 'submitMessage', key: 'contact' }
  ];

  var items = [];
  var apiState = 0; // 0 = not requested, 1 = loading, 2 = ready
  var apiFailed = false; // Google's script could not be loaded (ad blocker, firewall...)
  var waiting = [];

  document.documentElement.className += ' easyrecaptcha-badge-' + (cfg.badge || 'bottomright');

  function inList(list, value) {
    for (var i = 0; i < list.length; i++) {
      if (list[i] === value) { return true; }
    }
    return false;
  }

  function closestForm(el) {
    while (el && el.nodeType === 1) {
      if (el.tagName === 'FORM') { return el; }
      el = el.parentNode;
    }
    return null;
  }

  function submitButton(form) {
    return form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
  }

  function insertBeforeSubmit(form, node) {
    var btn = submitButton(form);
    if (btn && btn.parentNode) {
      btn.parentNode.insertBefore(node, btn);
    } else {
      form.appendChild(node);
    }
  }

  /* ---- Google API ----------------------------------------------------- */

  function whenApiReady(callback) {
    if (apiState === 2) { callback(); return; }
    waiting.push(callback);
    if (apiState === 1) { return; }
    apiState = 1;

    var script = document.createElement('script');
    script.src = 'https://' + cfg.host + '/recaptcha/api.js?render=' +
      (V3 ? encodeURIComponent(cfg.siteKey) : 'explicit') + '&hl=' + encodeURIComponent(cfg.hl || 'en');
    script.async = true;
    script.defer = true;
    script.onload = function () {
      window.grecaptcha.ready(function () {
        apiState = 2;
        var queue = waiting.slice();
        waiting = [];
        for (var i = 0; i < queue.length; i++) { queue[i](); }
      });
    };
    script.onerror = function () {
      // Blocked (ad blocker, firewall...). Do not trap the visitor's click: let the form go
      // to the server, which refuses it and shows the "captcha failed" message.
      apiFailed = true;
      apiState = 0;
      waiting = [];
    };
    document.head.appendChild(script);
  }

  /* ---- v3 ------------------------------------------------------------- */

  function refreshToken(item, done) {
    whenApiReady(function () {
      try {
        window.grecaptcha.execute(cfg.siteKey, { action: item.key }).then(function (token) {
          item.input.value = token;
          if (done) { done(); }
        }, function () {
          if (done) { done(); }
        });
      } catch (e) {
        if (done) { done(); }
      }
    });
  }

  function prepareV3(item) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = TOKEN_FIELD;
    input.value = '';
    item.form.appendChild(input);
    item.input = input;

    if (cfg.legal) {
      var legal = document.createElement('p');
      legal.className = 'easyrecaptcha-legal';
      legal.innerHTML = cfg.legal;
      insertBeforeSubmit(item.form, legal);
    }

    // If the visitor submits before a token exists (very fast autofill), get one, then submit.
    item.form.addEventListener('submit', function (event) {
      if (item.input.value || apiFailed) { return; }
      event.preventDefault();
      var submitter = event.submitter || document.activeElement;
      refreshToken(item, function () {
        // Re-submitting from script loses the clicked button's name=value (e.g. submitMessage).
        if (submitter && submitter.name && submitter.form === item.form) {
          var extra = document.createElement('input');
          extra.type = 'hidden';
          extra.name = submitter.name;
          extra.value = submitter.value;
          item.form.appendChild(extra);
        }
        HTMLFormElement.prototype.submit.call(item.form);
      });
    });
  }

  /* ---- v2 ------------------------------------------------------------- */

  function activateV2(item) {
    var box = document.createElement('div');
    box.className = 'easyrecaptcha-box';
    insertBeforeSubmit(item.form, box);

    var error = document.createElement('div');
    error.className = 'easyrecaptcha-error';
    error.style.display = 'none';
    error.appendChild(document.createTextNode(cfg.msgRequired || ''));
    box.parentNode.insertBefore(error, box.nextSibling);

    item.widget = window.grecaptcha.render(box, {
      sitekey: cfg.siteKey,
      theme: cfg.theme === 'dark' ? 'dark' : 'light',
      size: cfg.size === 'compact' ? 'compact' : 'normal'
    });

    // Capture phase: stop the submission (and any other handler) until the box is ticked.
    item.form.addEventListener('submit', function (event) {
      if (!window.grecaptcha.getResponse(item.widget)) {
        event.preventDefault();
        event.stopImmediatePropagation();
        error.style.display = 'block';
      } else {
        error.style.display = 'none';
      }
    }, true);
  }

  /* ---- discovery ------------------------------------------------------ */

  function activate(item) {
    if (item.active) { return; }
    item.active = true;
    if (V3) {
      refreshToken(item);
    } else {
      activateV2(item);
    }
  }

  function startWhenNeeded(item) {
    var go = function () {
      whenApiReady(function () { activate(item); });
    };
    if (!cfg.lazy) { go(); return; }
    var events = ['focusin', 'pointerdown', 'touchstart', 'keydown'];
    var once = function () {
      for (var i = 0; i < events.length; i++) { item.form.removeEventListener(events[i], once, true); }
      go();
    };
    for (var i = 0; i < events.length; i++) { item.form.addEventListener(events[i], once, true); }
  }

  function discover() {
    for (var f = 0; f < FIELDS.length; f++) {
      if (!inList(cfg.forms, FIELDS[f].key)) { continue; }
      var nodes = document.querySelectorAll('[name="' + FIELDS[f].name + '"]');
      for (var n = 0; n < nodes.length; n++) {
        var form = closestForm(nodes[n]);
        if (!form || form.getAttribute('data-easyrecaptcha')) { continue; }
        form.setAttribute('data-easyrecaptcha', FIELDS[f].key);
        var item = { form: form, key: FIELDS[f].key, active: false };
        items.push(item);
        if (V3) { prepareV3(item); }
        startWhenNeeded(item);
      }
    }
  }

  function init() {
    discover();

    // Checkout re-renders parts of the page: pick up forms that appear later.
    if (window.MutationObserver) {
      var timer = null;
      new MutationObserver(function () {
        clearTimeout(timer);
        timer = setTimeout(discover, 150);
      }).observe(document.body, { childList: true, subtree: true });
    }

    if (V3) {
      setInterval(function () {
        if (apiState !== 2 || document.hidden) { return; }
        for (var i = 0; i < items.length; i++) { if (items[i].active) { refreshToken(items[i]); } }
      }, REFRESH_MS);
      document.addEventListener('visibilitychange', function () {
        if (document.hidden || apiState !== 2) { return; }
        for (var i = 0; i < items.length; i++) { if (items[i].active) { refreshToken(items[i]); } }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
