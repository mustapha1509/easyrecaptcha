/**
 * EasyRecaptcha - back office login script (ES5, no dependencies).
 * Settings arrive in this script's own URL (?sk=..&v=..&th=..&sz=..&host=..&hl=..&msg=..),
 * so nothing else has to be injected into the login page.
 */
(function () {
  'use strict';

  function ownParams() {
    var el = document.currentScript;
    if (!el) {
      var all = document.getElementsByTagName('script');
      for (var i = all.length - 1; i >= 0; i--) {
        if (all[i].src && all[i].src.indexOf('easyrecaptcha-admin.js') !== -1) { el = all[i]; break; }
      }
    }
    var out = {};
    if (!el || !el.src || el.src.indexOf('?') === -1) { return out; }
    var pairs = el.src.split('?')[1].split('#')[0].split('&');
    for (var p = 0; p < pairs.length; p++) {
      var kv = pairs[p].split('=');
      out[decodeURIComponent(kv[0])] = decodeURIComponent((kv[1] || '').replace(/\+/g, ' '));
    }
    return out;
  }

  var cfg = ownParams();
  if (!cfg.sk) { return; }
  var V3 = cfg.v === 'v3';

  function findForm() {
    var form = document.getElementById('login_form');
    if (form) { return form; }
    var pass = document.querySelector('input[name="passwd"]');
    return pass ? pass.form : null;
  }

  var failed = false;

  function load(callback) {
    var script = document.createElement('script');
    script.src = 'https://' + (cfg.host || 'www.google.com') + '/recaptcha/api.js?render=' +
      (V3 ? encodeURIComponent(cfg.sk) : 'explicit') + '&hl=' + encodeURIComponent(cfg.hl || 'en');
    script.async = true;
    script.defer = true;
    script.onload = function () { window.grecaptcha.ready(callback); };
    script.onerror = function () { failed = true; }; // let the server refuse it with a visible message
    document.head.appendChild(script);
  }

  function start() {
    var form = findForm();
    if (!form || form.getAttribute('data-easyrecaptcha')) { return; }
    form.setAttribute('data-easyrecaptcha', 'admin_login');

    var btn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');

    if (V3) {
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'g-recaptcha-response';
      form.appendChild(input);

      var refresh = function (done) {
        window.grecaptcha.execute(cfg.sk, { action: 'admin_login' }).then(function (t) {
          input.value = t;
          if (done) { done(); }
        }, function () { if (done) { done(); } });
      };
      load(function () {
        refresh();
        setInterval(refresh, 90 * 1000);
      });
      form.addEventListener('submit', function (event) {
        if (input.value || !window.grecaptcha || !window.grecaptcha.execute) { return; }
        event.preventDefault();
        var submitter = event.submitter || document.activeElement;
        refresh(function () {
          if (submitter && submitter.name && submitter.form === form) {
            var extra = document.createElement('input');
            extra.type = 'hidden';
            extra.name = submitter.name;
            extra.value = submitter.value;
            form.appendChild(extra);
          }
          HTMLFormElement.prototype.submit.call(form);
        });
      });
      return;
    }

    var box = document.createElement('div');
    box.style.margin = '12px 0';
    if (btn && btn.parentNode) { btn.parentNode.insertBefore(box, btn); } else { form.appendChild(box); }
    var error = document.createElement('div');
    error.style.cssText = 'display:none;color:#c0392b;margin:0 0 12px';
    error.appendChild(document.createTextNode(cfg.msg || ''));
    box.parentNode.insertBefore(error, box.nextSibling);

    var widget = null;
    load(function () {
      widget = window.grecaptcha.render(box, {
        sitekey: cfg.sk,
        theme: cfg.th === 'dark' ? 'dark' : 'light',
        size: cfg.sz === 'compact' ? 'compact' : 'normal'
      });
    });
    form.addEventListener('submit', function (event) {
      if (failed) { return; }
      if (widget === null || !window.grecaptcha.getResponse(widget)) {
        event.preventDefault();
        event.stopImmediatePropagation();
        error.style.display = 'block';
      }
    }, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
