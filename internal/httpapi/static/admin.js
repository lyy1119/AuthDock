// Shared helpers for the AuthDock management pages.
//
// Everything is relative to the page URL so the pages keep working behind a
// reverse proxy that mounts the app under a path prefix (code-server's
// /proxy/<port>/, for example).
(function () {
  'use strict';

  var ICONS = {
    menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16.5 5.2a3.5 3.5 0 0 1 0 6.6"/><path d="M18 20a6.5 6.5 0 0 0-2-4.7"/>',
    server: '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19.5 14.2a1.7 1.7 0 0 0 .3 1.9l.2.1a2 2 0 1 1-2.8 2.8l-.1-.2a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V20a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.2a2 2 0 1 1-2.8-2.8l.2-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.2-.1a2 2 0 1 1 2.8-2.8l.1.2a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.2a2 2 0 1 1 2.8 2.8l-.2.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.4 1.1z"/>',
    logout: '<path d="M9 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
    check: '<path d="M20 6L9 17l-5-5"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    chevron: '<path d="M6 9l6 6 6-6"/>'
  };

  function icon(name) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.7');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    svg.setAttribute('class', 'icon');
    svg.innerHTML = ICONS[name] || '';
    return svg;
  }

  var API = new URL('../api/admin/', window.location.href);

  function redirectToLogin() {
    window.location.href = new URL('../login', window.location.href).href;
  }

  // request calls an admin endpoint and resolves with the decoded JSON body.
  // Every failure becomes an Error carrying the server message.
  async function request(path, options) {
    var init = Object.assign({ credentials: 'same-origin' }, options || {});
    init.headers = Object.assign({ Accept: 'application/json' }, init.headers || {});
    if (init.body !== undefined && typeof init.body !== 'string') {
      init.body = JSON.stringify(init.body);
      init.headers['Content-Type'] = 'application/json';
    }

    var response = await fetch(new URL(path, API), init);
    var data = null;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }

    if (response.status === 401) {
      redirectToLogin();
      throw new Error('会话已过期，请重新登录');
    }
    if (!response.ok || !data || data.ok === false) {
      throw new Error((data && data.message) || ('请求失败（HTTP ' + response.status + '）'));
    }
    return data;
  }

  function showMessage(element, text, kind) {
    if (!element) {
      return;
    }
    element.textContent = text || '';
    element.classList.toggle('is-error', kind === 'error');
    element.classList.toggle('is-ok', kind === 'ok');
  }

  function textElement(tag, className, text) {
    var element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (text !== undefined) {
      element.textContent = text;
    }
    return element;
  }

  function iconButton(kind, label, iconName) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'icon-btn ' + kind;
    button.title = label;
    button.setAttribute('aria-label', label);
    button.appendChild(icon(iconName));
    return button;
  }

  document.addEventListener('DOMContentLoaded', function () {
    // Fill static icon placeholders.
    var placeholders = document.querySelectorAll('[data-icon]');
    for (var i = 0; i < placeholders.length; i++) {
      var placeholder = placeholders[i];
      placeholder.replaceChildren(icon(placeholder.getAttribute('data-icon')));
    }

    var rail = document.querySelector('.rail');
    var toggle = document.getElementById('rail-toggle');
    if (rail && toggle) {
      if (window.localStorage.getItem('authdock.rail') === 'open') {
        rail.classList.add('is-open');
      }
      toggle.addEventListener('click', function () {
        var open = rail.classList.toggle('is-open');
        window.localStorage.setItem('authdock.rail', open ? 'open' : 'closed');
      });
    }

    var logout = document.getElementById('logout');
    if (logout) {
      logout.addEventListener('click', function () {
        fetch(new URL('../api/auth/logout', window.location.href), {
          method: 'POST',
          credentials: 'same-origin'
        }).catch(function () {
          // Ignore: the redirect below is what matters.
        }).finally(redirectToLogin);
      });
    }
  });

  window.AuthDock = {
    API: API,
    request: request,
    icon: icon,
    iconButton: iconButton,
    textElement: textElement,
    showMessage: showMessage,
    redirectToLogin: redirectToLogin
  };
})();
