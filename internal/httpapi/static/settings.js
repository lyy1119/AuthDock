// System settings page: currently just the gateway base domain.
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    var AuthDock = window.AuthDock;

    var form = document.getElementById('settings-form');
    var input = document.getElementById('gateway-domain');
    var saveButton = document.getElementById('save');
    var message = document.getElementById('message');

    var saved = '';

    async function load() {
      try {
        var data = await AuthDock.request('settings');
        saved = (data.settings && data.settings.gateway_domain) || '';
        input.value = saved;
      } catch (err) {
        AuthDock.showMessage(message, err.message, 'error');
      }
    }

    document.getElementById('cancel').addEventListener('click', function () {
      input.value = saved;
      AuthDock.showMessage(message, '已还原为上次保存的值');
    });

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var value = input.value.trim();
      saveButton.disabled = true;
      try {
        var data = await AuthDock.request('settings', {
          method: 'PUT',
          body: { gateway_domain: value }
        });
        saved = (data.settings && data.settings.gateway_domain) || '';
        input.value = saved;
        AuthDock.showMessage(message, '已保存', 'ok');
      } catch (err) {
        AuthDock.showMessage(message, err.message, 'error');
      } finally {
        saveButton.disabled = false;
      }
    });

    load();
  });
})();
