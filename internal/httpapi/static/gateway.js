// Gateway settings page: one accordion panel per account, each holding that
// account's routing rules (目标 = subdomain + path, 源 = upstream URL).
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    var AuthDock = window.AuthDock;

    var container = document.getElementById('gateway');
    var message = document.getElementById('message');

    var state = {
      domain: '',
      users: [],
      expanded: {},
      drafts: {}
    };

    function literal(text) {
      return AuthDock.textElement('span', 'literal', text);
    }

    function input(value, placeholder, extraClass) {
      var element = document.createElement('input');
      element.type = 'text';
      element.className = 'field' + (extraClass ? ' ' + extraClass : '');
      element.value = value || '';
      element.placeholder = placeholder;
      element.autocomplete = 'off';
      return element;
    }

    function renderRuleRow(user, rule) {
      var isDraft = !rule || !rule.id;
      var row = document.createElement('tr');

      // 目标: https://<subdomain>.<gateway domain>/<path>
      var targetCell = document.createElement('td');
      var line = AuthDock.textElement('div', 'rule-line');
      line.appendChild(literal('https://'));
      var subdomainInput = input(isDraft ? '' : rule.subdomain, 'calendar 或 *');
      line.appendChild(subdomainInput);
      line.appendChild(literal('.' + (state.domain || '（未设置网关域名）') + '/'));
      var pathInput = input(isDraft ? '*' : rule.path, '* 或 /path');
      line.appendChild(pathInput);
      targetCell.appendChild(line);
      row.appendChild(targetCell);

      // 源: upstream URL
      var sourceCell = document.createElement('td');
      var upstreamInput = input(isDraft ? '' : rule.upstream, 'http://10.0.0.1:10123/', 'wide');
      sourceCell.appendChild(upstreamInput);
      row.appendChild(sourceCell);

      var actions = AuthDock.textElement('div', 'actions');

      var confirmButton = AuthDock.iconButton('is-confirm', isDraft ? '保存新规则' : '保存该行修改', 'check');
      confirmButton.addEventListener('click', async function () {
        var body = {
          subdomain: subdomainInput.value.trim(),
          path: pathInput.value.trim() || '*',
          upstream: upstreamInput.value.trim()
        };
        confirmButton.disabled = true;
        try {
          if (isDraft) {
            body.user_id = user.id;
            await AuthDock.request('gateway/rules', { method: 'POST', body: body });
          } else {
            await AuthDock.request('gateway/rules/' + rule.id, { method: 'PATCH', body: body });
          }
          AuthDock.showMessage(message, '规则已保存', 'ok');
          await load();
        } catch (err) {
          AuthDock.showMessage(message, err.message, 'error');
        } finally {
          confirmButton.disabled = false;
        }
      });
      actions.appendChild(confirmButton);

      var deleteButton = AuthDock.iconButton('is-danger', isDraft ? '放弃这条新规则' : '删除该规则', 'trash');
      deleteButton.addEventListener('click', async function () {
        if (isDraft) {
          state.drafts[user.id] = (state.drafts[user.id] || []).filter(function (draft) {
            return draft !== rule;
          });
          render();
          return;
        }
        if (!window.confirm('删除 ' + rule.subdomain + ' 的这条规则？')) {
          return;
        }
        deleteButton.disabled = true;
        try {
          await AuthDock.request('gateway/rules/' + rule.id, { method: 'DELETE' });
          AuthDock.showMessage(message, '规则已删除', 'ok');
          await load();
        } catch (err) {
          AuthDock.showMessage(message, err.message, 'error');
        } finally {
          deleteButton.disabled = false;
        }
      });
      actions.appendChild(deleteButton);

      var actionCell = document.createElement('td');
      actionCell.className = 'align-right';
      actionCell.appendChild(actions);
      row.appendChild(actionCell);

      return row;
    }

    function renderRules(user) {
      var rules = (user.rules || []).slice();
      var drafts = state.drafts[user.id] || [];

      if (rules.length === 0 && drafts.length === 0) {
        return [AuthDock.textElement('p', 'empty', '这个账号还没有网关规则')];
      }

      var table = AuthDock.textElement('table', 'table');
      var head = document.createElement('thead');
      var headRow = document.createElement('tr');
      headRow.appendChild(AuthDock.textElement('th', '', '目标'));
      headRow.appendChild(AuthDock.textElement('th', '', '源'));
      var actionHead = AuthDock.textElement('th', 'align-right', '操作');
      headRow.appendChild(actionHead);
      head.appendChild(headRow);
      table.appendChild(head);

      var body = document.createElement('tbody');
      rules.forEach(function (rule) {
        body.appendChild(renderRuleRow(user, rule));
      });
      drafts.forEach(function (draft) {
        body.appendChild(renderRuleRow(user, draft));
      });
      table.appendChild(body);
      return [table];
    }

    function renderPanel(user) {
      var section = AuthDock.textElement('section', 'acc');
      var head = document.createElement('button');
      head.type = 'button';
      head.className = 'acc-head';
      var expanded = state.expanded[user.id] === true;
      head.setAttribute('aria-expanded', expanded ? 'true' : 'false');

      head.appendChild(AuthDock.textElement('span', 'acc-title', user.username));
      var ruleCount = (user.rules || []).length;
      var meta = ruleCount === 0 ? '暂无规则' : ruleCount + ' 条规则';
      if (user.role === 'admin') {
        meta += ' · 管理员';
      }
      head.appendChild(AuthDock.textElement('span', 'acc-meta', meta));
      head.appendChild(AuthDock.textElement('span', 'spacer'));
      var chevron = AuthDock.icon('chevron');
      chevron.classList.add('chevron');
      head.appendChild(chevron);

      head.addEventListener('click', function () {
        state.expanded[user.id] = !expanded;
        render();
      });
      section.appendChild(head);

      if (expanded) {
        var panelBody = AuthDock.textElement('div', 'acc-body');
        renderRules(user).forEach(function (child) {
          panelBody.appendChild(child);
        });

        var addButton = document.createElement('button');
        addButton.type = 'button';
        addButton.className = 'btn';
        addButton.appendChild(AuthDock.icon('plus'));
        addButton.appendChild(AuthDock.textElement('span', '', '添加规则'));
        addButton.addEventListener('click', function () {
          state.drafts[user.id] = state.drafts[user.id] || [];
          state.drafts[user.id].push({});
          render();
        });
        panelBody.appendChild(addButton);
        section.appendChild(panelBody);
      }

      return section;
    }

    function render() {
      container.replaceChildren();

      if (state.domain) {
        container.appendChild(AuthDock.textElement('p', 'empty',
          '网关域名：' + state.domain + '   （可在系统设置中修改）'));
      } else {
        container.appendChild(AuthDock.textElement('p', 'empty',
          '尚未设置网关域名，请先到“系统设置”里填写。'));
      }

      if (state.users.length === 0) {
        container.appendChild(AuthDock.textElement('p', 'empty', '还没有账号'));
        return;
      }
      state.users.forEach(function (user) {
        container.appendChild(renderPanel(user));
      });
    }

    async function load() {
      try {
        var data = await AuthDock.request('gateway');
        state.domain = data.gateway_domain || '';
        state.users = data.users || [];
        // Expand the first account the first time the page is shown.
        if (!state.initialisedClicks && state.users.length > 0) {
          state.expanded[state.users[0].id] = true;
          state.initialisedClicks = true;
        }
        render();
      } catch (err) {
        AuthDock.showMessage(message, err.message, 'error');
      }
    }

    load();
  });
})();
