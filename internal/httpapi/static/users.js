// User management page.
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    var AuthDock = window.AuthDock;

    var table = document.getElementById('users-table');
    var tbody = document.getElementById('users-body');
    var empty = document.getElementById('empty');
    var message = document.getElementById('message');
    var dialog = document.getElementById('user-dialog');
    var form = document.getElementById('user-form');
    var dialogMessage = document.getElementById('dialog-message');
    var dialogSubmit = document.getElementById('create-user');

    function roleSelect(role) {
      var select = document.createElement('select');
      select.className = 'field';
      [['user', '普通用户'], ['admin', '管理员']].forEach(function (pair) {
        var option = document.createElement('option');
        option.value = pair[0];
        option.textContent = pair[1];
        select.appendChild(option);
      });
      select.value = role;
      return select;
    }

    function renderRow(user) {
      var row = document.createElement('tr');

      var nameCell = document.createElement('td');
      var nameWrap = AuthDock.textElement('div', 'username');
      nameWrap.appendChild(AuthDock.textElement('span', '', user.username));
      if (user.self) {
        nameWrap.appendChild(AuthDock.textElement('span', 'badge', '当前账号'));
      }
      nameCell.appendChild(nameWrap);
      row.appendChild(nameCell);

      var password = document.createElement('input');
      password.type = 'password';
      password.className = 'field';
      password.placeholder = '留空则不修改';
      password.autocomplete = 'new-password';
      password.setAttribute('aria-label', '为 ' + user.username + ' 设置新密码');
      var passwordCell = document.createElement('td');
      passwordCell.appendChild(password);
      row.appendChild(passwordCell);

      var role = roleSelect(user.role);
      role.setAttribute('aria-label', user.username + ' 的身份');
      var roleCell = document.createElement('td');
      roleCell.appendChild(role);
      row.appendChild(roleCell);

      var actions = AuthDock.textElement('div', 'actions');

      var confirmButton = AuthDock.iconButton('is-confirm', '保存该行的身份与密码', 'check');
      confirmButton.addEventListener('click', async function () {
        confirmButton.disabled = true;
        var body = { role: role.value };
        if (password.value) {
          body.password = password.value;
        }
        try {
          var result = await AuthDock.request('users/' + user.id, { method: 'PATCH', body: body });
          password.value = '';
          if (result.logged_out) {
            window.alert('已取消自己的管理员身份，请重新登录');
            AuthDock.redirectToLogin();
            return;
          }
          AuthDock.showMessage(message, '已保存 ' + user.username, 'ok');
          await load();
        } catch (err) {
          AuthDock.showMessage(message, err.message, 'error');
        } finally {
          confirmButton.disabled = false;
        }
      });
      actions.appendChild(confirmButton);

      var deleteButton = AuthDock.iconButton('is-danger', '删除该账号', 'trash');
      deleteButton.addEventListener('click', async function () {
        if (!window.confirm('确定删除用户 ' + user.username + ' 吗？其网关规则会一并删除。')) {
          return;
        }
        deleteButton.disabled = true;
        try {
          await AuthDock.request('users/' + user.id, { method: 'DELETE' });
          AuthDock.showMessage(message, '已删除 ' + user.username, 'ok');
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

    async function load() {
      try {
        var data = await AuthDock.request('users');
        tbody.replaceChildren();
        data.users.forEach(function (user) {
          tbody.appendChild(renderRow(user));
        });
        var hasUsers = data.users.length > 0;
        table.hidden = !hasUsers;
        empty.hidden = hasUsers;
      } catch (err) {
        AuthDock.showMessage(message, err.message, 'error');
      }
    }

    document.getElementById('add-user').addEventListener('click', function () {
      form.reset();
      AuthDock.showMessage(dialogMessage, '');
      dialog.showModal();
    });

    document.getElementById('cancel-new').addEventListener('click', function () {
      dialog.close();
    });

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var body = {
        username: document.getElementById('new-username').value.trim(),
        password: document.getElementById('new-password').value,
        role: document.getElementById('new-role').value
      };

      dialogSubmit.disabled = true;
      try {
        await AuthDock.request('users', { method: 'POST', body: body });
        dialog.close();
        AuthDock.showMessage(message, '已创建用户 ' + body.username, 'ok');
        await load();
      } catch (err) {
        AuthDock.showMessage(dialogMessage, err.message, 'error');
      } finally {
        dialogSubmit.disabled = false;
      }
    });

    load();
  });
})();
