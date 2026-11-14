import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { loadDnsModules, createMockDom } from './helpers.js';

function makeClassList(initial = []) {
  const set = new Set(initial);
  return {
    add: (...cls) => cls.forEach(c => set.add(c)),
    remove: (...cls) => cls.forEach(c => set.delete(c)),
    contains: (c) => set.has(c),
  };
}

function makeElement(tag = 'div', id = '') {
  const attrs = new Map();
  const listeners = new Map();
  const children = [];
  let _innerHTML = '';
  const el = {
    tagName: tag.toUpperCase(),
    id,
    value: '',
    textContent: '',
    style: {},
    className: '',
    classList: makeClassList(),
    children,
    set innerHTML(val) {
      _innerHTML = val;
      if (val === '') {
        children.length = 0;
      }
    },
    get innerHTML() {
      return _innerHTML;
    },
    setAttribute: (k, v) => attrs.set(k, String(v)),
    getAttribute: (k) => (attrs.has(k) ? attrs.get(k) : null),
    appendChild: (child) => {
      children.push(child);
      return child;
    },
    addEventListener: (evt, fn) => {
      if (!listeners.has(evt)) listeners.set(evt, []);
      listeners.get(evt).push(fn);
    },
    trigger: (evt) => {
      for (const fn of listeners.get(evt) || []) {
        fn({ target: el });
      }
    },
  };
  return el;
}

describe('Admin Panel JS (users filter, lazy zonefile loading, backups)', () => {
  let main;
  let dom;
  let adminElements;

  beforeEach(async () => {
    dom = createMockDom('adminuser.example.com.');
    adminElements = {
      'admin-tab': makeElement('button', 'admin-tab'),
      'admin-backups-tab': makeElement('button', 'admin-backups-tab'),
      'admin-user-search': makeElement('input', 'admin-user-search'),
      'admin-users-status': makeElement('div', 'admin-users-status'),
      'admin-users-list': makeElement('div', 'admin-users-list'),
      'admin-backups-status': makeElement('div', 'admin-backups-status'),
      'admin-backups-list': makeElement('ul', 'admin-backups-list'),
      'admin-delete-user-toast': makeElement('div', 'admin-delete-user-toast'),
      'admin-delete-toast-username': makeElement('strong', 'admin-delete-toast-username'),
      'admin-delete-toast-error': makeElement('div', 'admin-delete-toast-error'),
      'admin-delete-toast-confirm': makeElement('button', 'admin-delete-toast-confirm'),
      'admin-delete-toast-cancel': makeElement('button', 'admin-delete-toast-cancel'),
      'admin-delete-mode-btn': makeElement('button', 'admin-delete-mode-btn'),
      'admin-delete-users-btn': makeElement('button', 'admin-delete-users-btn'),
    };

    const origGetById = dom.document.getElementById;
    dom.document.getElementById = (id) => adminElements[id] || origGetById(id);
    dom.document.createElement = (tag) => makeElement(tag);
    const origQuerySelector = dom.document.querySelector;
    dom.document.querySelector = (sel) => {
      if (sel === 'meta[name="current-user"]') {
        return { content: 'adminuser' };
      }
      return origQuerySelector ? origQuerySelector(sel) : null;
    };

    const mods = await loadDnsModules(dom);
    main = mods.main;
    main.reset_admin_state();
  });

  it('filter_admin_users filters by username case-insensitively', () => {
    const users = [
      { username: 'Alice', alias: 'alice', record_count: 3 },
      { username: 'bob', alias: 'custom', record_count: 5 },
      { username: 'alice-dev', alias: 'alice-dev', record_count: 4 },
    ];
    assert.equal(main.filter_admin_users(users, '').length, 3);
    assert.deepEqual(
      main.filter_admin_users(users, 'ALICE').map(u => u.username),
      ['Alice', 'alice-dev']
    );
    assert.deepEqual(
      main.filter_admin_users(users, '  bob ').map(u => u.username),
      ['bob']
    );
    assert.deepEqual(main.filter_admin_users(users, 'charlie'), []);
  });

  it('loads users once, filters on input, and downloads zonefile only when clicked', async () => {
    const fetchedUrls = [];
    globalThis.fetch = async (url) => {
      fetchedUrls.push(url);
      if (url === '/app/admin/users') {
        return {
          ok: true,
          json: async () => ({
            users: [
              { username: 'alice', alias: 'alice-sub', record_count: 4 },
              { username: 'bob', alias: 'bob', record_count: 3 },
            ],
          }),
        };
      }
      if (url === '/app/admin/users/alice/zonefile') {
        return {
          ok: true,
          text: async () => '$ORIGIN alice-sub.example.com.\nweb IN A 192.0.2.10\n',
        };
      }
      throw new Error(`Unexpected fetch: ${url}`);
    };

    main.init_admin_panel();
    adminElements['admin-tab'].trigger('shown.bs.tab');
    await new Promise(r => setImmediate(r));

    // Only the user list was fetched; no zonefiles downloaded yet
    assert.deepEqual(fetchedUrls, ['/app/admin/users']);
    assert.equal(adminElements['admin-users-list'].children.length, 2);

    // Clicking alice downloads alice's zonefile on demand and caches it
    const aliceItem = adminElements['admin-users-list'].children[0];
    const aliceRowHeader = aliceItem.children[0];
    const aliceBtn = aliceRowHeader.children[0];
    const aliceWrapper = aliceItem.children[1];
    const alicePre = aliceWrapper.children[0];

    aliceBtn.trigger('click');
    await new Promise(r => setImmediate(r));

    assert.deepEqual(fetchedUrls, [
      '/app/admin/users',
      '/app/admin/users/alice/zonefile',
    ]);
    assert.equal(aliceBtn.getAttribute('aria-expanded'), 'true');
    assert.equal(aliceWrapper.classList.contains('d-none'), false);
    assert.match(alicePre.textContent, /192\.0\.2\.10/);

    // Collapse and re-expand alice: should NOT fetch again
    aliceBtn.trigger('click');
    assert.equal(aliceBtn.getAttribute('aria-expanded'), 'false');
    assert.equal(aliceWrapper.classList.contains('d-none'), true);

    aliceBtn.trigger('click');
    await new Promise(r => setImmediate(r));
    assert.equal(fetchedUrls.length, 2);

    // Real-time search filters list without extra network requests
    adminElements['admin-user-search'].value = 'bob';
    adminElements['admin-user-search'].trigger('input');
    assert.equal(adminElements['admin-users-list'].children.length, 1);
    assert.match(adminElements['admin-users-list'].children[0].children[0].children[0].innerHTML, /bob/);
    assert.equal(fetchedUrls.length, 2);
  });

  it('supports multi-select delete mode, toggle selection, cancel, and confirmed bulk deletion', async () => {
    const calls = [];
    globalThis.fetch = async (url, opts = {}) => {
      calls.push({ url, method: opts.method || 'GET' });
      if (url === '/app/admin/users' && (opts.method || 'GET') === 'GET') {
        return {
          ok: true,
          json: async () => ({
            users: [
              { username: 'adminuser', alias: 'adminuser', record_count: 3 },
              { username: 'alice', alias: 'alice', record_count: 3 },
              { username: 'bob', alias: 'bob', record_count: 3 },
            ],
          }),
        };
      }
      if ((url === '/app/admin/users/alice' || url === '/app/admin/users/bob') && opts.method === 'DELETE') {
        return {
          ok: true,
          json: async () => ({ status: 'deleted' }),
        };
      }
      throw new Error(`Unexpected fetch: ${opts.method || 'GET'} ${url}`);
    };

    const deleteModeBtn = adminElements['admin-delete-mode-btn'];
    const deleteUsersBtn = adminElements['admin-delete-users-btn'];
    deleteModeBtn.innerHTML = '<i class="bi bi-trash me-1"></i>Delete users';
    deleteUsersBtn.classList.add('d-none');
    deleteUsersBtn.disabled = true;

    main.init_admin_panel();
    adminElements['admin-tab'].trigger('shown.bs.tab');
    await new Promise(r => setImmediate(r));

    // Initially no checkboxes or trash icons on user rows, action button hidden
    assert.equal(adminElements['admin-users-list'].children[1].children[0].children.length, 1);
    assert.equal(deleteUsersBtn.classList.contains('d-none'), true);

    // Enter selection mode via 'Delete users'
    deleteModeBtn.trigger('click');
    assert.match(deleteModeBtn.innerHTML, /Exit user deletion/);
    assert.equal(deleteUsersBtn.classList.contains('d-none'), false);
    assert.equal(deleteUsersBtn.disabled, true);
    assert.equal(deleteUsersBtn.textContent, 'Select users to delete');

    // Exiting selection mode restores normal state
    deleteModeBtn.trigger('click');
    assert.match(deleteModeBtn.innerHTML, /Delete users/);
    assert.equal(deleteUsersBtn.classList.contains('d-none'), true);
    assert.equal(adminElements['admin-users-list'].children[1].children[0].children.length, 1);

    // Re-enter selection mode
    deleteModeBtn.trigger('click');

    // Self row still has no checkbox; other rows have checkbox + headerBtn
    const selfRowHeader = adminElements['admin-users-list'].children[0].children[0];
    assert.equal(selfRowHeader.children.length, 1);

    const aliceRowHeader = adminElements['admin-users-list'].children[1].children[0];
    const aliceCheckbox = aliceRowHeader.children[0];
    const aliceHeaderBtn = aliceRowHeader.children[1];
    assert.equal(aliceCheckbox.type, 'checkbox');
    assert.equal(aliceCheckbox.checked, false);

    // Clicking anywhere in alice's entry selects alice and enables button
    aliceHeaderBtn.trigger('click');
    assert.equal(aliceCheckbox.checked, true);
    assert.equal(deleteUsersBtn.disabled, false);
    assert.equal(deleteUsersBtn.textContent, 'Delete selected users');

    // Clicking again unselects alice and disables button
    aliceHeaderBtn.trigger('click');
    assert.equal(aliceCheckbox.checked, false);
    assert.equal(deleteUsersBtn.disabled, true);
    assert.equal(deleteUsersBtn.textContent, 'Select users to delete');

    // Select both alice and bob (via row click and checkbox change)
    aliceHeaderBtn.trigger('click');
    const bobRowHeader = adminElements['admin-users-list'].children[2].children[0];
    const bobCheckbox = bobRowHeader.children[0];
    bobCheckbox.checked = true;
    bobCheckbox.trigger('change');

    assert.equal(deleteUsersBtn.disabled, false);
    assert.equal(deleteUsersBtn.textContent, 'Delete selected users');

    // Click 'Delete selected users' -> shows confirmation toast
    deleteUsersBtn.trigger('click');
    assert.equal(adminElements['admin-delete-user-toast'].classList.contains('show'), true);
    assert.equal(adminElements['admin-delete-toast-username'].textContent, 'alice, bob');

    // Cancel toast -> hides toast without sending DELETE
    adminElements['admin-delete-toast-cancel'].trigger('click');
    assert.equal(adminElements['admin-delete-user-toast'].classList.contains('show'), false);
    assert.equal(calls.filter(c => c.method === 'DELETE').length, 0);

    // Confirm deletion -> sends DELETE for alice and bob, removes them, exits selection mode
    deleteUsersBtn.trigger('click');
    adminElements['admin-delete-toast-confirm'].trigger('click');
    await new Promise(r => setImmediate(r));

    assert.deepEqual(calls, [
      { url: '/app/admin/users', method: 'GET' },
      { url: '/app/admin/users/alice', method: 'DELETE' },
      { url: '/app/admin/users/bob', method: 'DELETE' },
    ]);
    assert.equal(adminElements['admin-delete-user-toast'].classList.contains('show'), false);
    assert.equal(adminElements['admin-users-list'].children.length, 1);
    assert.match(adminElements['admin-users-list'].children[0].children[0].children[0].innerHTML, /adminuser/);
    assert.equal(deleteUsersBtn.classList.contains('d-none'), true);
    assert.match(deleteModeBtn.innerHTML, /Delete users/);
  });

  it('loads and renders backup filenames in the Backups tab', async () => {
    globalThis.fetch = async (url) => {
      assert.equal(url, '/app/admin/backups');
      return {
        ok: true,
        json: async () => ({
          backups: ['bind-2026-11-14_01-00-00.tar.gz', 'bind-2026-11-13_12-00-00.tar.gz'],
        }),
      };
    };

    main.init_admin_panel();
    adminElements['admin-backups-tab'].trigger('shown.bs.tab');
    await new Promise(r => setImmediate(r));

    assert.equal(adminElements['admin-backups-list'].children.length, 2);
    assert.equal(
      adminElements['admin-backups-list'].children[0].textContent,
      'bind-2026-11-14_01-00-00.tar.gz'
    );
    assert.equal(adminElements['admin-backups-status'].textContent, '2 backups');
  });
});
