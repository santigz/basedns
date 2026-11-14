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

  it('shows confirmation toast on delete click, supports cancel, and deletes on confirm', async () => {
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
      if (url === '/app/admin/users/alice' && opts.method === 'DELETE') {
        return {
          ok: true,
          json: async () => ({ status: 'deleted', username: 'alice' }),
        };
      }
      throw new Error(`Unexpected fetch: ${opts.method || 'GET'} ${url}`);
    };

    main.init_admin_panel();
    adminElements['admin-tab'].trigger('shown.bs.tab');
    await new Promise(r => setImmediate(r));

    // Current admin user row has no delete button
    const selfRowHeader = adminElements['admin-users-list'].children[0].children[0];
    assert.equal(selfRowHeader.children.length, 1);

    // Click delete button on alice
    const aliceDeleteBtn = adminElements['admin-users-list'].children[1].children[0].children[1];
    aliceDeleteBtn.trigger('click');

    assert.equal(adminElements['admin-delete-user-toast'].classList.contains('show'), true);
    assert.equal(adminElements['admin-delete-toast-username'].textContent, 'alice');

    // Cancel hides toast without sending DELETE
    adminElements['admin-delete-toast-cancel'].trigger('click');
    assert.equal(adminElements['admin-delete-user-toast'].classList.contains('show'), false);
    assert.equal(calls.filter(c => c.method === 'DELETE').length, 0);

    // Click delete again and confirm
    aliceDeleteBtn.trigger('click');
    adminElements['admin-delete-toast-confirm'].trigger('click');
    await new Promise(r => setImmediate(r));

    assert.deepEqual(calls, [
      { url: '/app/admin/users', method: 'GET' },
      { url: '/app/admin/users/alice', method: 'DELETE' },
    ]);
    assert.equal(adminElements['admin-delete-user-toast'].classList.contains('show'), false);
    assert.equal(adminElements['admin-users-list'].children.length, 2);
    assert.match(adminElements['admin-users-list'].children[1].children[0].children[0].innerHTML, /bob/);
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
