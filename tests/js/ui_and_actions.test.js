import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { loadDnsModules, createMockDom } from './helpers.js';

const BASE_ZONE_TEXT = `$ORIGIN user.example.com.
$TTL 60

@  IN  SOA ns.user.example.com. admin.user.example.com. 1 60 60 60 60
@  IN  NS  ns
ns IN  A   192.0.2.1
`;

describe('UI Record Creation, Deletion Protection, XSS & Error Handling (main.js)', () => {
  let main;
  let zonefile;
  let dom;

  beforeEach(async () => {
    dom = createMockDom('user.example.com.');
    const mods = await loadDnsModules(dom);
    main = mods.main;
    zonefile = mods.zonefile;
    main.set_user_origin('user.example.com.');
    main.set_zone(zonefile.parse(BASE_ZONE_TEXT));
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({}),
      text: async () => BASE_ZONE_TEXT,
    });
  });

  it('converts IDN target hostnames to Punycode (toASCII) in CNAME, MX, and NS creation', async () => {
    // 1. CNAME with non-ASCII alias
    const cnameForm = dom.createForm([
      { id: 'cname-name', value: 'blog', classes: ['cname-hostname-validation'] },
      { id: 'cname-alias', value: 'españa.example.com.', classes: ['hostname-validation'] },
      { id: 'cname-ttl', value: '300', classes: ['ttl-validation'] },
    ]);
    main.create_record_cname(cnameForm.button);
    await new Promise(r => setImmediate(r));
    assert.equal(main.get_zone().cname[0].alias, 'xn--espaa-rta.example.com.');

    // 2. MX with non-ASCII mail server host
    const mxForm = dom.createForm([
      { id: 'mx-name', value: '@', classes: ['hostname-validation'] },
      { id: 'mx-host', value: 'correo.españa.es.', classes: ['hostname-validation'] },
      { id: 'mx-priority', value: '10', classes: ['priority-validation'] },
      { id: 'mx-ttl', value: '', classes: ['ttl-validation'] },
    ]);
    main.create_record_mx(mxForm.button);
    await new Promise(r => setImmediate(r));
    assert.equal(main.get_zone().mx[0].host, 'correo.xn--espaa-rta.es.');

    // 3. NS with non-ASCII nameserver host
    const nsForm = dom.createForm([
      { id: 'ns-name', value: 'sub', classes: ['hostname-validation'] },
      { id: 'ns-nameserver', value: 'ns1.españa.es.', classes: ['nameserver-validation'] },
      { id: 'ns-ttl', value: '', classes: ['ttl-validation'] },
    ]);
    main.create_record_ns(nsForm.button);
    await new Promise(r => setImmediate(r));
    const subNs = main.get_zone().ns.find(r => r.name === 'sub');
    assert.equal(subNs.host, 'ns1.xn--espaa-rta.es.');
  });

  it('blocks creating a TXT record when #txt-value is empty instead of writing "undefined"', async () => {
    const txtForm = dom.createForm([
      { id: 'txt-name', value: '@', classes: ['hostname-validation'] },
      { id: 'txt-value', value: '', classes: ['txt-validation'] },
      { id: 'txt-ttl', value: '', classes: ['ttl-validation'] },
    ]);

    main.create_record_txt(txtForm.button);
    await new Promise(r => setImmediate(r));

    const currentZone = main.get_zone();
    assert.equal(currentZone.txt, undefined, 'Empty TXT record must not be added to zone');
    assert.equal(txtForm.button.disabled, true);
  });

  it('protects mandatory apex NS and glue A records in is_rr_deletable() and handles missing SOA safely', () => {
    const soa = { mname: 'ns.user.example.com.' };
    assert.equal(main.is_rr_deletable('ns', { name: '@', host: 'ns' }, soa), false);
    assert.equal(main.is_rr_deletable('ns', { host: 'ns' }, soa), false, 'Omitted name (@) must still be protected');
    assert.equal(
      main.is_rr_deletable('ns', { name: '@', host: 'ns.user.example.com.' }, soa),
      false,
      'FQDN host matching SOA mname must still be protected'
    );
    assert.equal(main.is_rr_deletable('a', { name: 'ns', ip: '192.0.2.1' }, soa), false);

    // Other records are deletable
    assert.equal(main.is_rr_deletable('a', { name: 'web', ip: '192.0.2.2' }, soa), true);
    assert.equal(main.is_rr_deletable('ns', { name: 'sub', host: 'ns2' }, soa), true);

    // Does not throw if soa is undefined
    assert.doesNotThrow(() => main.is_rr_deletable('ns', { name: '@', host: 'ns' }, undefined));
  });

  it('escapes HTML in table rows and updates #zone-file via textContent (preventing DOM XSS)', async () => {
    const xssZone = zonefile.parse(BASE_ZONE_TEXT);
    xssZone.txt = [{ name: '@', txt: '<script>alert("xss")</script>' }];

    await main.rebuild_zone(null, xssZone);

    assert.ok(
      !dom.tbody.innerHTML.includes('<script>'),
      'Table HTML must escape <script> tags in record values'
    );
    assert.ok(
      dom.tbody.innerHTML.includes('&lt;script&gt;'),
      'Table HTML must contain escaped &lt;script&gt;'
    );
    assert.ok(
      dom.zoneFileEl.textContent.includes('<script>alert(\\"xss\\")</script>'),
      '#zone-file must be updated via textContent'
    );
  });

  it('handles HTTP 401 string error detail in update_zonefile() without throwing TypeError', async () => {
    globalThis.fetch = async () => ({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Invalid user.' }),
    });

    await assert.rejects(
      async () => {
        await main.update_zonefile(BASE_ZONE_TEXT);
      },
      (err) => {
        assert.equal(err.success, false);
        assert.equal(err.message, 'Invalid user.');
        return true;
      }
    );
  });

  it('catches errors in delete_rr() when the server rejects a record deletion', async () => {
    const z = zonefile.parse(BASE_ZONE_TEXT);
    z.a.push({ name: 'web', ip: '192.0.2.50' });
    main.set_zone(z);
    main.rebuild_zone_table();

    globalThis.fetch = async () => ({
      ok: false,
      status: 400,
      json: async () => ({
        detail: { error: 'Bad zone file', message: 'NS has no address records' },
      }),
    });

    const deleteButton = {
      attributes: { rr_id: { nodeValue: String(z.a[1].id) } },
      closest: (sel) => (sel === 'tr' ? { querySelector: () => ({ innerText: 'A' }) } : null),
    };

    main.delete_rr(deleteButton);
    await new Promise(r => setImmediate(r));

    assert.equal(dom.alerts.length, 1, 'Error alert should be inserted when delete_rr fails');
    assert.equal(main.get_zone().a.length, 2, 'Failed deletion must not mutate active zone');
  });

  it('preserves #reset-error-msg element across multiple failed reset_zone() calls', async () => {
    globalThis.fetch = async () => ({
      ok: false,
      status: 500,
      text: async () => 'Internal Server Error',
    });

    main.reset_zone();
    await new Promise(r => setImmediate(r));
    assert.equal(dom.resetFooterDiv.classList.contains('d-none'), false);

    // Second failure must not throw TypeError from #reset-error-msg being overwritten
    main.reset_zone();
    await new Promise(r => setImmediate(r));
    assert.ok(
      dom.document.querySelector('#reset-error-msg') !== null,
      '#reset-error-msg span must not be destroyed on reset failure'
    );
  });

  it('allows deleting secondary ns A records while keeping the primary glue A record protected', () => {
    const z = zonefile.parse(BASE_ZONE_TEXT);
    z.a.push({ name: 'ns', ip: '192.0.2.99' });
    main.set_zone(z);

    assert.equal(main.is_rr_deletable('a', z.a[0], z.soa), false, 'Primary ns A record must remain protected');
    assert.equal(main.is_rr_deletable('a', z.a[1], z.soa), true, 'Secondary ns A record must be deletable');
  });

  it('renders CAA, SRV, PTR, SPF, and DS records in table view without rendering SOA in the table', () => {
    const z = zonefile.parse(BASE_ZONE_TEXT);
    z.caa = [{ name: '@', flags: 0, tag: 'issue', value: 'letsencrypt.org' }];
    z.srv = [{ name: '_sip._tcp', priority: 10, weight: 5, port: 5060, target: 'sip.user.example.com.' }];
    z.ptr = [{ name: '1', host: 'host.user.example.com.' }];
    z.spf = [{ name: '@', data: '"v=spf1 -all"' }];
    z.ds = [{ name: 'sub', key_tag: '12345', algorithm: '13', digest_type: '2', digest: 'ABCDEF' }];
    main.set_zone(z);
    main.rebuild_zone_table();

    assert.ok(dom.tbody.innerHTML.includes('CAA'), 'Table must render CAA records');
    assert.ok(dom.tbody.innerHTML.includes('letsencrypt.org'), 'Table must include CAA value');
    assert.ok(dom.tbody.innerHTML.includes('SRV'), 'Table must render SRV records');
    assert.ok(dom.tbody.innerHTML.includes('PTR'), 'Table must render PTR records');
    assert.ok(dom.tbody.innerHTML.includes('SPF'), 'Table must render SPF records');
    assert.ok(dom.tbody.innerHTML.includes('DS'), 'Table must render DS records');
    assert.ok(!dom.tbody.innerHTML.includes('>SOA<'), 'Table must not render SOA record row');
  });

  it('clears form inputs after successful record creation and supports SRV and CAA creation', async () => {
    const srvForm = dom.createForm([
      { id: 'srv-name', value: '_sip._tcp', classes: ['hostname-validation'] },
      { id: 'srv-priority', value: '10', classes: ['priority-validation'] },
      { id: 'srv-weight', value: '20', classes: ['priority-validation'] },
      { id: 'srv-port', value: '5060', classes: ['priority-validation'] },
      { id: 'srv-target', value: 'voip.españa.es.', classes: ['nameserver-validation'] },
      { id: 'srv-ttl', value: '120', classes: ['ttl-validation'] },
    ]);
    main.create_record_srv(srvForm.button);
    await new Promise(r => setImmediate(r));
    assert.equal(main.get_zone().srv[0].target, 'voip.xn--espaa-rta.es.');
    assert.equal(srvForm.inputs[0].value, '', 'Form input should be cleared after record creation');

    const caaForm = dom.createForm([
      { id: 'caa-name', value: '@', classes: ['hostname-validation'] },
      { id: 'caa-flags', value: '0', classes: ['priority-validation'] },
      { id: 'caa-tag', value: 'issue', classes: [] },
      { id: 'caa-value', value: 'letsencrypt.org', classes: ['txt-validation'] },
      { id: 'caa-ttl', value: '', classes: ['ttl-validation'] },
    ]);
    main.create_record_caa(caaForm.button);
    await new Promise(r => setImmediate(r));
    assert.equal(main.get_zone().caa[0].value, 'letsencrypt.org');
  });
});
