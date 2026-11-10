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

  it('requires both a valid new subdomain and acknowledgement checkbox before enabling change_origin() submission', async () => {
    const { inputs } = dom.createForm([{ id: 'new-origin-input', value: '' }]);
    const originInput = inputs[0];
    const suffixEl = { id: 'new-origin-root-suffix', textContent: '.' };
    const ackInput = dom.createInput({ id: 'change-origin-ack', value: '' });
    ackInput.checked = false;
    const submitBtn = { id: 'change-origin-submit', disabled: true };
    const errorFooter = { classList: dom.makeClassList(['modal-footer', 'd-none']) };
    const errorSpan = {
      id: 'change-origin-error-msg',
      textContent: '',
      closest: (sel) => (sel === 'div' ? errorFooter : null),
    };

    dom.elementsById.set('new-origin-input', originInput);
    dom.elementsById.set('new-origin-root-suffix', suffixEl);
    dom.elementsById.set('change-origin-ack', ackInput);
    dom.elementsById.set('change-origin-submit', submitBtn);
    dom.queryMap.set('#change-origin-error-msg', errorSpan);

    main.set_change_origin_listeners();
    assert.equal(suffixEl.textContent, '.example.com.');

    // 1. Valid input but checkbox unchecked -> submit button remains disabled
    originInput.value = 'españa';
    originInput.trigger('input');
    assert.equal(submitBtn.disabled, true, 'Submit button must remain disabled until acknowledgement is checked');

    // 2. Check acknowledgement -> submit button enabled
    ackInput.checked = true;
    ackInput.trigger('change');
    assert.equal(submitBtn.disabled, false, 'Submit button must be enabled when input is valid and checkbox is checked');

    // 3. Invalid input (current origin) -> submit button disabled again
    originInput.value = 'user';
    originInput.trigger('input');
    assert.equal(submitBtn.disabled, true, 'Submit button must be disabled when new origin equals current origin');

    // 4. Submit valid new origin -> sends POST /origin with Punycode subdomain and acknowledge: true
    originInput.value = 'MyZone';
    originInput.trigger('input');
    assert.equal(submitBtn.disabled, false);

    let capturedReq = null;
    let reloaded = false;
    dom.window.location.reload = () => { reloaded = true; };
    globalThis.fetch = async (url, opts) => {
      capturedReq = { url, opts };
      return { ok: true, json: async () => ({ status: 'updated' }) };
    };

    await main.change_origin();
    assert.equal(capturedReq.url, '/origin');
    assert.equal(capturedReq.opts.method, 'POST');
    assert.deepEqual(JSON.parse(capturedReq.opts.body), {
      subdomain: 'myzone',
      acknowledge: true,
    });
    assert.equal(reloaded, true);

    // 5. Server conflict error (409) -> displays error message in modal footer
    globalThis.fetch = async () => ({
      ok: false,
      status: 409,
      json: async () => ({
        detail: { error: 'Origin unavailable', message: 'Subdomain "myzone.example.com." is already taken.' },
      }),
    });

    await main.change_origin();
    assert.equal(errorFooter.classList.contains('d-none'), false);
    assert.match(errorSpan.textContent, /already taken/);
  });

  it('creates and edits SPF, DMARC, long 2048-bit DKIM TXT records, and two-CNAME DKIM rotation records via UI forms', async () => {
    const rsa2048Dkim =
      'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' +
      'M'.repeat(340) +
      'IDAQAB';

    // 1. Create SPF record at @
    const spfForm = dom.createForm([
      { id: 'txt-name', value: '@', classes: ['hostname-validation'] },
      { id: 'txt-value', value: 'v=spf1 mx a -all', classes: ['txt-validation'] },
      { id: 'txt-ttl', value: '300', classes: ['ttl-validation'] },
    ]);
    main.create_record_txt(spfForm.button);
    await new Promise(r => setImmediate(r));

    // 2. Create 2048-bit DKIM TXT record at default._domainkey
    spfForm.inputs[0].value = 'default._domainkey';
    spfForm.inputs[1].value = rsa2048Dkim;
    spfForm.inputs[2].value = '300';
    main.create_record_txt(spfForm.button);
    await new Promise(r => setImmediate(r));

    // 3. Create two CNAME-delegated DKIM selector records (selector1._domainkey and selector2._domainkey)
    const cnameForm = dom.createForm([
      { id: 'cname-name', value: 'selector1._domainkey', classes: ['cname-hostname-validation'] },
      { id: 'cname-alias', value: 'selector1-user-example-com._domainkey.example.onmicrosoft.com.', classes: ['hostname-validation'] },
      { id: 'cname-ttl', value: '300', classes: ['ttl-validation'] },
    ]);
    main.create_record_cname(cnameForm.button);
    await new Promise(r => setImmediate(r));

    cnameForm.inputs[0].value = 'selector2._domainkey';
    cnameForm.inputs[1].value = 'selector2-user-example-com._domainkey.example.onmicrosoft.com.';
    cnameForm.inputs[2].value = '300';
    main.create_record_cname(cnameForm.button);
    await new Promise(r => setImmediate(r));

    // Verify generated zonefile has the 2048-bit DKIM record split into 2 quoted chunks and both CNAMEs
    const reparsed = zonefile.parse(dom.zoneFileEl.textContent);
    assert.equal(reparsed.txt.length, 2);
    assert.equal(reparsed.txt[0].name, '@');
    assert.equal(reparsed.txt[0].txt, '"v=spf1 mx a -all"');
    assert.equal(reparsed.txt[1].name, 'default._domainkey');

    const dkimChunks = zonefile.splitArgs(reparsed.txt[1].txt, null, true);
    assert.equal(dkimChunks.length, 2);
    assert.equal(dkimChunks.map(c => c.slice(1, -1)).join(''), rsa2048Dkim);

    assert.equal(reparsed.cname.length, 2);
    assert.equal(reparsed.cname[0].name, 'selector1._domainkey');
    assert.equal(reparsed.cname[1].name, 'selector2._domainkey');

    // Simulate reload from zonefile (where DKIM TXT is stored as 2 quoted chunks) and edit it via edit_rr()
    main.set_zone(reparsed);
    main.rebuild_zone_table();
    const dkimRrId = main.get_zone().txt[1].id;
    const editBtn = {
      attributes: { rr_id: { nodeValue: String(dkimRrId) } },
      closest: (sel) => (sel === 'tr' ? { querySelector: () => ({ innerText: 'TXT' }) } : null),
    };
    main.edit_rr(editBtn);
    assert.equal(spfForm.inputs[0].value, 'default._domainkey');
    assert.equal(spfForm.inputs[1].value, reparsed.txt[1].txt);

    // Update the edited DKIM record with a new 4096-bit key (3 chunks)
    const rsa4096Dkim =
      'v=DKIM1; k=rsa; p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA' +
      'N'.repeat(684) +
      'IDAQAB';
    spfForm.inputs[1].value = rsa4096Dkim;
    main.create_record_txt(spfForm.button);
    await new Promise(r => setImmediate(r));

    const afterEdit = zonefile.parse(dom.zoneFileEl.textContent);
    assert.equal(afterEdit.txt.length, 2, 'Editing must update the existing DKIM record in place');
    const updatedChunks = zonefile.splitArgs(afterEdit.txt[1].txt, null, true);
    assert.equal(updatedChunks.length, 3);
    assert.equal(updatedChunks.map(c => c.slice(1, -1)).join(''), rsa4096Dkim);
  });

  it('truncates record values longer than 50 characters with ... and show more/less toggle button', () => {
    // 1. Strings <= 50 chars should be displayed directly without truncation or buttons
    const shortText = 'v=spf1 mx -all';
    assert.equal(main.format_record_value(shortText), 'v=spf1 mx -all');

    const exact50Chars = 'a'.repeat(50);
    assert.equal(main.format_record_value(exact50Chars), 'a'.repeat(50));

    // 2. Strings > 50 chars should be truncated to 50 chars with ... and show more button
    const long51Chars = 'b'.repeat(51);
    const formatted51 = main.format_record_value(long51Chars);
    assert.ok(formatted51.includes('record-value-container'));
    assert.ok(formatted51.includes('<span>' + 'b'.repeat(50) + '</span>...'));
    assert.ok(formatted51.includes('>show more</button>'));
    assert.ok(formatted51.includes('<span>' + 'b'.repeat(51) + '</span>'));
    assert.ok(formatted51.includes('>show less</button>'));
    assert.ok(formatted51.includes('d-none'));

    // 3. XSS prevention in both short preview and full view
    const xssLong = '<script>' + 'x'.repeat(45) + '</script>';
    const formattedXss = main.format_record_value(xssLong);
    assert.ok(!formattedXss.includes('<script>'));
    assert.ok(formattedXss.includes('&lt;script&gt;'));

    // 4. Null / undefined / empty string handling
    assert.equal(main.format_record_value(null), '');
    assert.equal(main.format_record_value(undefined), '');
    assert.equal(main.format_record_value(''), '');
  });

  it('toggle_record_value toggles between collapsed short view and full view', () => {
    let focusedBtn = null;
    const makeBtn = (label) => ({
      focus: () => { focusedBtn = label; },
    });
    const shortBtn = makeBtn('show more');
    const fullBtn = makeBtn('show less');

    const shortClassList = new Set();
    const fullClassList = new Set(['d-none']);

    const shortEl = {
      classList: {
        contains: (c) => shortClassList.has(c),
        add: (c) => shortClassList.add(c),
        remove: (c) => shortClassList.delete(c),
      },
      querySelector: (sel) => (sel === '.record-toggle-btn' ? shortBtn : null),
    };

    const fullEl = {
      classList: {
        contains: (c) => fullClassList.has(c),
        add: (c) => fullClassList.add(c),
        remove: (c) => fullClassList.delete(c),
      },
      querySelector: (sel) => (sel === '.record-toggle-btn' ? fullBtn : null),
    };

    const container = {
      querySelector: (sel) => {
        if (sel === '.record-value-short') return shortEl;
        if (sel === '.record-value-full') return fullEl;
        return null;
      },
    };

    const buttonInShort = {
      closest: (sel) => (sel === '.record-value-container' ? container : null),
    };
    const buttonInFull = {
      closest: (sel) => (sel === '.record-value-container' ? container : null),
    };

    // Initially short is visible, full is d-none
    assert.equal(shortClassList.has('d-none'), false);
    assert.equal(fullClassList.has('d-none'), true);

    // Click 'show more' -> expands
    main.toggle_record_value(buttonInShort);
    assert.equal(shortClassList.has('d-none'), true, 'short view must have d-none added');
    assert.equal(fullClassList.has('d-none'), false, 'full view must have d-none removed');
    assert.equal(focusedBtn, 'show less', 'focus must move to show less button');

    // Click 'show less' -> collapses
    main.toggle_record_value(buttonInFull);
    assert.equal(shortClassList.has('d-none'), false, 'short view must have d-none removed');
    assert.equal(fullClassList.has('d-none'), true, 'full view must have d-none added');
    assert.equal(focusedBtn, 'show more', 'focus must move to show more button');
  });

  it('renders long TXT records truncated in zone table and preserves full text on edit', () => {
    const txtForm = dom.createForm([
      { id: 'txt-name', value: '', classes: ['hostname-validation'] },
      { id: 'txt-value', value: '', classes: ['txt-validation'] },
      { id: 'txt-ttl', value: '', classes: ['ttl-validation'] },
    ]);

    const z = zonefile.parse(BASE_ZONE_TEXT);
    const longTxt = 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3123456789012345678901234567890';
    const shortTxt = 'v=spf1 -all';
    z.txt = [
      { name: 'default._domainkey', txt: longTxt },
      { name: '@', txt: shortTxt },
    ];
    main.set_zone(z);
    main.rebuild_zone_table();

    // Table tbody should contain the truncated 50 chars of longTxt followed by ... and 'show more'
    const truncatedPrefix = longTxt.slice(0, 50);
    assert.ok(dom.tbody.innerHTML.includes(truncatedPrefix), 'Table must contain 50-char prefix');
    assert.ok(dom.tbody.innerHTML.includes(`${truncatedPrefix}</span>...`), 'Table must display ... after 50 chars');
    assert.ok(dom.tbody.innerHTML.includes('show more'), 'Table must contain "show more" button for long record');
    assert.ok(dom.tbody.innerHTML.includes('show less'), 'Table must contain hidden "show less" button for long record');

    // Short TXT record should NOT have show more button
    assert.ok(dom.tbody.innerHTML.includes(shortTxt));
    const shortRowMatch = dom.tbody.innerHTML.includes(`<span>${shortTxt}</span>...`);
    assert.equal(shortRowMatch, false, 'Short record must not be truncated with ...');

    // Edit the long TXT record and verify full text is populated into the form
    const editBtn = {
      attributes: { rr_id: { nodeValue: String(z.txt[0].id) } },
      closest: (sel) => (sel === 'tr' ? { querySelector: () => ({ innerText: 'TXT' }) } : null),
    };
    main.edit_rr(editBtn);
    assert.equal(txtForm.inputs[1].value, longTxt, 'Editing must load the full un-truncated TXT into the form');
  });
});
