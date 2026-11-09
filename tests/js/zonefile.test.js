import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadDnsModules } from './helpers.js';

describe('Zonefile Parsing and Generation (zonefile.js)', () => {
  let zonefile;

  before(async () => {
    const mods = await loadDnsModules();
    zonefile = mods.zonefile;
  });

  it('parses and regenerates the default user zone template', () => {
    const raw = `$ORIGIN user.example.com.
$TTL 60

@  IN  SOA ns.user.example.com. admin.user.example.com. 1 60 60 60 60
@  IN  NS  ns
ns IN  A   192.0.2.1
`;
    const parsed = zonefile.parse(raw);
    assert.equal(parsed.$origin, 'user.example.com.');
    assert.equal(parsed.$ttl, '60');
    assert.deepEqual(parsed.soa, {
      name: '@',
      mname: 'ns.user.example.com.',
      rname: 'admin.user.example.com.',
      serial: 1,
      refresh: 60,
      retry: 60,
      expire: 60,
      minimum: 60,
    });
    assert.deepEqual(parsed.ns, [{ name: '@', host: 'ns' }]);
    assert.deepEqual(parsed.a, [{ name: 'ns', ip: '192.0.2.1' }]);

    const generated = zonefile.generate(parsed);
    const reparsed = zonefile.parse(generated);
    assert.deepEqual(reparsed, parsed);
  });

  it('does not corrupt $ORIGIN or SOA when origin/username contains "soa" (e.g. soares.example.com.)', () => {
    const raw = `$ORIGIN soares.example.com.
$TTL 60

@  IN  SOA ns.soares.example.com. admin.soares.example.com. 1 60 60 60 60
@  IN  NS  ns
ns IN  A   192.0.2.1
`;
    const z1 = zonefile.parse(raw);
    const gen1 = zonefile.generate(z1);
    const z2 = zonefile.parse(gen1);

    assert.equal(z2.$origin, 'soares.example.com.');
    assert.equal(z2.$ttl, '60');
    assert.ok(z2.soa, 'SOA record must not be lost when $ORIGIN contains "soa"');
    assert.equal(z2.soa.mname, 'ns.soares.example.com.');

    // Second round-trip must also succeed without throwing in processSOA
    const gen2 = zonefile.generate(z2);
    const z3 = zonefile.parse(gen2);
    assert.deepEqual(z3, z2);
  });

  it('does not swallow records when SOA has no parentheses and a later TXT record has parentheses', () => {
    const raw = `$ORIGIN user.example.com.
$TTL 60

@  IN  SOA ns.user.example.com. admin.user.example.com. 1 60 60 60 60
@  IN  NS  ns
ns IN  A   192.0.2.1
web IN A   192.0.2.2
@  IN  TXT "v=spf1 (comment with parens) -all"
`;
    const parsed = zonefile.parse(raw);
    assert.equal(parsed.ns?.length, 1, 'NS record must not be swallowed by flatten()');
    assert.equal(parsed.a?.length, 2, 'A records must not be swallowed by flatten()');
    assert.equal(parsed.txt?.length, 1, 'TXT record must not be swallowed by flatten()');
    assert.equal(parsed.soa.serial, 1);
  });

  it('parses multiline SOA records with parentheses and inline comments', () => {
    const raw = `$ORIGIN user.example.com.
$TTL 3600
@ IN SOA ns.user.example.com. admin.user.example.com. (
    2026110801 ; serial
    7200       ; refresh
    3600       ; retry
    1209600    ; expire
    3600       ; minimum
)
@ IN NS ns
ns IN A 192.0.2.1
`;
    const parsed = zonefile.parse(raw);
    assert.equal(parsed.soa.serial, 2026110801);
    assert.equal(parsed.soa.refresh, 7200);
    assert.equal(parsed.soa.retry, 3600);
    assert.equal(parsed.soa.expire, 1209600);
    assert.equal(parsed.soa.minimum, 3600);
  });

  it('quotes unquoted TXT values containing semicolons so DMARC/DKIM records are not truncated as comments', () => {
    const zone = {
      $origin: 'user.example.com.',
      $ttl: '60',
      soa: {
        name: '@',
        mname: 'ns.user.example.com.',
        rname: 'admin.user.example.com.',
        serial: 100,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60,
      },
      ns: [{ name: '@', host: 'ns' }],
      a: [{ name: 'ns', ip: '192.0.2.1' }],
      txt: [
        { name: '_dmarc', txt: 'v=DMARC1; p=reject; rua=mailto:dmarc@user.example.com' },
      ],
    };

    const generated = zonefile.generate(zone);
    assert.match(
      generated,
      /_dmarc\tIN\tTXT\t"v=DMARC1; p=reject; rua=mailto:dmarc@user\.example\.com"/
    );

    const reparsed = zonefile.parse(generated);
    assert.equal(
      reparsed.txt[0].txt,
      '"v=DMARC1; p=reject; rua=mailto:dmarc@user.example.com"'
    );
  });

  it('quotes unquoted TXT values with spaces and escapes internal double quotes', () => {
    const zone = {
      $origin: 'user.example.com.',
      $ttl: '60',
      soa: {
        name: '@',
        mname: 'ns.user.example.com.',
        rname: 'admin.user.example.com.',
        serial: 100,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60,
      },
      ns: [{ name: '@', host: 'ns' }],
      a: [{ name: 'ns', ip: '192.0.2.1' }],
      txt: [
        { name: '@', txt: 'v=spf1 mx a -all' },
        { name: 'quote', txt: 'hello "world"; test' },
      ],
    };

    const generated = zonefile.generate(zone);
    assert.match(generated, /@\tIN\tTXT\t"v=spf1 mx a -all"/);
    assert.match(generated, /quote\tIN\tTXT\t"hello \\"world\\"; test"/);

    const reparsed = zonefile.parse(generated);
    assert.equal(reparsed.txt.length, 2);
    assert.equal(reparsed.txt[0].txt, '"v=spf1 mx a -all"');
    assert.equal(reparsed.txt[1].txt, '"hello \\"world\\"; test"');
  });

  it('splits TXT records longer than 255 characters into <=255-byte quoted chunks for BIND compatibility', () => {
    const longDkim = 'v=DKIM1; k=rsa; p=' + 'M'.repeat(300);
    const zone = {
      $origin: 'user.example.com.',
      $ttl: '60',
      soa: {
        name: '@',
        mname: 'ns.user.example.com.',
        rname: 'admin.user.example.com.',
        serial: 100,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60,
      },
      ns: [{ name: '@', host: 'ns' }],
      a: [{ name: 'ns', ip: '192.0.2.1' }],
      txt: [
        { name: 'dkim._domainkey', txt: longDkim },
        { name: 'quoted._domainkey', txt: `"${longDkim}"` },
      ],
    };

    const generated = zonefile.generate(zone);
    const reparsed = zonefile.parse(generated);

    for (const rr of reparsed.txt) {
      const chunks = zonefile.splitArgs(rr.txt, null, true);
      assert.ok(chunks.length >= 2, 'Long TXT record must be split into multiple chunks');
      for (const chunk of chunks) {
        assert.ok(chunk.startsWith('"') && chunk.endsWith('"'), 'Each chunk must be quoted');
        const inner = chunk.slice(1, -1);
        assert.ok(inner.length <= 255, `Chunk inner length (${inner.length}) must be <= 255`);
      }
      const reassembled = chunks.map(c => c.slice(1, -1)).join('');
      assert.equal(reassembled, longDkim);
    }
  });

  it('does not corrupt output when TXT records contain JS replace patterns ($`, $&, $$, $1) or template placeholders ({zone}, {datetime})', () => {
    const trickyTxt = 'price $$100 prefix $` match $& suffix $\' and {zone} {datetime} {time} {srv}';
    const zone = {
      $origin: 'user.example.com.',
      $ttl: '60',
      soa: {
        name: '@',
        mname: 'ns.user.example.com.',
        rname: 'admin.user.example.com.',
        serial: 100,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60,
      },
      ns: [{ name: '@', host: 'ns' }],
      a: [{ name: 'ns', ip: '192.0.2.1' }],
      txt: [{ name: '@', txt: trickyTxt }],
    };

    const generated = zonefile.generate(zone);
    const reparsed = zonefile.parse(generated);
    assert.equal(reparsed.txt[0].txt, `"${trickyTxt}"`);
  });

  it('handles escaped double quotes and apostrophes in TXT records without breaking comment stripping or tokenization', () => {
    const raw = `; User's zone comment with an apostrophe
$ORIGIN user.example.com.
$TTL 60
@ IN SOA ns.user.example.com. admin.user.example.com. 1 60 60 60 60
@ IN NS ns ; admin's nameserver
ns IN A 192.0.2.1
@ IN TXT "v=test \\"quoted\\"; keep-after-semicolon"
sub IN TXT don't_treat_apostrophe_as_unclosed_quote ; trailing comment
`;
    const parsed = zonefile.parse(raw);
    assert.equal(parsed.ns[0].host, 'ns');
    assert.equal(parsed.txt[0].txt, '"v=test \\"quoted\\"; keep-after-semicolon"');
    assert.equal(parsed.txt[1].txt, "don't_treat_apostrophe_as_unclosed_quote");
  });

  it('inherits missing owner names from the immediately preceding record in the zonefile regardless of type', () => {
    const raw = `$ORIGIN user.example.com.
$TTL 60
@    IN SOA  ns.user.example.com. admin.user.example.com. 1 60 60 60 60
     IN NS   ns
ns   IN A    192.0.2.1
mail IN A    192.0.2.10
     IN AAAA 2001:db8::10
     IN MX   10 mail
     IN TXT  "v=spf1 a -all"
`;
    const parsed = zonefile.parse(raw);
    assert.equal(parsed.ns[0].name, '@');
    assert.equal(parsed.aaaa[0].name, 'mail');
    assert.equal(parsed.mx[0].name, 'mail');
    assert.equal(parsed.txt[0].name, 'mail');
  });

  it('supports both [TTL] [IN] <type> and [IN] [TTL] <type> as well as CRLF line endings', () => {
    const raw = [
      '$ORIGIN user.example.com.',
      '$TTL 60',
      '@ 300 IN SOA ns.user.example.com. admin.user.example.com. 1 60 60 60 60',
      '@ IN 300 NS ns',
      'ns 600 IN A 192.0.2.1',
      'www IN 120 CNAME ns',
      '',
    ].join('\r\n');

    const parsed = zonefile.parse(raw);
    assert.equal(parsed.soa.ttl, 300);
    assert.equal(parsed.ns[0].ttl, 300);
    assert.equal(parsed.a[0].ttl, 600);
    assert.equal(parsed.cname[0].ttl, 120);
    assert.equal(parsed.cname[0].alias, 'ns');
  });
});
