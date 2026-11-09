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

  describe('Mail Server SPF, DKIM (varying key sizes & formats), and DMARC', () => {
    const baseZone = () => ({
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
    });

    it('handles Ed25519, RSA-1024, RSA-2048, and RSA-4096 DKIM keys with appropriate <=255-byte chunk counts', () => {
      // 1. Ed25519 (~74 chars -> 1 chunk)
      const ed25519Dkim = 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=';
      // 2. RSA-1024 minimal (~234 chars -> 1 chunk, <= 255 bytes)
      const rsa1024B64 = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5N3lnvvrYgPCRSoqn+awTpE+iGYcKBPpo8HHbcFfCIIV10Hwo4PhCoGZSaKVHOjDm4yefKXhQjM7iKzEPuBatE7O47hAx1CJpNuIdLxhILSbEmbMxJrJAG0HZVn8z6EAoOHZNaPHmK2h4UUrjOG8zA5BHfzJf7tGwI+K619fFUwIDAQAB';
      const rsa1024Dkim = `v=DKIM1; k=rsa; p=${rsa1024B64}`;
      // 3. RSA-1024 with extra service/hash/flag tags (~262 chars -> crosses 255-byte limit -> 2 chunks)
      const rsa1024TaggedDkim = `v=DKIM1; h=sha256; k=rsa; s=email; t=y:s; p=${rsa1024B64}`;
      // 4. RSA-2048 (~410 chars -> 2 chunks)
      const rsa2048B64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' + 'A'.repeat(340) + 'IDAQAB';
      const rsa2048Dkim = `v=DKIM1; k=rsa; p=${rsa2048B64}`;
      // 5. RSA-4096 (~754 chars -> 3 chunks)
      const rsa4096B64 = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA' + 'B'.repeat(684) + 'IDAQAB';
      const rsa4096Dkim = `v=DKIM1; k=rsa; p=${rsa4096B64}`;

      const zone = baseZone();
      zone.txt = [
        { name: 'ed._domainkey', txt: ed25519Dkim },
        { name: 'rsa1024._domainkey', txt: rsa1024Dkim },
        { name: 'rsa1024tag._domainkey', txt: rsa1024TaggedDkim },
        { name: 'rsa2048._domainkey', txt: rsa2048Dkim },
        { name: 'rsa4096._domainkey', txt: rsa4096Dkim },
      ];

      const generated = zonefile.generate(zone);
      const reparsed = zonefile.parse(generated);
      assert.equal(reparsed.txt.length, 5);

      const expectedCases = [
        { name: 'ed._domainkey', expectedChunks: 1, fullValue: ed25519Dkim },
        { name: 'rsa1024._domainkey', expectedChunks: 1, fullValue: rsa1024Dkim },
        { name: 'rsa1024tag._domainkey', expectedChunks: 2, fullValue: rsa1024TaggedDkim },
        { name: 'rsa2048._domainkey', expectedChunks: 2, fullValue: rsa2048Dkim },
        { name: 'rsa4096._domainkey', expectedChunks: 3, fullValue: rsa4096Dkim },
      ];

      expectedCases.forEach((tc, idx) => {
        const rr = reparsed.txt[idx];
        assert.equal(rr.name, tc.name);
        const chunks = zonefile.splitArgs(rr.txt, null, true);
        assert.equal(
          chunks.length,
          tc.expectedChunks,
          `Expected ${tc.name} (${tc.fullValue.length} chars) to produce ${tc.expectedChunks} chunk(s), got ${chunks.length}`
        );
        for (const chunk of chunks) {
          assert.ok(chunk.startsWith('"') && chunk.endsWith('"'));
          assert.ok(chunk.length - 2 <= 255, `Chunk length (${chunk.length - 2}) must be <= 255`);
        }
        const reassembled = chunks.map(c => c.slice(1, -1)).join('');
        assert.equal(reassembled, tc.fullValue);
      });
    });

    it('handles pre-split multi-string DKIM keys and opendkim-genkey parenthesized format', () => {
      const keyPart1 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' + 'X'.repeat(180);
      const keyPart2 = 'Y'.repeat(160) + 'IDAQAB';
      const expectedFull = `v=DKIM1; h=sha256; k=rsa; p=${keyPart1}${keyPart2}`;

      // 1. Pre-split two quoted strings separated by space
      const preSplitSpace = `"v=DKIM1; h=sha256; k=rsa; p=${keyPart1}" "${keyPart2}"`;
      // 2. Pre-split adjacent quoted strings without space
      const preSplitAdjacent = `"v=DKIM1; h=sha256; k=rsa; p=${keyPart1}""${keyPart2}"`;
      // 3. opendkim-genkey parenthesized format with trailing comment
      const opendkimFormat = `( "v=DKIM1; h=sha256; k=rsa; "\n\t  "p=${keyPart1}"\n\t  "${keyPart2}" )  ; ----- DKIM key default for user.example.com`;
      // 4. Edited two-chunk record where the first chunk was modified to exceed 255 chars
      const editedOver255 = `"v=DKIM1; h=sha256; k=rsa; p=${keyPart1}${'Z'.repeat(40)}" "${keyPart2}"`;
      const expectedEditedFull = `v=DKIM1; h=sha256; k=rsa; p=${keyPart1}${'Z'.repeat(40)}${keyPart2}`;

      const zone = baseZone();
      zone.txt = [
        { name: 's1._domainkey', txt: preSplitSpace },
        { name: 's2._domainkey', txt: preSplitAdjacent },
        { name: 's3._domainkey', txt: opendkimFormat },
        { name: 's4._domainkey', txt: editedOver255 },
      ];

      const generated = zonefile.generate(zone);
      const reparsed = zonefile.parse(generated);

      for (let i = 0; i < 3; i++) {
        const chunks = zonefile.splitArgs(reparsed.txt[i].txt, null, true);
        for (const chunk of chunks) {
          assert.ok(chunk.startsWith('"') && chunk.endsWith('"'));
          assert.ok(chunk.length - 2 <= 255);
        }
        assert.equal(chunks.map(c => c.slice(1, -1)).join(''), expectedFull);
      }

      // Check the edited >255 chunk was cleanly re-chunked into 2 chunks of <= 255 chars
      const s4Chunks = zonefile.splitArgs(reparsed.txt[3].txt, null, true);
      assert.equal(s4Chunks.length, 2);
      assert.equal(s4Chunks[0].length - 2, 255);
      assert.equal(s4Chunks.map(c => c.slice(1, -1)).join(''), expectedEditedFull);
    });

    it('parses multiline parenthesized TXT records (e.g. opendkim-genkey output) directly from a zonefile', () => {
      const part1 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' + 'K'.repeat(200);
      const part2 = 'L'.repeat(140) + 'IDAQAB';
      const rawZone = `$ORIGIN user.example.com.
$TTL 60
@ IN SOA ns.user.example.com. admin.user.example.com. (
    2026110901 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    60         ; minimum
)
@ IN NS ns
ns IN A 192.0.2.1
default._domainkey IN TXT ( "v=DKIM1; h=sha256; k=rsa; "
    "p=${part1}"
    "${part2}" ) ; ----- DKIM key default for user.example.com
@ IN TXT "v=spf1 mx -all"
`;
      const parsed = zonefile.parse(rawZone);
      assert.equal(parsed.txt.length, 2);
      assert.equal(parsed.txt[0].name, 'default._domainkey');
      const dkimChunks = zonefile.splitArgs(parsed.txt[0].txt, null, true);
      assert.equal(dkimChunks.length, 3);
      assert.equal(
        dkimChunks.map(c => c.slice(1, -1)).join(''),
        `v=DKIM1; h=sha256; k=rsa; p=${part1}${part2}`
      );
      assert.equal(parsed.txt[1].name, '@');
      assert.equal(parsed.txt[1].txt, '"v=spf1 mx -all"');
    });

    it('handles long SPF records (>255 chars) and multiple coexisting TXT records at apex (@)', () => {
      const longSpf =
        'v=spf1 mx a ip4:192.0.2.0/24 ip4:198.51.100.0/24 ip4:203.0.113.0/24 ip6:2001:db8::/32 ' +
        'include:_spf.google.com include:spf.protection.outlook.com ' +
        'include:amazonses.com include:mailgun.org include:sendgrid.net ' +
        'include:spf.messagingengine.com include:_spf.protonmail.ch include:servers.mcsv.net ~all';
      assert.ok(longSpf.length > 255, 'Test SPF string must exceed 255 characters');

      const zone = baseZone();
      zone.txt = [
        { name: '@', txt: longSpf },
        { name: '@', txt: 'google-site-verification=abc123xyz789' },
        { name: '_dmarc', txt: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@user.example.com' },
      ];

      const generated = zonefile.generate(zone);
      const reparsed = zonefile.parse(generated);
      assert.equal(reparsed.txt.length, 3);

      const spfChunks = zonefile.splitArgs(reparsed.txt[0].txt, null, true);
      assert.equal(spfChunks.length, 2);
      assert.ok(spfChunks.every(c => c.length - 2 <= 255));
      assert.equal(spfChunks.map(c => c.slice(1, -1)).join(''), longSpf);

      assert.equal(reparsed.txt[1].name, '@');
      assert.equal(reparsed.txt[1].txt, '"google-site-verification=abc123xyz789"');
      assert.equal(reparsed.txt[2].name, '_dmarc');
    });
  });
});
