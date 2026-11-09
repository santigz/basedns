import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadDnsModules, createMockDom, installGlobalDom } from './helpers.js';

describe('Form Input Validations & SOA Serial Logic (main.js)', () => {
  let main;
  let dom;

  before(async () => {
    const mods = await loadDnsModules();
    main = mods.main;
    dom = mods.dom;
  });

  describe('next_soa_serial()', () => {
    it('returns a monotonically increasing serial even when called multiple times in the same second', () => {
      const s1 = main.next_soa_serial(1);
      const s2 = main.next_soa_serial(s1);
      const s3 = main.next_soa_serial(s2);
      assert.ok(s2 > s1, `Expected s2 (${s2}) > s1 (${s1})`);
      assert.ok(s3 > s2, `Expected s3 (${s3}) > s2 (${s2})`);
    });

    it('increments properly when existing serial is in YYYYMMDDnn format (> Unix epoch seconds)', () => {
      const dateSerial = 2026110801;
      const next = main.next_soa_serial(dateSerial);
      assert.equal(next, dateSerial + 1);
    });
  });

  describe('validate_ipv4()', () => {
    it('accepts valid IPv4 addresses', () => {
      for (const ip of ['0.0.0.0', '127.0.0.1', '192.0.2.10', '255.255.255.255']) {
        assert.equal(main.validate_ipv4(ip), true, `Expected ${ip} to be valid`);
      }
    });

    it('rejects IPv4 addresses with leading zeros (rejected by BIND named-checkzone)', () => {
      for (const ip of ['192.168.001.1', '010.0.0.1', '1.2.3.00', '1.2.03.4']) {
        assert.equal(main.validate_ipv4(ip), false, `Expected ${ip} with leading zeros to be rejected`);
      }
    });

    it('rejects malformed or out-of-range IPv4 addresses', () => {
      for (const ip of ['', '256.0.0.1', '1.2.3.256', '1.2.3', '1.2.3.4.5', '1.2.3.a', ' 1.2.3.4 ']) {
        assert.equal(main.validate_ipv4(ip), false, `Expected ${ip} to be rejected`);
      }
    });
  });

  describe('validate_ipv6()', () => {
    it('accepts valid IPv6 addresses', () => {
      for (const ip of [
        '::1',
        '2001:db8::1',
        '2001:db8:0:0:1:0:0:1',
        'fe80::1ff:fe23:4567:890a',
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      ]) {
        assert.equal(main.validate_ipv6(ip), true, `Expected ${ip} to be valid`);
      }
    });

    it('rejects IPv6 addresses with %zone_id suffixes (rejected by BIND in AAAA records)', () => {
      for (const ip of ['fe80::1%eth0', 'fe80::1%1', '2001:db8::1%lo']) {
        assert.equal(main.validate_ipv6(ip), false, `Expected ${ip} with zone index to be rejected`);
      }
    });

    it('rejects invalid IPv6 strings', () => {
      for (const ip of ['', '2001:db8::gggg', '12345::1', '192.0.2.1', '2001:db8:::1']) {
        assert.equal(main.validate_ipv6(ip), false, `Expected ${ip} to be rejected`);
      }
    });
  });

  describe('Hostname, CNAME Hostname & Nameserver Validations', () => {
    const checkValidator = (validatorFn, value, badInput = false) => {
      const { inputs } = dom.createForm([{ id: 'test-input', value, badInput }]);
      validatorFn(inputs[0]);
      return !inputs[0].classList.contains('is-invalid');
    };

    it('accepts valid relative, subdomain, wildcard, underscore, and IDN hostnames', () => {
      for (const name of [
        '@',
        'www',
        'sub.domain',
        'host-1',
        '123',
        '*',
        '*.sub',
        '_dmarc',
        'default._domainkey',
        'selector-1._domainkey',
        'google._domainkey.mail',
        '_smtp._tls',
        '_mta-sts',
        'españa',
      ]) {
        assert.equal(
          checkValidator(main.validate_hostname, name),
          true,
          `Expected "${name}" to be valid in validate_hostname`
        );
      }
    });

    it('accepts DKIM selector hostnames and external targets for CNAME-delegated DKIM (e.g. two-CNAME rotation)', () => {
      for (const selector of ['selector1._domainkey', 'selector2._domainkey', 's1._domainkey.sub']) {
        assert.equal(
          checkValidator(main.validate_cname_hostname, selector),
          true,
          `Expected DKIM CNAME selector "${selector}" to be valid`
        );
      }
      for (const target of [
        'selector1-user-example-com._domainkey.example.onmicrosoft.com.',
        's1.domainkey.u12345.wl.sendgrid.net.',
        'abc123.dkim.amazonses.com.',
      ]) {
        assert.equal(
          checkValidator(main.validate_hostname, target),
          true,
          `Expected DKIM CNAME target "${target}" to be valid`
        );
      }
    });

    it('rejects invalid DNS hostnames (embedded @, dots, hyphens at ends, spaces, special chars)', () => {
      for (const bad of [
        '',
        '   ',
        'a b',
        'a\tb',
        'user@host',
        'a@b@c',
        '@@',
        '.',
        '..',
        '.leadingdot',
        'double..dot',
        '-leadinghyphen',
        'trailinghyphen-',
        'sub.-bad.com',
        'semi;colon',
        'quote"char',
        'paren(char)',
        'a'.repeat(64),
      ]) {
        assert.equal(
          checkValidator(main.validate_hostname, bad),
          false,
          `Expected "${bad}" to be rejected by validate_hostname`
        );
      }
    });

    it('rejects "@" for CNAME owner name and NS nameserver target', () => {
      assert.ok(
        typeof main.validate_cname_hostname === 'function',
        'validate_cname_hostname must be defined to prevent @ on CNAME'
      );
      assert.equal(
        checkValidator(main.validate_cname_hostname, '@'),
        false,
        '"@" must be rejected for CNAME owner name (conflicts with SOA/NS at zone apex)'
      );
      assert.equal(
        checkValidator(main.validate_cname_hostname, 'www'),
        true,
        '"www" must be allowed for CNAME owner name'
      );
      assert.equal(
        checkValidator(main.validate_nameserver, '@'),
        false,
        '"@" must be rejected for NS nameserver target'
      );
      assert.equal(
        checkValidator(main.validate_nameserver, '-badns'),
        false,
        'Invalid DNS labels must be rejected for NS nameserver target'
      );
    });

    it('populates .invalid-feedback with the specific reason why a DNS name is invalid', () => {
      const getFeedback = (validatorFn, value) => {
        const { inputs } = dom.createForm([{ id: 'test-input', value }]);
        validatorFn(inputs[0]);
        return inputs[0].feedbackEl.textContent;
      };

      assert.match(getFeedback(main.validate_hostname, ''), /empty/i);
      assert.match(getFeedback(main.validate_hostname, 'host name'), /space/i);
      assert.match(getFeedback(main.validate_hostname, 'user@host'), /"@"/);
      assert.match(getFeedback(main.validate_hostname, '.'), /single dot/i);
      assert.match(getFeedback(main.validate_hostname, '.leading'), /start with a dot/i);
      assert.match(getFeedback(main.validate_hostname, 'double..dot'), /consecutive dots/i);
      assert.match(getFeedback(main.validate_hostname, '-leading'), /hyphen/i);
      assert.match(getFeedback(main.validate_hostname, 'trailing-'), /hyphen/i);
      assert.match(getFeedback(main.validate_hostname, 'a'.repeat(64)), /63 characters/i);
      assert.match(getFeedback(main.validate_hostname, ('a'.repeat(50) + '.').repeat(6)), /253 characters/i);
      assert.match(getFeedback(main.validate_hostname, 'sub.*.example'), /leftmost label/i);
      assert.match(getFeedback(main.validate_hostname, 'bad;char'), /Invalid character ";"/i);
      assert.match(getFeedback(main.validate_cname_hostname, '@'), /not allowed for CNAME/i);
      assert.match(getFeedback(main.validate_nameserver, '@'), /not allowed as a target/i);
    });

    it('clears .is-invalid appearance when the user deletes all characters back to an empty input', () => {
      const { inputs } = dom.createForm([
        { id: 'a-name', value: '-badhost', classes: ['hostname-validation'] },
      ]);
      dom.queryAllMap.set('.hostname-validation', inputs);
      main.set_input_validations();

      inputs[0].trigger('input');
      assert.equal(inputs[0].classList.contains('is-invalid'), true);

      inputs[0].value = '';
      inputs[0].trigger('input');
      assert.equal(inputs[0].classList.contains('is-invalid'), false, 'Emptied input should return to neutral non-invalid state');
    });
  });

  describe('validate_ttl()', () => {
    const checkTtl = (value, badInput = false) => {
      const { inputs } = dom.createForm([{ id: 'test-ttl', value, badInput }]);
      main.validate_ttl(inputs[0]);
      return !inputs[0].classList.contains('is-invalid');
    };

    it('accepts empty TTL (default) and valid integers >= 60', () => {
      assert.equal(checkTtl(''), true);
      assert.equal(checkTtl('60'), true);
      assert.equal(checkTtl('3600'), true);
      assert.equal(checkTtl('86400'), true);
    });

    it('rejects TTL < 60, floats, scientific notation, trailing text, and badInput', () => {
      for (const bad of ['0', '59', '-60', '60.5', '60e1', '1e2', '60abc', 'abc']) {
        assert.equal(checkTtl(bad), false, `Expected TTL "${bad}" to be rejected`);
      }
      assert.equal(checkTtl('', true), false, 'Expected badInput on number input to be rejected');
    });
  });

  describe('validate_priority()', () => {
    const checkPriority = (value, badInput = false) => {
      const { inputs } = dom.createForm([{ id: 'test-prio', value, badInput }]);
      main.validate_priority(inputs[0]);
      return !inputs[0].classList.contains('is-invalid');
    };

    it('accepts valid 16-bit unsigned integers (0..65535)', () => {
      assert.equal(checkPriority('0'), true);
      assert.equal(checkPriority('10'), true);
      assert.equal(checkPriority('65535'), true);
    });

    it('rejects empty, negative, float, scientific notation, > 65535, and badInput', () => {
      for (const bad of ['', '-1', '-10', '10.5', '1e2', '65536', '100000', 'abc']) {
        assert.equal(checkPriority(bad), false, `Expected MX priority "${bad}" to be rejected`);
      }
      assert.equal(checkPriority('', true), false, 'Expected badInput on priority input to be rejected');
    });
  });

  describe('validate_txt()', () => {
    it('requires a non-empty TXT value', () => {
      assert.ok(typeof main.validate_txt === 'function', 'validate_txt must be defined');
      const { inputs } = dom.createForm([{ id: 'txt-value', value: '', classes: ['txt-validation'] }]);
      main.validate_input(inputs[0]);
      assert.equal(inputs[0].classList.contains('is-invalid'), true, 'Empty TXT value must be marked invalid');

      inputs[0].value = 'v=spf1 -all';
      main.validate_input(inputs[0]);
      assert.equal(inputs[0].classList.contains('is-invalid'), false, 'Non-empty TXT value must be valid');
    });
  });

  describe('get_origin_subdomain_error()', () => {
    it('accepts valid single-label DNS subdomains including IDN labels', () => {
      for (const sub of ['myproject', 'zone-1', '123', 'a', 'españa', 'MyZone']) {
        assert.equal(
          main.get_origin_subdomain_error(sub, 'user.example.com.'),
          null,
          `Expected subdomain "${sub}" to be valid`
        );
      }
    });

    it('rejects empty, multi-label (dots), @, *, underscores, hyphens at ends, >63 chars, reserved "ns", and current origin', () => {
      for (const bad of [
        '',
        '   ',
        'my zone',
        'sub.domain',
        'myzone.',
        '.myzone',
        '@',
        'user@zone',
        '*',
        '*.zone',
        'my_zone',
        '-leading',
        'trailing-',
        'a'.repeat(64),
        'ns',
        'NS',
        'user',
        'USER',
      ]) {
        assert.notEqual(
          main.get_origin_subdomain_error(bad, 'user.example.com.'),
          null,
          `Expected subdomain "${bad}" to be rejected`
        );
      }
    });
  });
});
