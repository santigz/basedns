import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '../..');

/**
 * Loads `punycode`, `zonefile`, and `main` modules.
 *
 * - By default, uses native ES Module `import()` against `static/js/*.js`.
 * - If `GIT_COMMIT` is set (e.g. `GIT_COMMIT=HEAD~1`) or if the target files in
 *   `static/js/` are from an older commit before `export` statements were added,
 *   loads the files from that commit/directory so the exact same test suite can
 *   be executed against legacy commits.
 */
export async function loadDnsModules(customDom = null) {
  const dom = customDom || createMockDom();
  installGlobalDom(dom);

  const gitCommit = process.env.GIT_COMMIT;
  const jsDir = path.join(ROOT_DIR, 'static/js');

  if (!gitCommit) {
    const zonefileContent = fs.readFileSync(path.join(jsDir, 'zonefile.js'), 'utf8');
    const mainContent = fs.readFileSync(path.join(jsDir, 'main.js'), 'utf8');
    const isNativeEsm = /\bexport\s+\{/.test(zonefileContent) && /\bexport\s+\{/.test(mainContent);

    if (isNativeEsm) {
      const punycodeMod = await import(pathToFileURL(path.join(jsDir, 'punycode.min.js')).href);
      const zonefileMod = await import(pathToFileURL(path.join(jsDir, 'zonefile.js')).href);
      const mainMod = await import(pathToFileURL(path.join(jsDir, 'main.js')).href);
      return {
        punycode: punycodeMod,
        zonefile: zonefileMod,
        main: mainMod,
        dom,
        isLegacy: false,
      };
    }
  }

  // Fallback for testing a previous git commit (either via GIT_COMMIT=<rev> or git checkout <rev> -- static/js)
  const readSource = (filename) => {
    if (gitCommit) {
      return execFileSync('git', ['show', `${gitCommit}:static/js/${filename}`], {
        cwd: ROOT_DIR,
        encoding: 'utf8',
      });
    }
    return fs.readFileSync(path.join(jsDir, filename), 'utf8');
  };

  const stripEsmSyntax = (code) =>
    code
      .replace(/^\s*import\s+[\s\S]*?from\s+['"][^'"]+['"];?\s*$/gm, '')
      .replace(/^\s*export\s+\{[\s\S]*?\};?\s*$/gm, '');

  const punycodeSrc = stripEsmSyntax(readSource('punycode.min.js'));
  const zonefileSrc = stripEsmSyntax(readSource('zonefile.js'));
  const mainSrc = stripEsmSyntax(readSource('main.js'));

  const sandbox = {
    console,
    Date,
    Math,
    JSON,
    Object,
    Array,
    String,
    Number,
    Boolean,
    RegExp,
    Error,
    TypeError,
    RangeError,
    SyntaxError,
    Promise,
    parseInt,
    parseFloat,
    isNaN,
    isFinite,
    structuredClone,
    setTimeout: dom.setTimeout,
    clearTimeout: dom.clearTimeout,
    fetch: (...args) => globalThis.fetch(...args),
    window: dom.window,
    document: dom.document,
    navigator: dom.navigator,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  const exposeSnippet = `
    globalThis.__exports = {
      punycode: {
        punycode: typeof punycode !== 'undefined' ? punycode : undefined,
        toASCII: typeof toASCII !== 'undefined' ? toASCII : undefined,
        toUnicode: typeof toUnicode !== 'undefined' ? toUnicode : undefined,
        encode: typeof encode !== 'undefined' ? encode : undefined,
        decode: typeof decode !== 'undefined' ? decode : undefined,
      },
      zonefile: {
        generate: typeof generate !== 'undefined' ? generate : undefined,
        parse: typeof parse !== 'undefined' ? parse : undefined,
        removeComments: typeof removeComments !== 'undefined' ? removeComments : undefined,
        flatten: typeof flatten !== 'undefined' ? flatten : undefined,
        normalizeRR: typeof normalizeRR !== 'undefined' ? normalizeRR : undefined,
        parseRRs: typeof parseRRs !== 'undefined' ? parseRRs : undefined,
        splitArgs: typeof splitArgs !== 'undefined' ? splitArgs : undefined,
        formatTxtData: typeof formatTxtData !== 'undefined' ? formatTxtData : undefined,
        chunkTxtString: typeof chunkTxtString !== 'undefined' ? chunkTxtString : undefined,
      },
      main: {
        escape_html: typeof escape_html !== 'undefined' ? escape_html : undefined,
        safe_to_unicode: typeof safe_to_unicode !== 'undefined' ? safe_to_unicode : undefined,
        safe_to_ascii: typeof safe_to_ascii !== 'undefined' ? safe_to_ascii : undefined,
        ttl_html: typeof ttl_html !== 'undefined' ? ttl_html : undefined,
        format_record_value: typeof format_record_value !== 'undefined' ? format_record_value : undefined,
        toggle_record_value: typeof toggle_record_value !== 'undefined' ? toggle_record_value : undefined,
        zone_table_row: typeof zone_table_row !== 'undefined' ? zone_table_row : undefined,
        fix_ttl_placeholder: typeof fix_ttl_placeholder !== 'undefined' ? fix_ttl_placeholder : undefined,
        current_date_id: typeof current_date_id !== 'undefined' ? current_date_id : undefined,
        next_soa_serial: typeof next_soa_serial !== 'undefined' ? next_soa_serial : undefined,
        update_zonefile: typeof update_zonefile !== 'undefined' ? update_zonefile : undefined,
        remove_rr_update_alerts: typeof remove_rr_update_alerts !== 'undefined' ? remove_rr_update_alerts : undefined,
        rebuild_zone: typeof rebuild_zone !== 'undefined' ? rebuild_zone : undefined,
        is_rr_deletable: typeof is_rr_deletable !== 'undefined' ? is_rr_deletable : undefined,
        rebuild_zone_table: typeof rebuild_zone_table !== 'undefined' ? rebuild_zone_table : undefined,
        create_record_a: typeof create_record_a !== 'undefined' ? create_record_a : undefined,
        create_record_aaaa: typeof create_record_aaaa !== 'undefined' ? create_record_aaaa : undefined,
        create_record_cname: typeof create_record_cname !== 'undefined' ? create_record_cname : undefined,
        create_record_mx: typeof create_record_mx !== 'undefined' ? create_record_mx : undefined,
        create_record_txt: typeof create_record_txt !== 'undefined' ? create_record_txt : undefined,
        create_record_ns: typeof create_record_ns !== 'undefined' ? create_record_ns : undefined,
        create_record_generic: typeof create_record_generic !== 'undefined' ? create_record_generic : undefined,
        evaluate_form_button: typeof evaluate_form_button !== 'undefined' ? evaluate_form_button : undefined,
        check_button: typeof check_button !== 'undefined' ? check_button : undefined,
        is_valid_dns_name: typeof is_valid_dns_name !== 'undefined' ? is_valid_dns_name : undefined,
        validate_hostname: typeof validate_hostname !== 'undefined' ? validate_hostname : undefined,
        validate_cname_hostname: typeof validate_cname_hostname !== 'undefined' ? validate_cname_hostname : undefined,
        validate_ttl: typeof validate_ttl !== 'undefined' ? validate_ttl : undefined,
        validate_ipv4: typeof validate_ipv4 !== 'undefined' ? validate_ipv4 : undefined,
        validate_ipv6: typeof validate_ipv6 !== 'undefined' ? validate_ipv6 : undefined,
        validate_a: typeof validate_a !== 'undefined' ? validate_a : undefined,
        validate_aaaa: typeof validate_aaaa !== 'undefined' ? validate_aaaa : undefined,
        validate_priority: typeof validate_priority !== 'undefined' ? validate_priority : undefined,
        validate_nameserver: typeof validate_nameserver !== 'undefined' ? validate_nameserver : undefined,
        validate_txt: typeof validate_txt !== 'undefined' ? validate_txt : undefined,
        validation_functions: typeof validation_functions !== 'undefined' ? validation_functions : undefined,
        validate_input: typeof validate_input !== 'undefined' ? validate_input : undefined,
        set_input_validations: typeof set_input_validations !== 'undefined' ? set_input_validations : undefined,
        delete_rr: typeof delete_rr !== 'undefined' ? delete_rr : undefined,
        domain_sanitizer: typeof domain_sanitizer !== 'undefined' ? domain_sanitizer : undefined,
        logout: typeof logout !== 'undefined' ? logout : undefined,
        fqdn: typeof fqdn !== 'undefined' ? fqdn : undefined,
        copy_fqdn: typeof copy_fqdn !== 'undefined' ? copy_fqdn : undefined,
        reset_zone: typeof reset_zone !== 'undefined' ? reset_zone : undefined,
        set_zone: (z) => { zone = z; },
        get_zone: () => zone,
        set_user_origin: (o) => { user_origin = o; },
        get_user_origin: () => user_origin,
      }
    };
  `;

  vm.runInContext(punycodeSrc, sandbox);
  vm.runInContext(zonefileSrc, sandbox);
  vm.runInContext(mainSrc, sandbox);
  vm.runInContext(exposeSnippet, sandbox);

  const rawZonefile = sandbox.__exports.zonefile;
  const origParse = rawZonefile.parse;
  if (origParse) {
    rawZonefile.parse = (text) => JSON.parse(JSON.stringify(origParse(text)));
  }

  return {
    punycode: sandbox.__exports.punycode,
    zonefile: rawZonefile,
    main: sandbox.__exports.main,
    dom,
    isLegacy: true,
  };
}

/**
 * Creates a lightweight mock DOM environment sufficient for testing `main.js`
 * validations, form buttons, previews, table rendering, and error alerts.
 */
export function createMockDom(origin = 'user.example.com.') {
  const elementsById = new Map();
  const queryMap = new Map();
  const queryAllMap = new Map();
  const alerts = [];

  const makeClassList = (initial = []) => {
    const set = new Set(initial);
    return {
      add: (...cls) => cls.forEach(c => set.add(c)),
      remove: (...cls) => cls.forEach(c => set.delete(c)),
      contains: (c) => set.has(c),
      [Symbol.iterator]: () => set[Symbol.iterator](),
    };
  };

  const createInput = ({ id, value = '', classes = [], badInput = false, form = null }) => {
    const listeners = {};
    const feedbackEl = {
      textContent: '',
      classList: makeClassList(['invalid-feedback']),
    };
    const parentElement = {
      querySelector: (sel) => (sel === '.invalid-feedback' ? feedbackEl : null),
    };
    const input = {
      id,
      value,
      placeholder: '',
      validity: { badInput },
      classList: makeClassList(classes),
      feedbackEl,
      parentElement,
      nextElementSibling: feedbackEl,
      addEventListener: (evt, fn) => {
        listeners[evt] = listeners[evt] || [];
        listeners[evt].push(fn);
      },
      trigger: (evt) => {
        (listeners[evt] || []).forEach(fn => fn({ target: input }));
      },
      closest: (sel) => (sel === 'form' ? form : null),
    };
    if (id) {
      elementsById.set(id, input);
    }
    return input;
  };

  const createForm = (inputConfigs = []) => {
    const button = {
      disabled: false,
      closest: (sel) => (sel === 'form' ? form : null),
      parentElement: {
        parentElement: {
          insertAdjacentElement: (pos, el) => {
            alerts.push(el);
          },
        },
      },
    };
    const inputs = [];
    const form = {
      button,
      inputs,
      querySelector: (sel) => {
        if (sel === 'button') return button;
        if (sel === '.is-invalid') return inputs.find(i => i.classList.contains('is-invalid')) || null;
        return null;
      },
      querySelectorAll: (sel) => {
        if (sel === 'input') return inputs;
        if (sel === 'input.is-invalid') return inputs.filter(i => i.classList.contains('is-invalid'));
        return [];
      },
    };
    for (const cfg of inputConfigs) {
      inputs.push(createInput({ ...cfg, form }));
    }
    return { form, button, inputs };
  };

  const zoneFileEl = {
    id: 'zone-file',
    textContent: '$ORIGIN user.example.com.\n$TTL 60\n@ IN SOA ns.user.example.com. admin.user.example.com. 1 60 60 60 60\n@ IN NS ns\nns IN A 192.0.2.1\n',
    innerHTML: '',
  };
  elementsById.set('zone-file', zoneFileEl);

  const tbody = {
    innerHTML: '',
    querySelectorAll: () => [],
  };
  const zoneTableEl = {
    id: 'zone-table',
    tbody,
    insertAdjacentElement: (pos, el) => {
      alerts.push(el);
    },
  };
  elementsById.set('zone-table', zoneTableEl);

  const resetFooterDiv = {
    innerHTML: 'Error resetting the zone.<br><span id="reset-error-msg"></span>',
    classList: makeClassList(['modal-footer', 'bg-danger-subtle', 'd-none']),
  };
  const resetErrorSpan = {
    id: 'reset-error-msg',
    textContent: '',
    closest: (sel) => {
      if (sel === 'div') {
        return resetFooterDiv;
      }
      return null;
    },
  };
  // Simulate overwriting innerHTML destroying the child #reset-error-msg span
  let resetSpanDestroyed = false;
  Object.defineProperty(resetFooterDiv, 'innerHTML', {
    get() {
      return this._html || '';
    },
    set(val) {
      this._html = val;
      if (!val.includes('id="reset-error-msg"')) {
        resetSpanDestroyed = true;
      }
    },
  });

  const metaOrigin = { content: origin };

  const document = {
    readyState: 'interactive',
    addEventListener: () => {},
    getElementById: (id) => elementsById.get(id) || null,
    createElement: (tag) => ({
      tagName: tag.toUpperCase(),
      innerHTML: '',
      get firstElementChild() {
        return { outerHTML: this.innerHTML, remove: () => {} };
      },
    }),
    querySelector: (sel) => {
      if (sel === 'meta[name="user-origin"]') return metaOrigin;
      if (sel === '#zone-table tbody') return tbody;
      if (sel === '#reset-error-msg') return resetSpanDestroyed ? null : resetErrorSpan;
      if (queryMap.has(sel)) return queryMap.get(sel);
      return null;
    },
    querySelectorAll: (sel) => {
      if (sel === '.new-rr-update-msg') return alerts;
      if (queryAllMap.has(sel)) return queryAllMap.get(sel);
      return [];
    },
  };

  const window = {
    location: {
      href: '',
      reload: () => {},
    },
  };

  const navigator = {
    clipboard: {
      writeText: async () => {},
    },
  };

  return {
    document,
    window,
    navigator,
    elementsById,
    queryMap,
    queryAllMap,
    alerts,
    tbody,
    zoneFileEl,
    zoneTableEl,
    resetFooterDiv,
    resetErrorSpan,
    createInput,
    createForm,
    makeClassList,
    setTimeout: () => 0,
    clearTimeout: () => {},
  };
}

export function installGlobalDom(dom) {
  globalThis.document = dom.document;
  globalThis.window = dom.window;
  try {
    Object.defineProperty(globalThis, 'navigator', {
      value: dom.navigator,
      configurable: true,
      writable: true,
    });
  } catch {
    // Ignore if navigator is non-configurable
  }
}
