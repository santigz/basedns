import { toASCII, toUnicode } from './punycode.min.js?v=2';
import { generate, parse } from './zonefile.js?v=2';

/**
  * @type {string} Stores the origin name for this user's zone.
  *                Obtained from the html code.
  */
var user_origin;

/**
  * @type {object} Stores the zone data in json format following https://github.com/elgs/dns-zonefile
  *                Obtained from the html code.
  */
var zone;

/**
  * @type {{type: string, id: number} | null} Tracks a record currently being edited in the form.
  */
var editing_state = null;

function set_zone(new_zone) {
  zone = new_zone;
}

function get_zone() {
  return zone;
}

function set_user_origin(origin) {
  user_origin = origin;
}

function get_user_origin() {
  return user_origin;
}


function escape_html(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safe_to_unicode(domain) {
  try {
    return toUnicode(domain);
  } catch (e) {
    return domain;
  }
}

function safe_to_ascii(domain) {
  try {
    return toASCII(domain);
  } catch (e) {
    return '';
  }
}

function ttl_html(ttl, zone_ttl) {
  if (ttl === undefined) {
    if (zone_ttl === undefined) {
      return '&nbsp;';
    } else {
      return `<small class="text-body-secondary">${escape_html(zone_ttl)} (default)</small>`;
    }
  } else {
    return escape_html(ttl);
  }
}

const EDITABLE_RECORD_TYPES = new Set(['a', 'aaaa', 'cname', 'mx', 'txt', 'ns', 'srv', 'caa']);

/**
  * Builds a row with a DNS record for the DNS zone table
  *
  * @param {string} [type] - Record type, eg. A, AAAA, MX, TXT...
  * @param {string} [name] - Hostname.
  * @param {string} [value] - Contents of the record.
  * @param {string} [ttl] - TTL of the actual record (may be unknown).
  * @param {string} [zone_ttl] - Global $TTL of the zone, used when record's TTL is unknown.
  * @param {number} [id] - Internal row ID.
  * @param {boolean} [deletable=true] - Whether the record can be modified/deleted.
  * @param {boolean} [is_default_at=false] - Whether '@' was inferred from an omitted owner name.
  * @returns {string} HTML code for the table row.
  */
function zone_table_row(type, name, value, ttl, zone_ttl, id, deletable = true, is_default_at = false) {
  const safe_type = type ? escape_html(type) : '&nbsp;';
  let name_html;
  let punycode_hint = '';
  if (is_default_at || name === undefined || name === null || name === '') {
    name_html = '<small class="text-body-secondary">@</small>';
  } else if (name === '@') {
    name_html = '@';
  } else {
    const unicode_name = safe_to_unicode(name);
    name_html = escape_html(unicode_name);
    if (unicode_name !== name) {
      punycode_hint = ` <small class="text-body-secondary font-monospace">(${escape_html(name)})</small>`;
    }
  }
  const safe_value = value ?? '&nbsp;';
  const ttl_show = ttl_html(ttl, zone_ttl);
  const is_editing = editing_state && type && editing_state.type === type.toLowerCase() && editing_state.id === id;
  const row_class = is_editing ? ' class="editing-record-row"' : '';
  const can_edit = deletable && type && EDITABLE_RECORD_TYPES.has(type.toLowerCase());

  let html = `
          <tr${row_class}>
              <th scope="row" class="font-monospace">${safe_type}</th>
              <td class="copy-fqdn"><span class="name font-monospace">${name_html}</span>${punycode_hint}<span class="copy-fqdn-hint text-primary" role="button" tabindex="0" title="Copy Fully Qualified Domain Name">copy FQDN</span></td>
              <td class="font-monospace text-break">${safe_value}</td>
              <td>${ttl_show}</td>
        `;
  if (deletable) {
    html += ` <td class="text-end text-nowrap">`;
    if (can_edit) {
      html += `
                  <button type="button" class="btn btn-sm btn-link text-secondary row-action-btn rounded-1" rr_id="${escape_html(id)}" onclick="edit_rr(this)" title="Edit record">
                    <i class="bi bi-pencil"></i> Edit
                  </button>`;
    }
    html += `
                  <button type="button" class="btn btn-sm btn-link text-danger row-action-btn rounded-1" rr_id="${escape_html(id)}" onclick="delete_rr(this)" title="Delete record">
                    <i class="bi bi-trash"></i> Delete
                  </button>
              </td>`;
  } else {
    html += ` <td class="text-end">
                  <small class="text-body-secondary" title="Required by parent zone delegation and SOA MNAME"><i class="bi bi-lock me-1"></i>Not deletable (delegation)</small>
              </td>`;
  }
  html += '</tr>';
  return html;
}


/**
  * Updates the Zone Directives ($ORIGIN and $TTL) summary bar inside the table view.
  */
function update_soa_summary() {
  if (!zone || typeof document === 'undefined') {
    return;
  }
  const originEl = document.getElementById('soa-origin');
  if (originEl) {
    originEl.textContent = zone['$origin'] || user_origin || '—';
  }
  const ttlEl = document.getElementById('soa-default-ttl');
  if (ttlEl) {
    ttlEl.textContent = zone['$ttl'] !== undefined ? `${zone['$ttl']}s` : '—';
  }
}


/**
  * The TTL input value for creating new DNS records initially just
  * shows `(default)` with no specific number.
  * Here we add the global zone's $TTL to be shown as default value.
  */
function fix_ttl_placeholder() {
  if (!zone || !('$ttl' in zone)) {
    return;
  }
  const inputs = document.querySelectorAll("input[id$='-ttl']");
  inputs.forEach(input => {
    input.placeholder = `${zone['$ttl']} (default)`;
  });
}


/**
  * Returns the current timestamp as integer like 'YYYYMMDD'.
  */
function current_date_id() {
  const currentDate = new Date();
  const year = currentDate.getFullYear();
  const month = String(currentDate.getMonth() + 1).padStart(2, '0');
  const day = String(currentDate.getDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}


function next_soa_serial(current_serial) {
  const currentDate = new Date();
  const now_sec = Math.floor(currentDate.getTime() / 1000);
  const prev = parseInt(current_serial, 10);
  if (!isNaN(prev) && prev >= now_sec) {
    return prev + 1;
  }
  return now_sec;
}

function update_zonefile(zone_text) {
  return new Promise((resolve, reject) => {
    fetch('/zonefile', {
      method: 'PUT',
      headers: {
        'Content-Type': 'text/plain',
      },
      body: zone_text,
    })
      .then(response => {
        if (response.ok) {
          resolve({ success: true, msg: 'Success' });
          return null;
        } else {
          return response.json();
        }
      })
      .then(update_msg => {
        if (update_msg) {
          const detail = update_msg.detail;
          const raw_msg = (typeof detail === 'object' && detail !== null && detail.message)
            ? detail.message
            : (typeof detail === 'string' ? detail : JSON.stringify(detail));
          const err_type = (typeof detail === 'object' && detail !== null && detail.error)
            ? detail.error
            : 'Error';
          const msg = String(raw_msg).replace(/\\n/g, '\n'); // Fix newlines
          reject({ success: false, type: err_type, message: msg });
        }
      })
      .catch(error => {
        const msg = error + '\n Please check your connection or reload the page if your session has expired.';
        reject({ success: false, type: 'Network error', message: msg });
      });
  });
}

function remove_rr_update_alerts() {
  document.querySelectorAll('.new-rr-update-msg').forEach(alert => {
    alert.remove();
  });
}

/**
  * Takes the current `zone` variable and
  * rebuilds the zone table and zone text accordingly.
  *
  * This function should be called whenever the `zone` variable is changed.
  */
function rebuild_zone(button, new_zone) {
  remove_rr_update_alerts();
  if ('soa' in new_zone && new_zone['soa']) {
    new_zone['soa']['serial'] = next_soa_serial(new_zone['soa']['serial']);
  }
  const new_zone_text = generate(new_zone);

  return new Promise((resolve, reject) => {
    update_zonefile(new_zone_text)
      .then(result => {
        zone = new_zone;
        rebuild_zone_table();
        const zone_file = document.getElementById("zone-file");
        if (zone_file) {
          zone_file.textContent = new_zone_text;
        }
        resolve();
      })
      .catch(error => {
        reject(error);
      });
  });
}

function is_rr_deletable(type, rr, soa) {
  if (!soa || !soa.mname) {
    return true;
  }
  const soa_ns = soa.mname.split('.')[0];
  const rr_name = rr.name || '@';
  const rr_host_short = rr.host ? rr.host.split('.')[0] : '';
  if (type == 'ns' && rr_name == '@' && (rr.host == soa_ns || rr.host == soa.mname || rr_host_short == soa_ns)) {
    if (zone && Array.isArray(zone.ns)) {
      const idx = zone.ns.indexOf(rr);
      const firstIdx = zone.ns.findIndex(r => {
        const r_name = r.name || '@';
        const r_host_short = r.host ? r.host.split('.')[0] : '';
        return r_name == '@' && (r.host == soa_ns || r.host == soa.mname || r_host_short == soa_ns);
      });
      if (idx !== -1 && firstIdx !== -1 && idx > firstIdx) {
        return true;
      }
    }
    return false;
  }
  if (type == 'a' && rr_name == soa_ns) {
    if (zone && Array.isArray(zone.a)) {
      const idx = zone.a.indexOf(rr);
      const firstIdx = zone.a.findIndex(r => (r.name || '@') == soa_ns);
      if (idx !== -1 && firstIdx !== -1 && idx > firstIdx) {
        return true;
      }
    }
    return false;
  }
  return true;
}

/**
  * Takes the current `zone` variable and rebuilds the zone table accordingly.
  */
function rebuild_zone_table() {
  // https://github.com/elgs/dns-zonefile
  if (!zone) { return; }
  update_soa_summary();
  var tbody = document.querySelector("#zone-table tbody");
  if (!tbody) { return; }
  var rows_html = '';
  var zone_ttl = zone['$ttl'];
  var rr_id = 1;
  if ('ns' in zone) {
    for (const rr of zone['ns']) {
      rr.id = rr_id++;
      const is_default_at = !('name' in rr);
      const rr_name = is_default_at ? '@' : rr['name'];
      const deletable = is_rr_deletable('ns', rr, zone.soa);
      const host_display = escape_html(safe_to_unicode(rr['host'] || ''));
      rows_html += zone_table_row('NS', rr_name, host_display, rr['ttl'], zone_ttl, rr.id, deletable, is_default_at);
    }
  }
  if ('a' in zone) {
    for (const rr of zone['a']) {
      rr.id = rr_id++;
      const deletable = is_rr_deletable('a', rr, zone.soa);
      rows_html += zone_table_row('A', rr['name'], escape_html(rr['ip'] ?? ''), rr['ttl'], zone_ttl, rr.id, deletable);
    }
  }
  if ('aaaa' in zone) {
    for (const rr of zone['aaaa']) {
      rr.id = rr_id++;
      rows_html += zone_table_row('AAAA', rr['name'], escape_html(rr['ip'] ?? ''), rr['ttl'], zone_ttl, rr.id, true);
    }
  }
  if ('cname' in zone) {
    for (const rr of zone['cname']) {
      rr.id = rr_id++;
      const alias_display = escape_html(safe_to_unicode(rr['alias'] || ''));
      rows_html += zone_table_row('CNAME', rr['name'], alias_display, rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('mx' in zone) {
    for (const rr of zone['mx']) {
      rr.id = rr_id++;
      const host_display = escape_html(safe_to_unicode(rr['host'] || ''));
      const value = `<span class="badge text-bg-secondary">${escape_html(rr['preference'] ?? '')}</span> ${host_display}`;
      rows_html += zone_table_row('MX', rr['name'], value, rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('txt' in zone) {
    for (const rr of zone['txt']) {
      rr.id = rr_id++;
      rows_html += zone_table_row('TXT', rr['name'], escape_html(rr['txt'] ?? ''), rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('srv' in zone) {
    for (const rr of zone['srv']) {
      rr.id = rr_id++;
      const value = `<span class="badge text-bg-secondary">${escape_html(rr['priority'] ?? '')} ${escape_html(rr['weight'] ?? '')} ${escape_html(rr['port'] ?? '')}</span> ${escape_html(safe_to_unicode(rr['target'] || ''))}`;
      rows_html += zone_table_row('SRV', rr['name'], value, rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('caa' in zone) {
    for (const rr of zone['caa']) {
      rr.id = rr_id++;
      const value = `<span class="badge text-bg-secondary">${escape_html(rr['flags'] ?? 0)} ${escape_html(rr['tag'] ?? '')}</span> ${escape_html(rr['value'] ?? '')}`;
      rows_html += zone_table_row('CAA', rr['name'], value, rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('ptr' in zone) {
    for (const rr of zone['ptr']) {
      rr.id = rr_id++;
      rows_html += zone_table_row('PTR', rr['name'], escape_html(safe_to_unicode(rr['host'] || '')), rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('spf' in zone) {
    for (const rr of zone['spf']) {
      rr.id = rr_id++;
      rows_html += zone_table_row('SPF', rr['name'], escape_html(rr['data'] ?? ''), rr['ttl'], zone_ttl, rr.id);
    }
  }
  if ('ds' in zone) {
    for (const rr of zone['ds']) {
      rr.id = rr_id++;
      const value = `${escape_html(rr['key_tag'] ?? '')} ${escape_html(rr['algorithm'] ?? '')} ${escape_html(rr['digest_type'] ?? '')} ${escape_html(rr['digest'] ?? '')}`;
      rows_html += zone_table_row('DS', rr['name'], value, rr['ttl'], zone_ttl, rr.id);
    }
  }
  tbody.innerHTML = rows_html;
  tbody.querySelectorAll(".copy-fqdn").forEach(element => {
    element.addEventListener("click", () => {
      if (typeof window !== 'undefined' && window.getSelection && window.getSelection().toString().length > 0) {
        return;
      }
      copy_fqdn(element);
    });
    const hint = element.querySelector && element.querySelector(".copy-fqdn-hint");
    if (hint && hint.addEventListener) {
      hint.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          copy_fqdn(element);
        }
      });
    }
  });
}


function update_input_preview(input) {
  const preview = document.getElementById(`${input.id}-preview`);
  if (!preview) {
    return;
  }
  const raw = input.value ? input.value.trim() : '';
  if (raw === '@') {
    if (input.classList.contains('nameserver-validation') || input.classList.contains('cname-hostname-validation')) {
      preview.textContent = '\xa0';
    } else {
      preview.textContent = user_origin;
    }
    return;
  }
  const name = safe_to_ascii(raw);
  if (!name) {
    preview.textContent = '\xa0';
    return;
  }
  if (name.slice(-1) == '.') {
    preview.textContent = name;
    return;
  }
  preview.textContent = name + '.' + user_origin;
}

// Live preview for name input with suffix ".example.com"
function set_input_previews() {
  document.querySelectorAll('input[preview$="true"]').forEach(input => {
    input.addEventListener('input', (e) => {
      if (input.value === '' && !(input.validity && input.validity.badInput)) {
        set_input_validation_state(input, null);
        evaluate_form_button(input);
      } else {
        validate_input(input);
      }
      update_input_preview(e.target);
    });
  });
}

function init_page() {
  user_origin = document.querySelector('meta[name="user-origin"]').content;
  zone = parse(document.getElementById('zone-file').textContent);
  rebuild_zone_table();
  fix_ttl_placeholder();
  set_input_validations();
  set_input_previews();
  set_change_origin_listeners();
}

function create_record_a(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("a-name").value.trim()),
    'ip': document.getElementById("a-ip").value.trim(),
    'ttl': document.getElementById("a-ttl").value.trim(),
  };
  create_record_generic(button, 'a', rr);
}

function create_record_aaaa(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("aaaa-name").value.trim()),
    'ip': document.getElementById("aaaa-ip").value.trim(),
    'ttl': document.getElementById("aaaa-ttl").value.trim(),
  };
  create_record_generic(button, 'aaaa', rr);
}

function create_record_cname(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("cname-name").value.trim()),
    'alias': safe_to_ascii(document.getElementById("cname-alias").value.trim()),
    'ttl': document.getElementById("cname-ttl").value.trim(),
  };
  create_record_generic(button, 'cname', rr);
}

function create_record_mx(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("mx-name").value.trim()),
    'host': safe_to_ascii(document.getElementById("mx-host").value.trim()),
    'preference': document.getElementById("mx-priority").value.trim(),
    'ttl': document.getElementById("mx-ttl").value.trim(),
  };
  create_record_generic(button, 'mx', rr);
}

function create_record_txt(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("txt-name").value.trim()),
    'txt': document.getElementById("txt-value").value.trim(),
    'ttl': document.getElementById("txt-ttl").value.trim(),
  };
  create_record_generic(button, 'txt', rr);
}

function create_record_ns(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("ns-name").value.trim()),
    'host': safe_to_ascii(document.getElementById("ns-nameserver").value.trim()),
    'ttl': document.getElementById("ns-ttl").value.trim(),
  };
  create_record_generic(button, 'ns', rr);
}

function create_record_srv(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("srv-name").value.trim()),
    'priority': document.getElementById("srv-priority").value.trim(),
    'weight': document.getElementById("srv-weight").value.trim(),
    'port': document.getElementById("srv-port").value.trim(),
    'target': safe_to_ascii(document.getElementById("srv-target").value.trim()),
    'ttl': document.getElementById("srv-ttl").value.trim(),
  };
  create_record_generic(button, 'srv', rr);
}

function create_record_caa(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("caa-name").value.trim()),
    'flags': document.getElementById("caa-flags").value.trim(),
    'tag': document.getElementById("caa-tag").value.trim(),
    'value': document.getElementById("caa-value").value.trim(),
    'ttl': document.getElementById("caa-ttl").value.trim(),
  };
  create_record_generic(button, 'caa', rr);
}

function show_rr_error(anchor_element, heading, error) {
  if (!anchor_element || !anchor_element.insertAdjacentElement) {
    return;
  }
  const html_error = `
    <div class="row mt-2 new-rr-update-msg">
    <div class="col">
      <div class="alert alert-danger alert-dismissible fade show mb-0" role="alert">
        <h6 class="alert-heading fw-bold">${escape_html(heading)}</h6>
        <pre class="mb-1">${escape_html(error.type ?? 'Error')}</pre>
        <hr class="my-2">
        <pre class="mb-0">${escape_html(error.message ?? String(error))}</pre>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    </div>
    </div>
    `;
  const div = document.createElement('div');
  div.innerHTML = html_error;
  anchor_element.insertAdjacentElement("afterend", div.firstElementChild);
}

function reset_record_form(button) {
  const form = button && button.closest ? button.closest('form') : null;
  if (!form || !form.querySelectorAll) {
    return;
  }
  form.querySelectorAll('input').forEach(input => {
    if (input.id === 'caa-flags') {
      input.value = '0';
    } else {
      input.value = '';
    }
    input.classList.remove('is-invalid');
    const preview = document.getElementById(`${input.id}-preview`);
    if (preview) {
      preview.textContent = '\xa0';
    }
  });
}

function create_record_generic(button, type, rr_dict) {
  if (!zone) { return; }
  if (!check_button(button)) {
    return;
  }
  const rr = {};
  for (let key in rr_dict) {
    if (rr_dict[key] !== undefined && rr_dict[key] !== null && rr_dict[key] !== '') {
      rr[key] = rr_dict[key];
    }
  }
  if (Object.keys(rr).length == 0) {
    return;
  }
  const new_zone = structuredClone(zone);
  const is_editing_this_type = editing_state && editing_state.type === type && (type in new_zone);

  if (is_editing_this_type) {
    const idx = new_zone[type].findIndex(item => item.id == editing_state.id);
    if (idx !== -1) {
      new_zone[type][idx] = rr;
    } else {
      new_zone[type].push(rr);
    }
  } else if (type in new_zone) {
    new_zone[type].push(rr);
  } else {
    new_zone[type] = [rr];
  }

  button.disabled = true;
  rebuild_zone(button, new_zone)
    .then(() => {
      button.disabled = false;
      reset_record_form(button);
      if (editing_state) {
        cancel_edit_rr();
      }
    })
    .catch(error => {
      button.disabled = false;
      const err_heading = is_editing_this_type ? 'Error updating the record:' : 'Error adding the record:';
      show_rr_error(button.parentElement.parentElement, err_heading, error);
    });
}


function set_field_value(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.value = value ?? '';
  el.classList.remove('is-invalid');
  update_input_preview(el);
}

function edit_rr(button) {
  const tr = button.closest('tr');
  if (!tr) return;
  const rr_type = tr.querySelector('th').innerText.trim().toLowerCase();
  const rrid = parseInt(button.attributes.rr_id.nodeValue, 10);
  if (!(rr_type in zone)) return;
  const rr = zone[rr_type].find(item => item.id == rrid);
  if (!rr) return;

  editing_state = { type: rr_type, id: rrid };
  rebuild_zone_table();

  // Switch to the matching record form tab
  const tabBtn = document.getElementById(`${rr_type}-tab`);
  if (tabBtn) {
    if (typeof window !== 'undefined' && window.bootstrap && window.bootstrap.Tab) {
      window.bootstrap.Tab.getOrCreateInstance(tabBtn).show();
    } else if (tabBtn.click) {
      tabBtn.click();
    }
  }

  // Populate form fields
  const name_val = safe_to_unicode(rr.name || '@');
  const ttl_val = rr.ttl ?? '';
  if (rr_type === 'a') {
    set_field_value('a-name', name_val);
    set_field_value('a-ip', rr.ip);
    set_field_value('a-ttl', ttl_val);
  } else if (rr_type === 'aaaa') {
    set_field_value('aaaa-name', name_val);
    set_field_value('aaaa-ip', rr.ip);
    set_field_value('aaaa-ttl', ttl_val);
  } else if (rr_type === 'cname') {
    set_field_value('cname-name', name_val);
    set_field_value('cname-alias', safe_to_unicode(rr.alias || ''));
    set_field_value('cname-ttl', ttl_val);
  } else if (rr_type === 'mx') {
    set_field_value('mx-name', name_val);
    set_field_value('mx-host', safe_to_unicode(rr.host || ''));
    set_field_value('mx-priority', rr.preference);
    set_field_value('mx-ttl', ttl_val);
  } else if (rr_type === 'txt') {
    set_field_value('txt-name', name_val);
    set_field_value('txt-value', rr.txt);
    set_field_value('txt-ttl', ttl_val);
  } else if (rr_type === 'ns') {
    set_field_value('ns-name', name_val);
    set_field_value('ns-nameserver', safe_to_unicode(rr.host || ''));
    set_field_value('ns-ttl', ttl_val);
  } else if (rr_type === 'srv') {
    set_field_value('srv-name', name_val);
    set_field_value('srv-priority', rr.priority);
    set_field_value('srv-weight', rr.weight);
    set_field_value('srv-port', rr.port);
    set_field_value('srv-target', safe_to_unicode(rr.target || ''));
    set_field_value('srv-ttl', ttl_val);
  } else if (rr_type === 'caa') {
    set_field_value('caa-name', name_val);
    set_field_value('caa-flags', rr.flags);
    set_field_value('caa-tag', rr.tag);
    set_field_value('caa-value', rr.value);
    set_field_value('caa-ttl', ttl_val);
  }

  const titleEl = document.getElementById('record-form-title');
  if (titleEl) {
    titleEl.textContent = `Edit ${rr_type.toUpperCase()} record`;
  }
  const cancelBtn = document.getElementById('cancel-edit-btn');
  if (cancelBtn) {
    cancelBtn.classList.remove('d-none');
  }
  const submitBtn = document.getElementById(`${rr_type}-button`);
  if (submitBtn) {
    submitBtn.textContent = 'Update Record';
    submitBtn.classList.replace('btn-success', 'btn-primary');
    submitBtn.disabled = false;
  }
  const panel = document.getElementById('new-record-panel');
  if (panel && panel.scrollIntoView) {
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function cancel_edit_rr() {
  const prev_type = editing_state ? editing_state.type : null;
  editing_state = null;
  const titleEl = document.getElementById('record-form-title');
  if (titleEl) {
    titleEl.textContent = 'Create new record';
  }
  const cancelBtn = document.getElementById('cancel-edit-btn');
  if (cancelBtn) {
    cancelBtn.classList.add('d-none');
  }
  EDITABLE_RECORD_TYPES.forEach(type => {
    const btn = document.getElementById(`${type}-button`);
    if (btn) {
      btn.textContent = 'Create Record';
      if (btn.classList && btn.classList.replace) {
        btn.classList.replace('btn-primary', 'btn-success');
      }
      if (prev_type === type) {
        reset_record_form(btn);
      }
    }
  });
  rebuild_zone_table();
}


function evaluate_form_button(input) {
  const form = input.closest('form');
  const button = form.querySelector('button');
  if (form.querySelector('.is-invalid')) {
    button.disabled = true;
  } else {
    button.disabled = false;
  }
}

function check_button(button) {
  const form = button.closest('form');
  form.querySelectorAll('input').forEach(input => {
    validate_input(input);
  });
  const invalid_inputs = form.querySelectorAll('input.is-invalid');
  if (invalid_inputs.length > 0) {
    button.disabled = true;
    return false;
  } else {
    button.disabled = false;
    return true;
  }
}

function set_input_validation_state(input, error_msg) {
  let feedback = null;
  if (input.parentElement && input.parentElement.querySelector) {
    feedback = input.parentElement.querySelector('.invalid-feedback');
  } else if (input.nextElementSibling && input.nextElementSibling.classList && input.nextElementSibling.classList.contains('invalid-feedback')) {
    feedback = input.nextElementSibling;
  }
  if (error_msg) {
    input.classList.add('is-invalid');
    if (feedback) {
      feedback.textContent = error_msg;
    }
  } else {
    input.classList.remove('is-invalid');
  }
}

function get_dns_name_error(value, allow_at = true, disallow_at_msg = null) {
  if (value === undefined || value === null || value === '') {
    return 'Hostname cannot be empty.';
  }
  const trimmed = String(value).trim();
  if (!trimmed) {
    return 'Hostname cannot be empty.';
  }
  if (/\s/.test(trimmed)) {
    return 'Hostname cannot contain spaces or whitespace.';
  }
  if (trimmed === '@') {
    if (allow_at) {
      return null;
    }
    return disallow_at_msg || '"@" (zone apex) is not allowed here.';
  }
  if (trimmed.includes('@')) {
    return '"@" can only be used alone to represent the zone apex, not inside a hostname.';
  }
  if (trimmed === '.') {
    return 'A single dot (".") is not a valid hostname.';
  }
  if (trimmed.startsWith('.')) {
    return 'Hostname cannot start with a dot (".").';
  }
  if (trimmed.includes('..')) {
    return 'Hostname cannot contain empty labels (consecutive dots "..").';
  }
  const raw_without_trailing_dot = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  const raw_labels = raw_without_trailing_dot.split('.');
  for (let i = 0; i < raw_labels.length; i++) {
    const raw_label = raw_labels[i];
    if (raw_label.startsWith('-') || raw_label.endsWith('-')) {
      return `Label "${raw_label}" cannot start or end with a hyphen ("-").`;
    }
  }
  const ascii = safe_to_ascii(trimmed);
  if (!ascii) {
    return 'Hostname contains invalid internationalized (IDN/Punycode) characters.';
  }
  const without_trailing_dot = ascii.endsWith('.') ? ascii.slice(0, -1) : ascii;
  if (!without_trailing_dot) {
    return 'Hostname cannot be empty.';
  }
  if (without_trailing_dot.length > 253) {
    return `Full domain name cannot exceed 253 characters (currently ${without_trailing_dot.length} characters).`;
  }
  const labels = without_trailing_dot.split('.');
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    const raw_label = raw_labels[i] ?? label;
    if (!label) {
      return 'Hostname cannot contain empty labels.';
    }
    if (label.length > 63) {
      if (raw_label !== label && raw_label.length <= 63) {
        return `Label "${raw_label}" exceeds the 63-character limit after Punycode conversion (${label.length} ASCII characters).`;
      }
      return `Each dot-separated label cannot exceed 63 characters (currently ${label.length} characters).`;
    }
    if (i === 0 && label === '*') {
      continue;
    }
    if (label === '*') {
      return 'Wildcard ("*") is only allowed as the leftmost label (e.g. "*.sub").';
    }
    if (label.includes('*')) {
      return 'Wildcard ("*") must be a standalone leftmost label (e.g. "*" or "*.sub"), not part of a label.';
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return `Label "${raw_label}" cannot start or end with a hyphen ("-").`;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(label)) {
      const bad_char = label.match(/[^a-zA-Z0-9_-]/)[0];
      return `Invalid character "${bad_char}" in label "${raw_label}". Only letters, digits, hyphens ("-"), and underscores ("_") are allowed.`;
    }
  }
  return null;
}

function is_valid_dns_name(value, allow_at = true) {
  return get_dns_name_error(value, allow_at) === null;
}

function validate_hostname(input) {
  const err = get_dns_name_error(input.value, true);
  set_input_validation_state(input, err);
  evaluate_form_button(input);
}

function validate_cname_hostname(input) {
  const err = get_dns_name_error(
    input.value,
    false,
    '"@" (zone apex) is not allowed for CNAME records (conflicts with SOA and NS records at the zone root).'
  );
  set_input_validation_state(input, err);
  evaluate_form_button(input);
}

function validate_ttl(input) {
  if (input.validity && input.validity.badInput) {
    set_input_validation_state(input, 'TTL must be a whole number (integer) in seconds.');
    evaluate_form_button(input);
    return;
  }
  const raw = input.value.trim();
  if (!raw) {
    set_input_validation_state(input, null);
    evaluate_form_button(input);
    return;
  }
  if (!/^\d+$/.test(raw)) {
    const msg = raw.startsWith('-')
      ? 'TTL cannot be negative (minimum is 60 seconds).'
      : 'TTL must be a whole number (integer) in seconds.';
    set_input_validation_state(input, msg);
    evaluate_form_button(input);
    return;
  }
  const number = Number(raw);
  if (!Number.isInteger(number) || number < 60) {
    set_input_validation_state(input, 'TTL must be at least 60 seconds.');
  } else if (number > 2147483647) {
    set_input_validation_state(input, 'TTL cannot exceed 2147483647 seconds (max 31-bit signed integer).');
  } else {
    set_input_validation_state(input, null);
  }
  evaluate_form_button(input);
}

function validate_ipv4(ip) {
  // Reject leading zeros (e.g. 010.0.0.1) which BIND 9 named-checkzone rejects
  const ipv4Regex = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
  if (ipv4Regex.test(ip)) {
    return ip.split('.').every(part => parseInt(part, 10) <= 255);
  }
  return false;
}

function validate_ipv6(ip) {
  // From https://github.com/Karbashevskyi/thiis/blob/main/src/regexp.ts (without %zone_id suffix)
  const ipv6Regex = /^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))$/;
  if (ipv6Regex.test(ip)) {
    return ip.split(':').every(part => part.length <= 4);
  }
  return false;
}

function validate_a(input) {
  const raw = input.value.trim();
  if (validate_ipv4(raw)) {
    set_input_validation_state(input, null);
  } else if (!raw) {
    set_input_validation_state(input, 'IPv4 address cannot be empty.');
  } else if (/^\d+\.\d+\.\d+\.\d+$/.test(raw) && raw.split('.').some(p => p.length > 1 && p.startsWith('0'))) {
    set_input_validation_state(input, 'IPv4 octets cannot have leading zeros (rejected by BIND named-checkzone).');
  } else {
    set_input_validation_state(input, 'Must be a valid IPv4 address (4 octets from 0 to 255, e.g. 192.0.2.1).');
  }
  evaluate_form_button(input);
}

function validate_aaaa(input) {
  const raw = input.value.trim();
  if (validate_ipv6(raw)) {
    set_input_validation_state(input, null);
  } else if (!raw) {
    set_input_validation_state(input, 'IPv6 address cannot be empty.');
  } else if (raw.includes('%')) {
    set_input_validation_state(input, 'IPv6 zone index (%interface) is not allowed in DNS AAAA records.');
  } else {
    set_input_validation_state(input, 'Must be a valid IPv6 address (e.g. 2001:db8::1).');
  }
  evaluate_form_button(input);
}

function validate_priority(input) {
  const max_val = input.id === 'caa-flags' ? 255 : 65535;
  if (input.validity && input.validity.badInput) {
    set_input_validation_state(input, `Must be a whole number between 0 and ${max_val}.`);
    evaluate_form_button(input);
    return;
  }
  const raw = input.value.trim();
  if (!raw) {
    set_input_validation_state(input, 'This field cannot be empty.');
    evaluate_form_button(input);
    return;
  }
  if (!/^\d+$/.test(raw)) {
    set_input_validation_state(input, `Must be a whole number between 0 and ${max_val}.`);
    evaluate_form_button(input);
    return;
  }
  const number = Number(raw);
  if (Number.isInteger(number) && number >= 0 && number <= max_val) {
    set_input_validation_state(input, null);
  } else {
    set_input_validation_state(input, `Must be between 0 and ${max_val}.`);
  }
  evaluate_form_button(input);
}

function validate_nameserver(input) {
  const err = get_dns_name_error(
    input.value,
    false,
    '"@" (zone apex) is not allowed as a target hostname. Enter a valid domain or hostname.'
  );
  set_input_validation_state(input, err);
  evaluate_form_button(input);
}

function validate_txt(input) {
  if (input.value && input.value.trim().length > 0) {
    set_input_validation_state(input, null);
  } else {
    set_input_validation_state(input, 'Value cannot be empty.');
  }
  evaluate_form_button(input);
}

const validation_functions = {
  'hostname-validation': validate_hostname,
  'cname-hostname-validation': validate_cname_hostname,
  'a-validation': validate_a,
  'aaaa-validation': validate_aaaa,
  'ttl-validation': validate_ttl,
  'priority-validation': validate_priority,
  'nameserver-validation': validate_nameserver,
  'txt-validation': validate_txt,
};

function validate_input(input) {
  const matchingClass = Array.from(input.classList).find(className => className in validation_functions);
  if (matchingClass) {
    validation_functions[matchingClass](input);
  }
}

function set_input_validations() {
  for (const v_class in validation_functions) {
    document.querySelectorAll('.' + v_class).forEach(input => {
      input.addEventListener('input', () => {
        if (input.value === '' && !(input.validity && input.validity.badInput)) {
          set_input_validation_state(input, null);
          evaluate_form_button(input);
        } else {
          validation_functions[v_class](input);
        }
      });
    });
  }
}

function delete_rr(button) {
  const rr_type = button.closest('tr').querySelector('th').innerText.trim().toLowerCase();
  const rrid = parseInt(button.attributes.rr_id.nodeValue, 10);
  if (!(rr_type in zone)) {
    return;
  }
  const idx = zone[rr_type].findIndex(item => item.id == rrid);
  if (idx == -1) {
    return;
  }
  if (editing_state && editing_state.type === rr_type && editing_state.id === rrid) {
    cancel_edit_rr();
  }
  const new_zone = structuredClone(zone);
  new_zone[rr_type].splice(idx, 1);
  rebuild_zone(button, new_zone)
    .then(_ => {
      // Zone table and file updated in place
    })
    .catch(error => {
      const table = document.getElementById('zone-table');
      if (table) {
        show_rr_error(table, 'Error deleting the record:', error);
      }
    });
}

function domain_sanitizer(domain) {
  // remove spaces
  return domain.replace(/\s+/g, '');
}

function logout() {
  window.location.href = 'https://auth.infor.tiernogalvan.es/logout?rd=https://dns.infor.tiernogalvan.es';
}


function fqdn(hostname) {
  const origin = document.querySelector('meta[name="user-origin"]').content;
  const cleaned = hostname ? hostname.trim() : '@';
  if (!cleaned || cleaned == '@') {
    return origin;
  }
  if (cleaned.slice(-1) == '.') {
    return cleaned;
  }
  return cleaned + '.' + origin;
}

function copy_fqdn(element) {
  const nameEl = element.querySelector(".name");
  const textToCopy = fqdn(nameEl ? nameEl.textContent : '@');
  navigator.clipboard.writeText(textToCopy)
    .then(() => {
      const copyHint = element.querySelector(".copy-fqdn-hint");
      if (copyHint) {
        copyHint.textContent = "copied!";
        setTimeout(() => {
          copyHint.textContent = "copy FQDN";
        }, 1500);
      }
    })
    .catch(err => console.error("Could not copy text: ", err));
}

function copy_text_value(text, button) {
  navigator.clipboard.writeText(text)
    .then(() => {
      if (!button) return;
      const span = button.querySelector('span');
      const target = span || button;
      const original = target.textContent;
      target.textContent = 'Copied!';
      setTimeout(() => {
        target.textContent = original;
      }, 1500);
    })
    .catch(err => console.error("Could not copy text: ", err));
}

function copy_zonefile(button) {
  const zoneFileEl = document.getElementById('zone-file');
  if (!zoneFileEl) return;
  copy_text_value(zoneFileEl.textContent, button);
}

function download_zonefile() {
  const zoneFileEl = document.getElementById('zone-file');
  if (!zoneFileEl || typeof Blob === 'undefined' || typeof URL === 'undefined') return;
  const blob = new Blob([zoneFileEl.textContent], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const filename = (user_origin || 'zone').replace(/\.$/, '') + '.zone';
  a.href = url;
  a.download = filename;
  if (document.body && document.body.appendChild) {
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
  URL.revokeObjectURL(url);
}


function reset_zone() {
  fetch('/reset_zonefile', {
    method: 'POST',
  })
    .then(response => {
      if (!response.ok) {
        throw new Error('Failed resetting the zone.');
      }
      return response.text();
    })
    .then(data => {
      window.location.reload();
    })
    .catch(error => {
      const err_span = document.querySelector('#reset-error-msg');
      if (err_span) {
        err_span.textContent = 'Failed resetting the zone.';
        err_span.closest('div').classList.remove('d-none');
      }
    });
}

function get_root_domain(origin = user_origin) {
  if (!origin) return '';
  const idx = origin.indexOf('.');
  return idx !== -1 ? origin.slice(idx + 1) : origin;
}

function get_origin_subdomain_error(value, current_origin = user_origin) {
  if (value === undefined || value === null || value === '') {
    return 'Subdomain cannot be empty.';
  }
  const trimmed = String(value).trim();
  if (!trimmed) {
    return 'Subdomain cannot be empty.';
  }
  if (/\s/.test(trimmed)) {
    return 'Subdomain cannot contain spaces or whitespace.';
  }
  if (trimmed.includes('@')) {
    return 'Subdomain cannot contain "@".';
  }
  if (trimmed.includes('.')) {
    return 'Subdomain must be a single label and cannot contain dots (".").';
  }
  if (trimmed.includes('*')) {
    return 'Subdomain cannot contain wildcard ("*").';
  }
  if (trimmed.includes('_')) {
    return 'Subdomain cannot contain underscores ("_"). Only letters, digits, and hyphens ("-") are allowed.';
  }
  if (trimmed.startsWith('-') || trimmed.endsWith('-')) {
    return 'Subdomain cannot start or end with a hyphen ("-").';
  }
  const ascii = safe_to_ascii(trimmed).toLowerCase();
  if (!ascii) {
    return 'Subdomain contains invalid internationalized (IDN/Punycode) characters.';
  }
  if (ascii.length > 63) {
    return `Subdomain cannot exceed 63 characters (currently ${ascii.length} characters).`;
  }
  if (ascii.startsWith('-') || ascii.endsWith('-')) {
    return 'Subdomain cannot start or end with a hyphen ("-").';
  }
  if (!/^[a-z0-9-]+$/.test(ascii)) {
    return 'Subdomain can only contain letters, digits, and hyphens ("-").';
  }
  if (ascii === 'ns') {
    return 'Subdomain "ns" is reserved and cannot be used.';
  }
  if (current_origin) {
    const current_sub = current_origin.split('.')[0].toLowerCase();
    if (ascii === current_sub) {
      return 'This is already your current zone origin.';
    }
  }
  return null;
}

function validate_new_origin_input(input) {
  if (!input) return false;
  const err = get_origin_subdomain_error(input.value, user_origin);
  set_input_validation_state(input, err);
  return err === null;
}

function evaluate_change_origin_form() {
  if (typeof document === 'undefined') return false;
  const input = document.getElementById('new-origin-input');
  const ack = document.getElementById('change-origin-ack');
  const submitBtn = document.getElementById('change-origin-submit');
  if (!input || !submitBtn) return false;
  const raw = input.value ? input.value.trim() : '';
  const err = raw ? get_origin_subdomain_error(raw, user_origin) : 'Subdomain cannot be empty.';
  const isAcked = Boolean(ack && ack.checked);
  const canSubmit = err === null && isAcked;
  submitBtn.disabled = !canSubmit;
  return canSubmit;
}

function set_change_origin_listeners() {
  if (typeof document === 'undefined') return;
  const suffixEl = document.getElementById('new-origin-root-suffix');
  if (suffixEl) {
    const root = get_root_domain(user_origin);
    if (root) {
      suffixEl.textContent = `.${root}`;
    }
  }
  const input = document.getElementById('new-origin-input');
  const ack = document.getElementById('change-origin-ack');
  if (input && input.addEventListener) {
    input.addEventListener('input', () => {
      const err_span = document.querySelector('#change-origin-error-msg');
      if (err_span && err_span.closest('div')) {
        err_span.closest('div').classList.add('d-none');
      }
      if (input.value === '') {
        set_input_validation_state(input, null);
      } else {
        validate_new_origin_input(input);
      }
      evaluate_change_origin_form();
    });
  }
  if (ack && ack.addEventListener) {
    ack.addEventListener('change', () => {
      evaluate_change_origin_form();
    });
  }
}

function change_origin() {
  if (typeof document === 'undefined') return;
  const input = document.getElementById('new-origin-input');
  const ack = document.getElementById('change-origin-ack');
  const submitBtn = document.getElementById('change-origin-submit');
  if (input && !validate_new_origin_input(input)) {
    if (submitBtn) submitBtn.disabled = true;
    return;
  }
  if (ack && !ack.checked) {
    if (submitBtn) submitBtn.disabled = true;
    return;
  }
  const subdomain = input ? safe_to_ascii(input.value.trim()).toLowerCase() : '';
  if (submitBtn) submitBtn.disabled = true;

  return fetch('/origin', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      subdomain,
      acknowledge: true,
    }),
  })
    .then(async response => {
      if (response.ok) {
        window.location.reload();
        return;
      }
      let msg = 'Failed changing the zone origin.';
      try {
        const data = await response.json();
        if (data && data.detail) {
          msg = typeof data.detail === 'object' && data.detail.message
            ? data.detail.message
            : String(data.detail);
        }
      } catch {
        // Fallback to default message
      }
      throw new Error(msg);
    })
    .catch(error => {
      if (submitBtn) submitBtn.disabled = false;
      const err_span = document.querySelector('#change-origin-error-msg');
      if (err_span) {
        err_span.textContent = error.message || 'Failed changing the zone origin.';
        if (err_span.closest('div')) {
          err_span.closest('div').classList.remove('d-none');
        }
      }
    });
}

if (typeof window !== 'undefined') {
  Object.assign(window, {
    create_record_a,
    create_record_aaaa,
    create_record_cname,
    create_record_mx,
    create_record_txt,
    create_record_ns,
    create_record_srv,
    create_record_caa,
    edit_rr,
    cancel_edit_rr,
    delete_rr,
    copy_zonefile,
    download_zonefile,
    copy_text_value,
    reset_zone,
    change_origin,
    logout,
  });
}

/**
  * Reads `user_origin` and `zone` variables from the HTML page
  * and builds the zone table and other fixes.
  */
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init_page);
  } else if (document.querySelector('meta[name="user-origin"]')) {
    init_page();
  }
}

export {
  escape_html,
  safe_to_unicode,
  safe_to_ascii,
  ttl_html,
  zone_table_row,
  update_soa_summary,
  fix_ttl_placeholder,
  current_date_id,
  next_soa_serial,
  update_zonefile,
  remove_rr_update_alerts,
  rebuild_zone,
  is_rr_deletable,
  rebuild_zone_table,
  set_input_previews,
  init_page,
  create_record_a,
  create_record_aaaa,
  create_record_cname,
  create_record_mx,
  create_record_txt,
  create_record_ns,
  create_record_srv,
  create_record_caa,
  edit_rr,
  cancel_edit_rr,
  show_rr_error,
  create_record_generic,
  evaluate_form_button,
  check_button,
  set_input_validation_state,
  get_dns_name_error,
  is_valid_dns_name,
  validate_hostname,
  validate_cname_hostname,
  validate_ttl,
  validate_ipv4,
  validate_ipv6,
  validate_a,
  validate_aaaa,
  validate_priority,
  validate_nameserver,
  validate_txt,
  validation_functions,
  validate_input,
  set_input_validations,
  delete_rr,
  domain_sanitizer,
  logout,
  fqdn,
  copy_fqdn,
  copy_text_value,
  copy_zonefile,
  download_zonefile,
  reset_zone,
  get_root_domain,
  get_origin_subdomain_error,
  validate_new_origin_input,
  evaluate_change_origin_form,
  set_change_origin_listeners,
  change_origin,
  set_zone,
  get_zone,
  set_user_origin,
  get_user_origin,
};
