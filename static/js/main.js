/**
  * @type {string} Stores the origin name for this user's zone.
  *                Obtained from the html code.
  */
var user_origin;

/**
* @type {string} Stores the zone data in json format following https://github.com/elgs/dns-zonefile
  *                Obtained from the html code.
  */
var zone;


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


/**
  * Builds a row with a DNS record for the DNS zone table
  *
  * @param {string} [name="type"] - Record type, eg. A, AAAA,  MX, TXT...
  * @param {string} [name="name"] - Hostname.
  * @param {string} [name="value"] - Contents of the record.
  * @param {string} [name="ttl"] - TTL of the actual record (may be unknown).
  * @param {string} [name="zone_ttl"] - Global $TTL of the zone, used when record's TTL is unknown.
  * @returns {string} HTML code for the table row.
  */
function zone_table_row(type, name, value, ttl, zone_ttl, id, deletable = true, is_default_at = false) {
  const safe_type = type ? escape_html(type) : '&nbsp;';
  let name_html;
  if (is_default_at) {
    name_html = '<small class="text-body-secondary">@</small>';
  } else if (name === undefined || name === null) {
    name_html = '&nbsp;';
  } else if (name === '@') {
    name_html = '@';
  } else {
    name_html = escape_html(safe_to_unicode(name));
  }
  const safe_value = value ?? '&nbsp;';
  const ttl_show = ttl_html(ttl, zone_ttl);
  let html = `
          <tr>
              <th scope="row">${safe_type}</th>
              <td class="copy-fqdn"><span class="name">${name_html}</span><span class="copy-fqdn-hint text-primary">copy FQDN</span></td>
              <td>${safe_value}</td>
              <td>${ttl_show}</td>
        `;
  if (deletable) {
    html += ` <td class="text-end">
                  <button class="btn btn-sm btn-outline-danger" rr_id="${escape_html(id)}" onclick="delete_rr(this)">
                  <i class="bi bi-trash"></i> Delete
                </button>
              </td>`;
  } else {
    html += ` <td class="text-end">
                  <small class="text-body-secondary">Not deletable</small>
              </td>`;
  }
  html += '</tr>';
  return html;
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
// function next_soa_serial(serial) {
//   const num_str = String(serial);
//   const date_id = current_date_id();
//   if (num_str.length === 10) {
//     if (num_str.slice(0, 8) == date_id) {
//       new_id = Number(num_str.slice(-2)) + 1;
//       return date_id + String(new_id);
//     }
//   }
//   return date_id + '00';
// }

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
        const msg = error + '\n Reloading page in 5 seconds...';
        reject({ success: false, type: 'Network error', message: msg });
        // Suele ser error de fin de sesión. Recargamos por si pide login.
        // TODO: sólo recargar si el usuario ha perdido sesión. Me falla por problemas CORS que no consigo resolver.
        setTimeout(() => {
          window.location.reload();
        }, 5000);
      });
  })
}

function remove_rr_update_alerts() {
  document.querySelectorAll('.new-rr-update-msg').forEach(alert => {
    alert.remove();
  })
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
        zone_file.textContent = new_zone_text;
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
    return false;
  }
  if (type == 'a' && rr_name == soa_ns) {
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
  var tbody = document.querySelector("#zone-table tbody");
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
      const deletable = is_rr_deletable('aaaa', rr, zone.soa);
      rows_html += zone_table_row('AAAA', rr['name'], escape_html(rr['ip'] ?? ''), rr['ttl'], zone_ttl, rr.id, deletable);
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
      const value = `${escape_html(rr['priority'] ?? '')} ${escape_html(rr['weight'] ?? '')} ${escape_html(rr['port'] ?? '')} ${escape_html(safe_to_unicode(rr['target'] || ''))}`;
      rows_html += zone_table_row('SRV', rr['name'], value, rr['ttl'], zone_ttl, rr.id);
    }
  }
  tbody.innerHTML = rows_html;
  tbody.querySelectorAll(".copy-fqdn").forEach(element => {
    element.addEventListener("click", () => copy_fqdn(element));
  });
}


/**
  * Reads `user_origin` and `zone` variables from the HTML page
  * and builds the zone table and other fixes.
  */
document.addEventListener('DOMContentLoaded', function() {
  user_origin = document.querySelector('meta[name="user-origin"]').content;
  zone = parse(document.getElementById('zone-file').textContent);
  rebuild_zone_table();
  fix_ttl_placeholder();
  set_input_validations();
});

// Live preview for name input with suffix ".example.com"
document.querySelectorAll('input[preview$="true"]').forEach(input => {
  input.addEventListener('input', (e) => {
    validate_input(input);
    const preview = document.getElementById(`${e.target.id}-preview`);
    if (e.target.value == '@') {
      if (input.classList.contains('nameserver-validation') || input.classList.contains('cname-hostname-validation')) {
        preview.textContent = '\xa0';
      } else {
        preview.textContent = user_origin;
      }
      return;
    }
    const name = safe_to_ascii(e.target.value.trim());
    if (!name) {
      preview.textContent = '\xa0';
      return;
    }
    if (name.slice(-1) == '.') {
      preview.textContent = name;
      return;
    }
    preview.textContent = name + '.' + user_origin;
  });
});

// function create_record_a(button) {
//   if (!zone) { return; }
//   const valid = validate_record_a(button);
//   if (!valid) {
//     return;
//   }
//   const name = toASCII(document.getElementById("a-name").value);
//   if (!name) {
//     return;
//   }
//   const ip = document.getElementById("a-ip").value;
//   const ttl = document.getElementById("a-ttl").value;
//   rr = {};
//   if (name) {
//     rr["name"] = name;
//   }
//   if (ip) {
//     rr["ip"] = ip;
//   }
//   if (ttl) {
//     rr["ttl"] = ttl;
//   }
//   if (Object.keys(rr).length == 0) {
//     return;
//   }
//   new_zone = structuredClone(zone);
//   if ('a' in new_zone) {
//     new_zone['a'].push(rr);
//   } else {
//     new_zone['a'] = [rr];
//   }
//   rebuild_zone(button, new_zone)
//     .catch(error => {
//       html_error = `
//         <div class="row mt-1">
//         <div class="col">
//           <div class="alert alert-danger new-rr-update-msg" role="alert">
//             <h5 class="alert-heading">Error adding the record:</h5>
//             <p><pre>${error.type}</pre></p>
//             <hr>
//             <p class="mb-0"><pre>${error.message}</pre></p>
//           </div>
//         </div>
//         </div>
//         `;
//       div = document.createElement('div');
//       div.innerHTML = html_error;
//       button.parentElement.parentElement.insertAdjacentElement("afterend", div.firstElementChild);
//     })
// }

function create_record_a(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("a-name").value.trim()),
    'ip': document.getElementById("a-ip").value.trim(),
    'ttl': document.getElementById("a-ttl").value.trim(),
  }
  create_record_generic(button, 'a', rr);
}

function create_record_aaaa(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("aaaa-name").value.trim()),
    'ip': document.getElementById("aaaa-ip").value.trim(),
    'ttl': document.getElementById("aaaa-ttl").value.trim(),
  }
  create_record_generic(button, 'aaaa', rr);
}

function create_record_cname(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("cname-name").value.trim()),
    'alias': safe_to_ascii(document.getElementById("cname-alias").value.trim()),
    'ttl': document.getElementById("cname-ttl").value.trim(),
  }
  create_record_generic(button, 'cname', rr);
}

function create_record_mx(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("mx-name").value.trim()),
    'host': safe_to_ascii(document.getElementById("mx-host").value.trim()),
    'preference': document.getElementById("mx-priority").value.trim(),
    'ttl': document.getElementById("mx-ttl").value.trim(),
  }
  create_record_generic(button, 'mx', rr);
}

function create_record_txt(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("txt-name").value.trim()),
    'txt': document.getElementById("txt-value").value.trim(),
    'ttl': document.getElementById("txt-ttl").value.trim(),
  }
  create_record_generic(button, 'txt', rr);
}

function create_record_ns(button) {
  const rr = {
    'name': safe_to_ascii(document.getElementById("ns-name").value.trim()),
    'host': safe_to_ascii(document.getElementById("ns-nameserver").value.trim()),
    'ttl': document.getElementById("ns-ttl").value.trim(),
  }
  create_record_generic(button, 'ns', rr);
}

function show_rr_error(anchor_element, heading, error) {
  const html_error = `
    <div class="row mt-1 new-rr-update-msg">
    <div class="col">
      <div class="alert alert-danger" role="alert">
        <h5 class="alert-heading">${escape_html(heading)}</h5>
        <pre>${escape_html(error.type ?? 'Error')}</pre>
        <hr>
        <pre class="mb-0">${escape_html(error.message ?? String(error))}</pre>
      </div>
    </div>
    </div>
    `;
  const div = document.createElement('div');
  div.innerHTML = html_error;
  anchor_element.insertAdjacentElement("afterend", div.firstElementChild);
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
  if (type in new_zone) {
    new_zone[type].push(rr);
  } else {
    new_zone[type] = [rr];
  }
  rebuild_zone(button, new_zone)
    .catch(error => {
      show_rr_error(button.parentElement.parentElement, 'Error adding the record:', error);
    })
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

function is_valid_dns_name(value, allow_at = true) {
  if (!value) {
    return false;
  }
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) {
    return false;
  }
  if (trimmed === '@') {
    return allow_at;
  }
  if (trimmed.includes('@') || trimmed === '.' || trimmed.startsWith('.') || trimmed.includes('..')) {
    return false;
  }
  const ascii = safe_to_ascii(trimmed);
  if (!ascii) {
    return false;
  }
  const without_trailing_dot = ascii.endsWith('.') ? ascii.slice(0, -1) : ascii;
  if (!without_trailing_dot || without_trailing_dot.length > 253) {
    return false;
  }
  const labels = without_trailing_dot.split('.');
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    if (!label || label.length > 63) {
      return false;
    }
    if (i === 0 && label === '*') {
      continue;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(label)) {
      return false;
    }
  }
  return true;
}

function validate_hostname(input) {
  if (is_valid_dns_name(input.value, true)) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
  }
  evaluate_form_button(input);
}

function validate_cname_hostname(input) {
  if (is_valid_dns_name(input.value, false)) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
  }
  evaluate_form_button(input);
}

function validate_ttl(input) {
  if (input.validity && input.validity.badInput) {
    input.classList.add('is-invalid');
    evaluate_form_button(input);
    return;
  }
  const raw = input.value.trim();
  if (!raw) {
    input.classList.remove('is-invalid');
    evaluate_form_button(input);
    return;
  }
  if (!/^\d+$/.test(raw)) {
    input.classList.add('is-invalid');
    evaluate_form_button(input);
    return;
  }
  const number = Number(raw);
  if (!Number.isInteger(number) || number < 60 || number > 2147483647) {
    input.classList.add('is-invalid');
  } else {
    input.classList.remove('is-invalid');
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
  if (validate_ipv4(input.value.trim())) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
  }
  evaluate_form_button(input);
}

function validate_aaaa(input) {
  if (validate_ipv6(input.value.trim())) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
  }
  evaluate_form_button(input);
}

function validate_priority(input) {
  if (input.validity && input.validity.badInput) {
    input.classList.add('is-invalid');
    evaluate_form_button(input);
    return;
  }
  const raw = input.value.trim();
  if (!/^\d+$/.test(raw)) {
    input.classList.add('is-invalid');
    evaluate_form_button(input);
    return;
  }
  const number = Number(raw);
  if (Number.isInteger(number) && number >= 0 && number <= 65535) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
  }
  evaluate_form_button(input);
}

function validate_nameserver(input) {
  if (is_valid_dns_name(input.value, false)) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
  }
  evaluate_form_button(input);
}

function validate_txt(input) {
  if (input.value && input.value.trim().length > 0) {
    input.classList.remove('is-invalid');
  } else {
    input.classList.add('is-invalid');
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
}

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
        validation_functions[v_class](input);
      });
    });
  }
}

function delete_rr(button) {
  const rr_type = button.closest('tr').querySelector('th').innerText.toLowerCase();
  const rrid = parseInt(button.attributes.rr_id.nodeValue, 10);
  if (!(rr_type in zone)) {
    return;
  }
  const idx = zone[rr_type].findIndex(item => item.id == rrid);
  if (idx == -1) {
    return;
  }
  const new_zone = structuredClone(zone);
  new_zone[rr_type].splice(idx, 1);
  rebuild_zone(button, new_zone)
    .then(_ => {
      // window.location.reload(true);
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

// function to_unicode(domain) {
//   return new URL(`http://${domain}`).hostname;
// }

// function to_punycode(domain) {
//   try {
//     return domain.normalize("NFC").split('.').map(part =>
//       part.startsWith('xn--') ? part : new URL(`http://${part}.com`).hostname.split('.')[0]
//     ).join('.');
//   } catch (error) {
//     return '';
//   }
// }

function logout() {
  window.location.href = 'https://auth.infor.tiernogalvan.es/logout?rd=https://dns.infor.tiernogalvan.es';
}


function fqdn(hostname) {
  const origin = document.querySelector('meta[name="user-origin"]').content;
  if (hostname == '@') {
    return origin;
  }
  if (hostname.slice(-1) == '.') {
    return hostname;
  }
  return hostname + '.' + origin;
}

/*
 *
 *
 *
 */

function copy_fqdn(element) {
  const textToCopy = fqdn(element.querySelector(".name").textContent);
  navigator.clipboard.writeText(textToCopy)
    .then(() => {
      const copyHint = element.querySelector(".copy-fqdn-hint");
      copyHint.textContent = "copied!";  // Change "copy" to "ok"
      setTimeout(() => {             // Reset after 1.5 seconds
        copyHint.textContent = "copy FQDN";
      }, 1500);
    })
    .catch(err => console.error("Could not copy text: ", err));
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
      // document.querySelector('#zone-file').textContent = data;
      // zone = parse(data);
      // rebuild_zone_table();
      // msg = document.querySelector('#reset-error-msg').closest('div');
      // msg.classList.add('d-none');
    })
    .catch(error => {
      const err_span = document.querySelector('#reset-error-msg');
      if (err_span) {
        err_span.textContent = 'Failed resetting the zone.';
        err_span.closest('div').classList.remove('d-none');
      }
    });
}
