// https://github.com/elgs/dns-zonefile
//
const defaultTemplate = `; Zone: {zone}
; Last modified {datetime}

{$origin}
{$ttl}

{name} {ttl}  IN  SOA {mname} {rname} ({serial} {refresh} {retry} {expire} {minimum})

{ns}
{mx}
{a}
{aaaa}
{cname}
{ptr}
{txt}
{srv}
{spf}
{caa}
{ds}

`;

/////////////////////////////////////////////////////////////////////////////////////
//                                                               __                //
//                                                              /  |               //
//   ______    ______   _______    ______    ______   ______   _$$ |_     ______   //
//  /      \  /      \ /       \  /      \  /      \ /      \ / $$   |   /      \  //
// /$$$$$$  |/$$$$$$  |$$$$$$$  |/$$$$$$  |/$$$$$$  |$$$$$$  |$$$$$$/   /$$$$$$  | //
// $$ |  $$ |$$    $$ |$$ |  $$ |$$    $$ |$$ |  $$/ /    $$ |  $$ | __ $$    $$ | //
// $$ \__$$ |$$$$$$$$/ $$ |  $$ |$$$$$$$$/ $$ |     /$$$$$$$ |  $$ |/  |$$$$$$$$/  //
// $$    $$ |$$       |$$ |  $$ |$$       |$$ |     $$    $$ |  $$  $$/ $$       | //
//  $$$$$$$ | $$$$$$$/ $$/   $$/  $$$$$$$/ $$/       $$$$$$$/    $$$$/   $$$$$$$/  //
// /  \__$$ |                                                                      //
// $$    $$/                                                                       //
//  $$$$$$/                                                                        //
//                                                                                 //
/////////////////////////////////////////////////////////////////////////////////////
let generate = function (options, template) {
  const json = JSON.parse(JSON.stringify(options));
  template = template || defaultTemplate;
  template = process$ORIGIN(json['$origin'], template);
  template = process$TTL(json['$ttl'], template);
  template = processSOA(json['soa'], template);
  template = processValues(json, template);
  template = processNS(json['ns'] || [], template);
  template = processA(json['a'] || [], template);
  template = processAAAA(json['aaaa'] || [], template);
  template = processCNAME(json['cname'] || [], template);
  template = processMX(json['mx'] || [], template);
  template = processPTR(json['ptr'] || [], template);
  template = processSRV(json['srv'] || [], template);
  template = processSPF(json['spf'] || [], template);
  template = processCAA(json['caa'] || [], template);
  template = processDS(json['ds'] || [], template);
  template = processTXT(json['txt'] || [], template);
  return template.replace(/\n{2,}/gim, '\n\n');
};

let process$ORIGIN = function (data, template) {
  let ret = '';
  if (typeof data !== 'undefined') {
    ret += '$ORIGIN ' + data;
  }
  return template.replace('{$origin}', () => ret);
};

let process$TTL = function (data, template) {
  let ret = '';
  if (typeof data !== 'undefined') {
    ret += '$TTL ' + data;
  }
  return template.replace('{$ttl}', () => ret);
};

let processSOA = function (data, template) {
  let ret = template;
  if (!data) {
    return ret;
  }
  data.name = data.name || '@';
  data.ttl = data.ttl || '';
  Object.keys(data).map(key => {
    ret = ret.replace('{' + key + '}', () => String(data[key]));
  });
  return ret;
};

let processNS = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tNS\t' + value.host + '\n';
  }
  return template.replace('{ns}', () => ret);
};

let processA = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tA\t' + value.ip + '\n';
  }
  return template.replace('{a}', () => ret);
};

let processAAAA = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tAAAA\t' + value.ip + '\n';
  }
  return template.replace('{aaaa}', () => ret);
};

let processCNAME = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tCNAME\t' + value.alias + '\n';
  }
  return template.replace('{cname}', () => ret);
};

let processMX = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tMX\t' + value.preference + '\t' + value.host + '\n';
  }
  return template.replace('{mx}', () => ret);
};

let processPTR = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tPTR\t' + value.host + '\n';
  }
  return template.replace('{ptr}', () => ret);
};

let chunkTxtString = function (str, maxLen = 255) {
  if (str.length === 0) {
    return ['""'];
  }
  const chunks = [];
  let i = 0;
  while (i < str.length) {
    let end = Math.min(i + maxLen, str.length);
    // Avoid splitting right after a trailing backslash escape
    let backslashes = 0;
    let j = end - 1;
    while (j >= i && str[j] === '\\') {
      backslashes++;
      j--;
    }
    if (backslashes % 2 === 1 && end < str.length) {
      end--;
    }
    chunks.push('"' + str.slice(i, end) + '"');
    i = end;
  }
  return chunks;
};

let formatTxtData = function (txt) {
  if (txt === undefined || txt === null) {
    return '""';
  }
  const raw = String(txt).replace(/\r?\n/g, ' ').trim();
  if (!raw) {
    return '""';
  }
  const tokens = splitArgs(raw, null, true);
  const allQuoted = tokens.length > 0 && tokens.every(
    t => t.length >= 2 && t.startsWith('"') && t.endsWith('"')
  );
  if (allQuoted) {
    const out = [];
    for (const token of tokens) {
      const inner = token.slice(1, -1);
      out.push(...chunkTxtString(inner, 255));
    }
    return out.join(' ');
  }
  // Unquoted TXT input: escape unescaped backslashes and double quotes, then quote & chunk
  let escaped = '';
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '\\') {
      if (i + 1 < raw.length && (raw[i + 1] === '"' || raw[i + 1] === '\\')) {
        escaped += '\\' + raw[i + 1];
        i++;
      } else {
        escaped += '\\\\';
      }
    } else if (ch === '"') {
      escaped += '\\"';
    } else {
      escaped += ch;
    }
  }
  return chunkTxtString(escaped, 255).join(' ');
};

let processTXT = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tTXT\t' + formatTxtData(value.txt) + '\n';
  }
  return template.replace('{txt}', () => ret);
};

let processSRV = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tSRV\t' + value.priority + '\t';
    ret += value.weight + '\t';
    ret += value.port + '\t';
    ret += value.target + '\n';
  }
  return template.replace('{srv}', () => ret);
};

let processSPF = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += 'IN\tSPF\t' + value.data + '\n';
  }
  return template.replace('{spf}', () => ret);
};

let processCAA = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += `IN\tCAA\t${value.flags}\t${value.tag}\t${value.value}\n`
  }
  return template.replace('{caa}', () => ret);
};

let processDS = function (data, template) {
  let ret = '';
  for (let value of data) {
    ret += (value.name || '@') + '\t';
    if (value.ttl) ret += value.ttl + '\t';
    ret += `IN\tDS\t${value.key_tag}\t${value.algorithm}\t${value.digest_type}\t${value.digest}\n`
  }
  return template.replace('{ds}', () => ret);
};

let processValues = function (options, template) {
  const zoneName = options['$origin'] || (options['soa'] && options['soa']['name']) || '';
  template = template.replace('{zone}', () => zoneName);
  template = template.replace('{datetime}', () => (new Date()).toISOString());
  return template.replace('{time}', () => String(Math.round(Date.now() / 1000)));
};

////////////////////////////////////////////////////////
//   ______    ______    ______    _______   ______   //
//  /      \  /      \  /      \  /       | /      \  //
// /$$$$$$  | $$$$$$  |/$$$$$$  |/$$$$$$$/ /$$$$$$  | //
// $$ |  $$ | /    $$ |$$ |  $$/ $$      \ $$    $$ | //
// $$ |__$$ |/$$$$$$$ |$$ |       $$$$$$  |$$$$$$$$/  //
// $$    $$/ $$    $$ |$$ |      /     $$/ $$       | //
// $$$$$$$/   $$$$$$$/ $$/       $$$$$$$/   $$$$$$$/  //
// $$ |                                               //
// $$ |                                               //
// $$/                                                //
//                                                    //
////////////////////////////////////////////////////////
let parse = function (text) {
  text = removeComments(text);
  text = flatten(text);
  return parseRRs(text);
};

let removeComments = function (text) {
  const lines = text.split(/\r?\n/);
  let ret = '';
  for (const line of lines) {
    if (line.trim().startsWith(';')) {
      continue;
    }
    const tokens = splitArgs(line, ';', true);
    for (const token of tokens) {
      ret += token;
      if (token.endsWith('\\')) {
        ret += ';';
      } else {
        ret += '\n';
        break;
      }
    }
  }
  return ret;
};

let flatten = function (text) {
  let re = /(^|[ \t]+)SOA([ \t]+\S+[ \t]+\S+\s*)\(([^)]*)\)/im;
  let match = re.exec(text);
  if (match !== null) {
    let mnameRname = match[2].replace(/\s+/gm, ' ');
    let params = match[3].replace(/\s+/gm, ' ').trim();
    let soa = match[1] + 'SOA' + mnameRname + params;
    return text.substring(0, match.index) + soa + text.substring(match.index + match[0].length);
  } else {
    return text;
  }
};

let normalizeRR = function (rr) {
  let rrArray = splitArgs(rr, null, true);
  let hasName = !rr.match(/^\s+/);
  let hasTtl = false;

  // According to RFC 1035:
  // <rr> contents take one of the following forms:
  // [<TTL>] [<class>] <type> <RDATA> -- We assume this one
  // [<class>] [<TTL>] <type> <RDATA>
  let idx = hasName ? 1 : 0;
  if (idx < rrArray.length && !isNaN(rrArray[idx])) {
    hasTtl = true;
    idx++;
  }
  if (idx < rrArray.length && rrArray[idx].toUpperCase() === 'IN') {
    rrArray[idx] = 'IN';
    idx++;
    if (!hasTtl && idx < rrArray.length && !isNaN(rrArray[idx])) {
      const ttlVal = rrArray[idx];
      rrArray[idx] = 'IN';
      rrArray[idx - 1] = ttlVal;
      hasTtl = true;
      idx++;
    }
  } else {
    rrArray.splice(idx, 0, 'IN');
    idx++;
  }

  let rrType = idx < rrArray.length ? rrArray[idx].toUpperCase() : '';
  if (idx < rrArray.length) {
    rrArray[idx] = rrType;
  }

  return {
    rrType,
    tokens: rrArray,
    hasName: hasName,
    hasTtl: hasTtl,
    typeIndex: idx
  };
};

let parseRRs = function (text) {
  let ret = {};
  let rrs = text.split('\n');
  let lastOwnerName = '@';
  for (let rr of rrs) {
    const trimmed = rr.trim();
    if (!trimmed) {
      continue;
    }
    let rrArray = splitArgs(rr, null, true);
    if (trimmed.toUpperCase().startsWith('$ORIGIN')) {
      ret.$origin = rrArray[1];
    } else if (trimmed.toUpperCase().startsWith('$TTL')) {
      ret.$ttl = rrArray[1];
    } else {
      const nrr = normalizeRR(rr);
      if (nrr.hasName) {
        lastOwnerName = nrr.tokens[0];
      } else {
        nrr.defaultName = lastOwnerName;
      }
      // console.log(nrr);
      switch (nrr.rrType) {
        case 'SOA':
          if (!nrr.hasName) {
            nrr.tokens.unshift(lastOwnerName);
          }
          ret.soa = parseSOA(nrr.tokens);
          break;
        case 'TXT':
          ret.txt = ret.txt || [];
          ret.txt.push(parseTXT(nrr, ret.txt));
          break;
        case 'NS':
          ret.ns = ret.ns || [];
          ret.ns.push(parseNS(nrr, ret.ns));
          break;
        case 'A':
          ret.a = ret.a || [];
          ret.a.push(parseA(nrr, ret.a));
          break;
        case 'AAAA':
          ret.aaaa = ret.aaaa || [];
          ret.aaaa.push(parseAAAA(nrr, ret.aaaa));
          break;
        case 'CNAME':
          ret.cname = ret.cname || [];
          ret.cname.push(parseCNAME(nrr, ret.cname));
          break;
        case 'MX':
          ret.mx = ret.mx || [];
          ret.mx.push(parseMX(nrr, ret.mx));
          break;
        case 'PTR':
          ret.ptr = ret.ptr || [];
          ret.ptr.push(parsePTR(nrr, ret.ptr, ret.$origin));
          break;
        case 'SRV':
          ret.srv = ret.srv || [];
          ret.srv.push(parseSRV(nrr, ret.srv));
          break;
        case 'SPF':
          ret.spf = ret.spf || [];
          ret.spf.push(parseSPF(nrr, ret.spf));
          break;
        case 'CAA':
          ret.caa = ret.caa || [];
          ret.caa.push(parseCAA(nrr, ret.caa));
          break;
        case 'DS':
          ret.ds = ret.ds || [];
          ret.ds.push(parseDS(nrr, ret.ds));
          break;
      }
    }
  }
  return ret;
};

let resolveMissingName = function (rrData, recordsSoFar) {
  if (!rrData.hasName) {
    if (rrData.defaultName) {
      rrData.tokens.unshift(rrData.defaultName);
    } else if (recordsSoFar && recordsSoFar.length) {
      rrData.tokens.unshift(recordsSoFar[recordsSoFar.length - 1].name);
    } else {
      rrData.tokens.unshift('@');
    }
  }
};

let parseSOA = function (rrTokens) {
  let soa = {};
  let l = rrTokens.length;
  soa.name = rrTokens[0];
  soa.minimum = parseInt(rrTokens[l - 1], 10);
  soa.expire = parseInt(rrTokens[l - 2], 10);
  soa.retry = parseInt(rrTokens[l - 3], 10);
  soa.refresh = parseInt(rrTokens[l - 4], 10);
  soa.serial = parseInt(rrTokens[l - 5], 10);
  soa.rname = rrTokens[l - 6];
  soa.mname = rrTokens[l - 7];
  if (!isNaN(rrTokens[1])) soa.ttl = parseInt(rrTokens[1], 10);
  return soa;
};

let parseNS = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    host: rrTokens[l - 1]
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseA = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    ip: rrTokens[l - 1]
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseAAAA = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    ip: rrTokens[l - 1]
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseCNAME = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    alias: rrTokens[l - 1]
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseMX = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    preference: parseInt(rrTokens[l - 2], 10),
    host: rrTokens[l - 1]
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseTXT = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  const txtArray = rrTokens.slice(rrData.typeIndex + 1);
  resolveMissingName(rrData, recordsSoFar);

  let result = {
    name: rrTokens[0],
    txt: txtArray.join(' ')
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parsePTR = function (rrData, recordsSoFar, currentOrigin) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    fullname: rrTokens[0] + '.' + currentOrigin,
    host: rrTokens[l - 1]
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseSRV = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    target: rrTokens[l - 1],
    priority: parseInt(rrTokens[l - 4], 10),
    weight: parseInt(rrTokens[l - 3], 10),
    port: parseInt(rrTokens[l - 2], 10)
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseSPF = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  const txtArray = rrTokens.slice(rrData.typeIndex + 1);
  resolveMissingName(rrData, recordsSoFar);

  let result = {
    name: rrTokens[0],
    data: txtArray.join(' ')
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseCAA = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    flags: parseInt(rrTokens[l - 3], 10),
    tag: rrTokens[l - 2],
    value: rrTokens[l - 1],
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let parseDS = function (rrData, recordsSoFar) {
  let rrTokens = rrData.tokens;
  resolveMissingName(rrData, recordsSoFar);

  let l = rrTokens.length;
  let result = {
    name: rrTokens[0],
    key_tag: rrTokens[l - 4],
    algorithm: rrTokens[l - 3],
    digest_type: rrTokens[l - 2],
    digest: rrTokens[l - 1],
  };

  if (rrData.hasTtl) result.ttl = parseInt(rrTokens[1], 10);
  return result;
};

let splitArgs = function (input, sep, keepQuotes) {
  let separator = sep || /\s/g;
  let doubleQuoteOpen = false;
  let tokenBuffer = [];
  let ret = [];

  let arr = input.split('');
  for (let i = 0; i < arr.length; ++i) {
    let element = arr[i];
    if (doubleQuoteOpen && element === '\\' && i + 1 < arr.length) {
      tokenBuffer.push(element);
      tokenBuffer.push(arr[++i]);
      continue;
    }
    let matches = element.match(separator);
    if (element === '"') {
      if (keepQuotes === true) {
        tokenBuffer.push(element);
      }
      doubleQuoteOpen = !doubleQuoteOpen;
      continue;
    }

    if (!doubleQuoteOpen && matches) {
      if (tokenBuffer.length > 0) {
        ret.push(tokenBuffer.join(''));
        tokenBuffer = [];
      }
    } else {
      tokenBuffer.push(element);
    }
  }
  if (tokenBuffer.length > 0) {
    ret.push(tokenBuffer.join(''));
  } else if (!!sep) {
    ret.push('');
  }
  return ret;
};
