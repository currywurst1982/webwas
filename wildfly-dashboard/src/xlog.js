'use strict';

// XLog (Scouter-style transaction scatter) built from the Undertow access log.
// Every finished HTTP request is one line in the access log; with %D (or %T)
// in the pattern it carries the processing time. The dashboard tails that file
// on the same host and turns each new line into a transaction.

const fs = require('fs');
const path = require('path');
const { addr } = require('./wildfly-client');

/** Pattern the dashboard configures: end time with milliseconds, request, status, bytes, elapsed ms, thread. */
const XLOG_PATTERN = '%h %{time,yyyy-MM-dd\'T\'HH:mm:ss.SSSZ} "%r" %s %b %D "%I"';

const ALIASES = {
  common: '%h %l %u %t "%r" %s %b',
  combined: '%h %l %u %t "%r" %s %b "%{i,Referer}" "%{i,User-Agent}"',
};

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** Parses "06/Oct/2026:00:28:38 +0000" (common log format time). */
function parseClfTime(s) {
  const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))? ([+-])(\d{2})(\d{2})$/.exec(s);
  if (!m) return NaN;
  const utc = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6], m[7] ? +m[7].padEnd(3, '0') : 0);
  const off = (+m[9] * 60 + +m[10]) * 60000 * (m[8] === '+' ? 1 : -1);
  return utc - off;
}

/** Parses ISO-like times such as 2026-10-06T00:28:38.067+0000 (adds the colon Date.parse wants). */
function parseIsoTime(s) {
  const t = Date.parse(String(s).replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
  return Number.isNaN(t) ? Date.parse(s) : t;
}

/**
 * Compiles an Undertow access-log pattern into a line parser.
 * Returns null when the pattern has no processing time (%D / %T).
 */
function compilePattern(pattern) {
  const p = ALIASES[pattern] || pattern;
  const fields = [];
  let re = '^';
  const tokenRe = /%\{([^}]*)\}|%([a-zA-Z])/g;
  let last = 0;
  let m;
  while ((m = tokenRe.exec(p)) !== null) {
    re += p.slice(last, m.index).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ +/g, '\\s+');
    last = tokenRe.lastIndex;
    const brace = m[1];
    const letter = m[2];
    let field = null;
    let group = '(.*?)';
    if (brace !== undefined) {
      if (/^time,/.test(brace)) { field = 'isoTime'; group = '(\\S+(?: \\S+)?)'; }
    } else {
      switch (letter) {
        case 'h': case 'a': case 'A': field = letter === 'h' ? 'ip' : null; group = '(\\S+)'; break;
        case 't': field = 'clfTime'; group = '\\[([^\\]]+)\\]'; break;
        case 'r': field = 'request'; break;
        case 's': field = 'status'; group = '(\\d{3}|-)'; break;
        case 'b': case 'B': field = 'bytes'; group = '(\\S+)'; break;
        case 'D': field = 'elapsedMs'; group = '(\\d+|-)'; break;
        case 'T': field = 'elapsedSec'; group = '([\\d.]+|-)'; break;
        case 'I': field = 'thread'; break;
        case 'm': field = 'method'; group = '(\\S+)'; break;
        case 'U': field = 'uri'; group = '(\\S+)'; break;
        case 'q': field = 'query'; group = '(\\S*)'; break;
        default: group = '(.*?)';
      }
    }
    fields.push(field);
    re += group;
  }
  re += `${p.slice(last).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ +/g, '\\s+')}\\s*$`;
  if (!fields.includes('elapsedMs') && !fields.includes('elapsedSec')) return null;
  if (!fields.includes('isoTime') && !fields.includes('clfTime')) return null;
  const lineRe = new RegExp(re);

  return (line) => {
    const mm = lineRe.exec(line);
    if (!mm) return null;
    const v = {};
    fields.forEach((f, i) => { if (f) v[f] = mm[i + 1]; });
    const end = v.isoTime !== undefined ? parseIsoTime(v.isoTime) : parseClfTime(v.clfTime);
    const elapsed = v.elapsedMs !== undefined ? Number(v.elapsedMs) : Math.round(Number(v.elapsedSec) * 1000);
    if (Number.isNaN(end) || Number.isNaN(elapsed)) return null; // "-" = start time not recorded
    let method = v.method;
    let uri = v.uri;
    if (v.request !== undefined) {
      const r = /^(\S+)\s+(\S+)/.exec(v.request);
      if (r) { method = method || r[1]; uri = uri || r[2]; }
    }
    if (v.query && uri && !uri.includes('?')) uri += v.query.startsWith('?') ? v.query : `?${v.query}`;
    return {
      end,
      elapsed,
      status: v.status && v.status !== '-' ? Number(v.status) : 0,
      method: method || '-',
      uri: uri || '-',
      ip: v.ip || null,
      bytes: v.bytes && /^\d+$/.test(v.bytes) ? Number(v.bytes) : 0,
      thread: v.thread || null,
    };
  };
}

/** Normalizes a URI into a service name: no query/session id, numeric and UUID segments folded. */
function serviceName(method, uri) {
  const p = String(uri || '-').split('?')[0].split(';')[0]
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/{uuid}')
    .replace(/\/\d+(?=\/|$)/g, '/{id}');
  return `${method} ${p}`;
}

/** Follows a growing log file across rotation/truncation; reads only what was appended. */
class FileTail {
  constructor(file, { backfillBytes = 4 * 1024 * 1024, maxReadBytes = 16 * 1024 * 1024 } = {}) {
    this.file = file;
    this.backfillBytes = backfillBytes;
    this.maxReadBytes = maxReadBytes;
    this.offset = null;
    this.ino = null;
    this.partial = '';
  }

  read() {
    let st;
    try {
      st = fs.statSync(this.file);
    } catch (e) {
      return { lines: [], error: e.code === 'ENOENT' ? 'access log 파일이 아직 없습니다 (요청이 들어오면 생성됩니다)' : e.message };
    }
    let skipFirst = false;
    if (this.offset === null || st.ino !== this.ino || st.size < this.offset) {
      // First read (start near the end) or the file was rotated/truncated (start from the top).
      const first = this.offset === null;
      this.offset = first ? Math.max(0, st.size - this.backfillBytes) : 0;
      skipFirst = first && this.offset > 0;
      this.ino = st.ino;
      this.partial = '';
    }
    if (st.size === this.offset) return { lines: [] };
    let start = this.offset;
    if (st.size - start > this.maxReadBytes) { start = st.size - this.maxReadBytes; skipFirst = true; this.partial = ''; }
    const len = st.size - start;
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(this.file, 'r');
    try {
      fs.readSync(fd, buf, 0, len, start);
    } finally {
      fs.closeSync(fd);
    }
    this.offset = st.size;
    const text = this.partial + buf.toString('utf8');
    const lines = text.split('\n');
    this.partial = lines.pop();
    if (skipFirst) lines.shift();
    return { lines: lines.filter((l) => l.trim()) };
  }
}

/** Ring buffer of parsed transactions with increasing sequence numbers. */
class XLogStore {
  constructor(max = 50000) {
    this.max = max;
    this.items = [];
    this.seq = 0;
  }

  add(tx) {
    tx.seq = ++this.seq;
    this.items.push(tx);
    if (this.items.length > this.max) this.items.splice(0, this.items.length - this.max);
  }

  since(seq, minEnd) {
    let i = this.items.length;
    while (i > 0 && this.items[i - 1].seq > seq) i--;
    return this.items.slice(i).filter((t) => t.end >= minEnd);
  }
}

// ---------------------------------------------------------------- management model

async function readSetup(client) {
  const [undertow, paths] = await client.composite([
    { operation: 'read-resource', address: addr('/subsystem=undertow'), recursive: true, 'resolve-expressions': true, 'include-defaults': true },
    { operation: 'read-children-resources', address: [], 'child-type': 'path', 'include-runtime': true },
  ]);
  if (!undertow) throw new Error('undertow 서브시스템을 읽지 못했습니다');
  const pathOf = (name) => (paths && paths[name] && paths[name].path) || null;
  const settings = [];
  const listeners = [];
  for (const [serverName, server] of Object.entries(undertow.server || {})) {
    for (const type of ['http-listener', 'https-listener', 'ajp-listener']) {
      for (const [name, l] of Object.entries(server[type] || {})) {
        listeners.push({ server: serverName, type, name, recordStart: Boolean(l['record-request-start-time']) });
      }
    }
    for (const [hostName, host] of Object.entries(server.host || {})) {
      const a = host.setting && host.setting['access-log'];
      if (!a) continue;
      const base = a['relative-to'] ? pathOf(a['relative-to']) : null;
      const dir = base ? path.resolve(base, a.directory || '.') : (a.directory || pathOf('jboss.server.log.dir'));
      const file = a['use-server-log'] ? null : path.join(dir || '.', `${a.prefix || 'access_log.'}${a.suffix || 'log'}`);
      settings.push({ server: serverName, host: hostName, pattern: a.pattern || 'common', file, useServerLog: Boolean(a['use-server-log']), prefix: a.prefix });
    }
  }
  return { settings, listeners };
}

/** Turns on what XLog needs. Returns whether a reload is required for it to take effect. */
async function enable(client, instanceName, { overwritePattern = false } = {}) {
  const setup = await readSetup(client);
  const steps = [];
  const host = setup.settings.find((s) => s.server === 'default-server' && s.host === 'default-host') || setup.settings[0];
  if (!host) {
    const safe = String(instanceName || 'wildfly').replace(/[^A-Za-z0-9._-]/g, '_');
    steps.push({
      operation: 'add',
      address: addr('/subsystem=undertow/server=default-server/host=default-host/setting=access-log'),
      pattern: XLOG_PATTERN,
      prefix: `access_log_${safe}.`,
    });
  } else if (!compilePattern(host.pattern) || host.useServerLog) {
    if (!overwritePattern) {
      return { needsPatternChange: true, currentPattern: host.pattern };
    }
    const a = addr(`/subsystem=undertow/server=${host.server}/host=${host.host}/setting=access-log`);
    steps.push({ operation: 'write-attribute', address: a, name: 'pattern', value: XLOG_PATTERN });
    if (host.useServerLog) steps.push({ operation: 'write-attribute', address: a, name: 'use-server-log', value: false });
  }
  let reloadRequired = false;
  for (const l of setup.listeners) {
    if (l.recordStart) continue;
    steps.push({
      operation: 'write-attribute',
      address: addr(`/subsystem=undertow/server=${l.server}/${l.type}=${l.name}`),
      name: 'record-request-start-time',
      value: true,
    });
    reloadRequired = true;
  }
  if (steps.length) await client.execute({ operation: 'composite', address: [], steps });
  return { changed: steps.length, reloadRequired };
}

module.exports = { XLOG_PATTERN, compilePattern, serviceName, FileTail, XLogStore, readSetup, enable, parseClfTime, parseIsoTime };
