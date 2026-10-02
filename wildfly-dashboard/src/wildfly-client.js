'use strict';

// Minimal client for the WildFly HTTP management API (the same API used by
// jboss-cli, the HAL console and the wildfly-mcp server). It speaks the JSON
// DMR format on POST /management and authenticates with HTTP Digest, which is
// the default mechanism of the WildFly ManagementRealm.

const crypto = require('crypto');
const http = require('http');
const https = require('https');

class WildFlyError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'WildFlyError';
    this.status = status;
  }
}

function parseChallenges(header) {
  if (!header) return [];
  const headers = Array.isArray(header) ? header : [header];
  const challenges = [];
  for (const h of headers) {
    for (const part of h.split(/,\s*(?=(?:Digest|Basic|Bearer)\s)/i)) {
      const m = part.match(/^\s*(\w+)\s*(.*)$/s);
      if (!m) continue;
      const params = {};
      const re = /(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/g;
      let p;
      while ((p = re.exec(m[2])) !== null) params[p[1].toLowerCase()] = p[2] !== undefined ? p[2] : p[3];
      challenges.push({ scheme: m[1].toLowerCase(), params });
    }
  }
  return challenges;
}

function hashFor(algorithm) {
  const a = String(algorithm || 'MD5').toUpperCase().replace(/-SESS$/, '');
  if (a === 'MD5') return 'md5';
  if (a === 'SHA-256') return 'sha256';
  if (a === 'SHA-512-256') return 'sha512-256';
  return null;
}

class WildFlyClient {
  constructor(server, { timeoutMs = 15000 } = {}) {
    this.server = server;
    this.url = new URL(server.url);
    this.timeoutMs = timeoutMs;
    this.digest = null; // cached challenge so most calls need a single round trip
    this.nc = 0;
  }

  authHeader(method, uri) {
    const { username, password } = this.server;
    if (!username) return null;
    if (!this.digest) return null;
    if (this.digest.scheme === 'basic') {
      return 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
    }
    const p = this.digest.params;
    const algo = hashFor(p.algorithm);
    const H = (s) => crypto.createHash(algo).update(s).digest('hex');
    const cnonce = crypto.randomBytes(8).toString('hex');
    const nc = (++this.nc).toString(16).padStart(8, '0');
    let ha1 = H(`${username}:${p.realm}:${password}`);
    if (/-sess$/i.test(p.algorithm || '')) ha1 = H(`${ha1}:${p.nonce}:${cnonce}`);
    const ha2 = H(`${method}:${uri}`);
    const qop = p.qop ? (p.qop.split(',').map((s) => s.trim()).includes('auth') ? 'auth' : null) : null;
    const response = qop
      ? H(`${ha1}:${p.nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
      : H(`${ha1}:${p.nonce}:${ha2}`);
    const parts = [
      `username="${username}"`, `realm="${p.realm}"`, `nonce="${p.nonce}"`, `uri="${uri}"`,
      `response="${response}"`,
    ];
    if (p.algorithm) parts.push(`algorithm=${p.algorithm}`);
    if (p.opaque) parts.push(`opaque="${p.opaque}"`);
    if (qop) parts.push(`qop=${qop}`, `nc=${nc}`, `cnonce="${cnonce}"`);
    return 'Digest ' + parts.join(', ');
  }

  rawRequest(body, auth) {
    const lib = this.url.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(body));
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'Content-Length': payload.length,
    };
    if (auth) headers.Authorization = auth;
    return new Promise((resolve, reject) => {
      const req = lib.request(this.url, {
        method: 'POST',
        headers,
        timeout: this.timeoutMs,
        rejectUnauthorized: this.server.rejectUnauthorized,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('timeout', () => req.destroy(new WildFlyError(`WildFly 관리 API 응답 시간 초과 (${this.timeoutMs}ms)`, 504)));
      req.on('error', (e) => reject(e instanceof WildFlyError ? e : new WildFlyError(`WildFly 연결 실패: ${e.message}`, 502)));
      req.end(payload);
    });
  }

  /** Sends one DMR operation and returns the parsed JSON response (outcome not checked). */
  async request(op) {
    const uri = this.url.pathname + this.url.search;
    let res = await this.rawRequest(op, this.authHeader('POST', uri));
    if (res.status === 401) {
      const challenges = parseChallenges(res.headers['www-authenticate']);
      const digest = challenges.find((c) => c.scheme === 'digest' && hashFor(c.params.algorithm) === 'md5') ||
        challenges.find((c) => c.scheme === 'digest' && hashFor(c.params.algorithm)) ||
        challenges.find((c) => c.scheme === 'basic');
      if (!digest) throw new WildFlyError('지원하지 않는 WildFly 인증 방식입니다', 502);
      if (!this.server.username) throw new WildFlyError('WildFly 관리 사용자 계정이 설정되지 않았습니다', 502);
      this.digest = digest;
      this.nc = 0;
      res = await this.rawRequest(op, this.authHeader('POST', uri));
      if (res.status === 401) {
        this.digest = null;
        throw new WildFlyError('WildFly 관리 사용자 인증 실패 (add-user.sh 로 만든 관리 계정을 확인하세요)', 502);
      }
    }
    let json;
    try {
      json = JSON.parse(res.body);
    } catch (e) {
      throw new WildFlyError(`WildFly 응답을 해석할 수 없습니다 (HTTP ${res.status})`, 502);
    }
    return json;
  }

  async execute(op) {
    const json = await this.request(op);
    if (json.outcome !== 'success') {
      throw new WildFlyError(failureText(json['failure-description']) || '작업 실패', 502);
    }
    return json.result;
  }

  /** Runs several operations in a single composite request; failed steps resolve to `undefined`. */
  async composite(steps) {
    // A composite fails as a whole when one step fails, but WildFly still
    // returns every step's outcome in "result", so keep the successful ones.
    const json = await this.request({ operation: 'composite', address: [], steps });
    const result = json.result || {};
    return steps.map((_, i) => {
      const step = result[`step-${i + 1}`];
      return step && step.outcome === 'success' ? step.result : undefined;
    });
  }
}

function failureText(f) {
  if (!f) return '';
  if (typeof f === 'string') return f;
  return JSON.stringify(f);
}

/** Converts "/core-service=platform-mbean/type=memory" into a DMR address list. */
function addr(path) {
  if (Array.isArray(path)) return path;
  return String(path).split('/').filter(Boolean).map((seg) => {
    const i = seg.indexOf('=');
    return { [seg.slice(0, i)]: seg.slice(i + 1) };
  });
}

module.exports = { WildFlyClient, WildFlyError, addr, parseChallenges };
