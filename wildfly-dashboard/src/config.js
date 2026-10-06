'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw new Error(`설정 파일을 읽을 수 없습니다: ${file}: ${e.message}`);
  }
}

function bool(v, def) {
  if (v === undefined || v === null || v === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function load() {
  const configFile = process.env.DASHBOARD_CONFIG || path.join(ROOT, 'config', 'config.json');
  const file = readJson(configFile) || {};
  const env = process.env;

  const cfg = {
    port: Number(env.DASHBOARD_PORT || file.port || 9080),
    host: env.DASHBOARD_HOST || file.host || '0.0.0.0',
    dataDir: path.resolve(ROOT, env.DASHBOARD_DATA_DIR || file.dataDir || 'data'),
    mock: bool(env.DASHBOARD_MOCK, Boolean(file.mock)),
    secureCookie: bool(env.DASHBOARD_SECURE_COOKIE, Boolean(file.secureCookie)),
    sessionTimeoutMinutes: Number(env.DASHBOARD_SESSION_TIMEOUT || file.sessionTimeoutMinutes || 30),
    requestTimeoutMs: Number(file.requestTimeoutMs || 15000),
    heapDump: {
      maxUploadMB: Number(env.DASHBOARD_MAX_UPLOAD_MB || (file.heapDump && file.heapDump.maxUploadMB) || 8192),
      jcmd: env.DASHBOARD_JCMD || (file.heapDump && file.heapDump.jcmd) || 'jcmd',
    },
    servers: Array.isArray(file.servers) ? file.servers : [],
  };

  // Automatic discovery of WildFly processes running on this host.
  const disc = file.discovery || {};
  cfg.discovery = {
    enabled: bool(env.DASHBOARD_DISCOVERY, disc.enabled !== undefined ? Boolean(disc.enabled) : fs.existsSync('/proc/self/cmdline')),
    intervalSeconds: Number(disc.intervalSeconds || 30),
    username: env.DASHBOARD_DISCOVERY_USER || disc.username || '',
    password: env.DASHBOARD_DISCOVERY_PASSWORD || disc.password || '',
    allowLocalHeapDump: disc.allowLocalHeapDump !== false,
  };

  // A single server can be configured purely through environment variables
  // (same variables as wildfly-mcp-server uses for its credentials).
  if (env.WILDFLY_URL || env.WILDFLY_HOST) {
    const url = env.WILDFLY_URL ||
      `${bool(env.WILDFLY_HTTPS, false) ? 'https' : 'http'}://${env.WILDFLY_HOST}:${env.WILDFLY_PORT || 9990}/management`;
    cfg.servers.unshift({
      id: 'env',
      name: env.WILDFLY_NAME || 'WildFly',
      url,
      username: env.WILDFLY_USER || env.WILDFLY_MCP_SERVER_USER_NAME,
      password: env.WILDFLY_PASSWORD || env.WILDFLY_MCP_SERVER_USER_PASSWORD,
      allowLocalHeapDump: bool(env.WILDFLY_LOCAL_HEAPDUMP, false),
    });
  }

  if (cfg.mock && cfg.servers.length === 0) {
    // Several simulated instances so the multi-instance view can be tried out.
    cfg.servers.push(
      { id: 'local-9990', name: 'was01', url: 'http://127.0.0.1:9990/management', discovered: true, pid: 24816, user: 'wildfly',
        mock: { name: 'was01', pid: 24816 } },
      { id: 'local-10090', name: 'was02', url: 'http://127.0.0.1:10090/management', discovered: true, pid: 25120, user: 'wildfly',
        mock: { name: 'was02', host: 'wildfly-prod-02.example.com', pid: 25120, heapMaxMB: 4096, heapLow: 0.55, heapHigh: 0.93, threads: 148, metaBaseMB: 388, uptimeHours: 30, tps: 25, latency: 1.6 } },
      { id: 'local-10190', name: 'was03', url: 'http://127.0.0.1:10190/management', discovered: true, pid: 25544, user: 'wildfly',
        mock: { name: 'was03', host: 'wildfly-prod-03.example.com', pid: 25544, state: 'reload-required', heapMaxMB: 1024, threads: 41, uptimeHours: 2 } },
      { id: 'batch01', name: 'batch01 (원격)', url: 'http://10.0.12.40:9990/management',
        mock: { name: 'batch01', down: true } },
    );
  }

  if (cfg.servers.length === 0 && !cfg.discovery.enabled) {
    cfg.servers.push({
      id: 'local',
      name: 'Local WildFly',
      url: 'http://localhost:9990/management',
      username: 'admin',
      password: 'admin',
      allowLocalHeapDump: true,
    });
  }

  cfg.servers = cfg.servers.map((s, i) => ({
    id: String(s.id || `server${i + 1}`),
    name: s.name || s.id || `server${i + 1}`,
    // Without an explicit name a local server takes its instance name once discovery finds its process.
    autoName: !s.name,
    url: normalizeUrl(s.url || `http://${s.host || 'localhost'}:${s.port || 9990}/management`),
    username: s.username || '',
    password: s.password || '',
    allowLocalHeapDump: Boolean(s.allowLocalHeapDump),
    rejectUnauthorized: s.rejectUnauthorized !== false,
    discovered: Boolean(s.discovered),
    pid: s.pid || null,
    user: s.user || null,
    mock: s.mock,
  }));

  // Discovered instances reuse these credentials unless discovery has its own.
  if (!cfg.discovery.username) {
    const local = cfg.servers.find((s) => /\/\/(127\.0\.0\.1|localhost)[:/]/.test(s.url) && s.username);
    if (local) Object.assign(cfg.discovery, { username: local.username, password: local.password });
  }

  fs.mkdirSync(cfg.dataDir, { recursive: true });
  fs.mkdirSync(path.join(cfg.dataDir, 'heapdumps'), { recursive: true });
  return cfg;
}

function normalizeUrl(url) {
  const u = String(url).replace(/\/+$/, '');
  return /\/management$/.test(u) ? u : `${u}/management`;
}

module.exports = { load, ROOT };
