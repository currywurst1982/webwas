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

  if (cfg.servers.length === 0) {
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
    url: normalizeUrl(s.url || `http://${s.host || 'localhost'}:${s.port || 9990}/management`),
    username: s.username || '',
    password: s.password || '',
    allowLocalHeapDump: Boolean(s.allowLocalHeapDump),
    rejectUnauthorized: s.rejectUnauthorized !== false,
  }));

  fs.mkdirSync(cfg.dataDir, { recursive: true });
  fs.mkdirSync(path.join(cfg.dataDir, 'heapdumps'), { recursive: true });
  return cfg;
}

function normalizeUrl(url) {
  const u = String(url).replace(/\/+$/, '');
  return /\/management$/.test(u) ? u : `${u}/management`;
}

module.exports = { load, ROOT };
