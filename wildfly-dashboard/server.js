'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');

const config = require('./src/config');
const { WildFlyClient } = require('./src/wildfly-client');
const { MockClient } = require('./src/mock');
const collectors = require('./src/collectors');
const threadAnalyzer = require('./src/thread-analyzer');
const { HeapDumpManager } = require('./src/heapdump');
const discovery = require('./src/discovery');
const { UserStore, requireLogin, requireAdmin, publicUser, validatePassword } = require('./src/auth');

const cfg = config.load();
const users = new UserStore(cfg.dataDir);
const heapDumps = new HeapDumpManager(cfg);

// ---- instance registry: servers from the config file + instances discovered on this host
const staticServers = cfg.servers;
let discoveredServers = [];
let lastDiscovery = null;
const clients = new Map(); // id -> { key, client }

const sameEndpoint = (url) => url.replace('//localhost', '//127.0.0.1').toLowerCase();
const allServers = () => [...staticServers, ...discoveredServers];
const findServer = (id) => allServers().find((s) => s.id === id);

function clientFor(server) {
  const key = `${server.url}|${server.username}|${server.password}`;
  const cached = clients.get(server.id);
  if (cached && cached.key === key) return cached.client;
  const client = cfg.mock ? new MockClient(server) : new WildFlyClient(server, { timeoutMs: cfg.requestTimeoutMs });
  clients.set(server.id, { key, client });
  return client;
}

function instanceName(p) {
  if (p.serverName) return p.serverName;
  const base = p.baseDir ? path.basename(p.baseDir) : '';
  if (base && base !== 'standalone') return base;
  const conf = (p.configFile || '').replace(/^.*[\\/]/, '').replace(/\.xml$/, '');
  return conf && conf !== 'standalone' ? `${conf} :${p.port}` : `WildFly :${p.port}`;
}

function runDiscovery() {
  if (!cfg.discovery.enabled || cfg.mock) return;
  const procs = discovery.scan();
  const configured = new Map(staticServers.map((s) => [sameEndpoint(s.url), s]));
  const next = [];
  const ports = procs.map((p) => p.port);
  for (const p of procs) {
    const known = configured.get(sameEndpoint(p.url));
    if (known) {
      // Already configured by hand: just remember which process answers there.
      Object.assign(known, { pid: p.pid, user: p.user });
      continue;
    }
    // Two processes resolving to the same port means one of them was mis-detected;
    // keep both (the PID check flags the wrong one) with distinct ids.
    const clash = ports.filter((x) => x === p.port).length > 1;
    next.push({
      id: clash ? `local-${p.port}-pid${p.pid}` : `local-${p.port}`,
      name: instanceName(p),
      url: p.url,
      username: cfg.discovery.username,
      password: cfg.discovery.password,
      allowLocalHeapDump: cfg.discovery.allowLocalHeapDump,
      rejectUnauthorized: true,
      discovered: true,
      pid: p.pid,
      user: p.user,
      baseDir: p.baseDir,
      configFile: p.configFile,
      portOffset: p.offset,
    });
  }
  discoveredServers = next;
  lastDiscovery = Date.now();
  for (const id of clients.keys()) if (!findServer(id)) clients.delete(id);
}

function sessionSecret() {
  if (process.env.DASHBOARD_SESSION_SECRET) return process.env.DASHBOARD_SESSION_SECRET;
  const file = path.join(cfg.dataDir, '.session-secret');
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return fs.readFileSync(file, 'utf8').trim();
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback');

app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
  });
  next();
});

app.use(session({
  name: 'wfdash.sid',
  secret: sessionSecret(),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'strict', secure: cfg.secureCookie, maxAge: cfg.sessionTimeoutMinutes * 60 * 1000 },
}));
app.use(express.json({ limit: '100kb' }));

// State-changing API calls must come from the dashboard's own scripts.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('X-Requested-With') !== 'wildfly-dashboard') {
    return res.status(403).json({ error: '허용되지 않은 요청입니다' });
  }
  next();
});

// --- pages ------------------------------------------------------------------
const PUBLIC = path.join(__dirname, 'public');
const loggedIn = (req) => Boolean(req.session.username && users.find(req.session.username));

app.get('/', (req, res) => res.redirect(loggedIn(req) ? '/app' : '/login'));
app.get('/login', (req, res) => (loggedIn(req) ? res.redirect('/app') : res.sendFile(path.join(PUBLIC, 'login.html'))));
app.get('/app', (req, res) => (loggedIn(req) ? res.sendFile(path.join(PUBLIC, 'app.html')) : res.redirect('/login')));
app.use('/static', express.static(PUBLIC, { index: false }));
app.use('/vendor/chart.js', express.static(path.join(__dirname, 'node_modules', 'chart.js', 'dist')));

// --- auth -------------------------------------------------------------------
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요' });
  const result = users.authenticate(username.trim(), password, req.ip);
  if (result.error) return res.status(result.locked ? 429 : 401).json({ error: result.error });
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: '세션 생성 실패' });
    req.session.username = result.user.username;
    res.json({ user: publicUser(result.user) });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('wfdash.sid');
    res.json({ ok: true });
  });
});

const api = express.Router();
api.use(requireLogin(users));

api.get('/auth/me', (req, res) => res.json({ user: publicUser(req.user), mock: cfg.mock }));
api.post('/auth/password', (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  try {
    users.changePassword(req.user.username, String(currentPassword || ''), String(newPassword || ''));
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- user management (admin) ---------------------------------------------------
api.get('/users', requireAdmin, (req, res) => {
  users.reloadIfChanged();
  res.json(users.users.map((u) => ({ ...publicUser(u), createdAt: u.createdAt, lastLoginAt: u.lastLoginAt || null })));
});
api.post('/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body || {};
  const err = validatePassword(password);
  if (err) return res.status(400).json({ error: err });
  if (users.find(username)) return res.status(409).json({ error: '이미 존재하는 사용자입니다' });
  try {
    users.upsert(String(username || ''), password, role || 'viewer', { mustChangePassword: true });
    res.status(201).json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
api.delete('/users/:username', requireAdmin, (req, res) => {
  if (req.params.username === req.user.username) return res.status(400).json({ error: '자기 자신은 삭제할 수 없습니다' });
  users.reloadIfChanged();
  const before = users.users.length;
  users.users = users.users.filter((u) => u.username !== req.params.username);
  if (users.users.length === before) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
  users.save();
  res.json({ ok: true });
});

// --- WildFly data -------------------------------------------------------------
const publicServer = (s) => ({
  id: s.id,
  name: s.name,
  url: s.url,
  source: s.discovered ? 'discovered' : 'config',
  pid: s.pid || null,
  user: s.user || null,
  baseDir: s.baseDir || null,
  allowLocalHeapDump: s.allowLocalHeapDump && !cfg.mock,
});

api.get('/servers', (req, res) => res.json(allServers().map(publicServer)));

// Status of every instance at once, for the multi-instance overview.
api.get('/instances', async (req, res) => {
  const timeout = (ms) => new Promise((_, reject) => setTimeout(() => reject(new Error('응답 시간 초과')), ms));
  const list = await Promise.all(allServers().map(async (s) => {
    const out = { ...publicServer(s), ok: false, error: null, warning: null, summary: null };
    try {
      out.summary = await Promise.race([collectors.summary(clientFor(s)), timeout(6000)]);
      out.ok = true;
      if (s.pid && out.summary.pid && s.pid !== out.summary.pid) {
        out.warning = `관리 포트가 다른 JVM(PID ${out.summary.pid})에 연결됩니다. 포트 오프셋이 standalone.xml 에만 설정된 경우 config.json 에 직접 등록하세요.`;
      }
    } catch (e) {
      out.error = e.message;
    }
    return out;
  }));
  res.json({ discoveryEnabled: cfg.discovery.enabled && !cfg.mock, lastDiscovery, instances: list });
});

function withServer(handler) {
  return async (req, res) => {
    const server = findServer(req.params.id);
    if (!server) return res.status(404).json({ error: '서버를 찾을 수 없습니다 (인스턴스가 종료되었을 수 있습니다)' });
    try {
      await handler(req, res, server, clientFor(server));
    } catch (e) {
      res.status(e.status && e.status >= 400 && e.status < 600 ? e.status : 502).json({ error: e.message });
    }
  };
}

api.get('/servers/:id/info', withServer(async (req, res, server, client) => {
  res.json(await collectors.serverInfo(client));
}));

api.get('/servers/:id/memory', withServer(async (req, res, server, client) => {
  res.json(await collectors.memory(client));
}));

api.get('/servers/:id/datasources', withServer(async (req, res, server, client) => {
  res.json(await collectors.datasources(client));
}));

api.post('/servers/:id/datasources/:name/test', requireAdmin, withServer(async (req, res, server, client) => {
  if (!/^[\w.$-]+$/.test(req.params.name)) return res.status(400).json({ error: '잘못된 데이터소스 이름' });
  res.json(await collectors.testConnection(client, req.params.name, req.query.xa === 'true'));
}));

const lastThreadDump = new Map(); // server id -> last dump, for text download

api.get('/servers/:id/threads', withServer(async (req, res, server, client) => {
  const dump = await collectors.threadDump(client);
  lastThreadDump.set(server.id, dump);
  res.json({ ...dump, analysis: threadAnalyzer.analyze(dump) });
}));

api.get('/servers/:id/threads.txt', withServer(async (req, res, server, client) => {
  const dump = req.query.fresh === 'true' || !lastThreadDump.has(server.id)
    ? await collectors.threadDump(client) : lastThreadDump.get(server.id);
  const stamp = new Date(dump.timestamp).toISOString().replace(/[:.]/g, '-');
  res.attachment(`threaddump-${server.id}-${stamp}.txt`).type('text/plain; charset=utf-8')
    .send(threadAnalyzer.toText(dump, server));
}));

// --- heap dumps ---------------------------------------------------------------
const upload = multer({
  dest: path.join(cfg.dataDir, 'heapdumps', 'upload-tmp'),
  limits: { fileSize: cfg.heapDump.maxUploadMB * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(hprof|hprof\.gz|bin|txt|histo|log)$/i.test(file.originalname);
    cb(ok ? null : Object.assign(new Error('.hprof, .hprof.gz 또는 클래스 히스토그램(.txt) 파일만 업로드할 수 있습니다'), { status: 400 }), ok);
  },
});

const handleErrors = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
};

api.get('/heapdumps', handleErrors((req, res) => res.json(heapDumps.list())));

api.post('/heapdumps/upload', requireAdmin, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? `파일이 너무 큽니다 (최대 ${cfg.heapDump.maxUploadMB}MB)` : err.message;
      return res.status(err.status || 400).json({ error: msg });
    }
    if (!req.file) return res.status(400).json({ error: '파일을 선택하세요' });
    try {
      const meta = await heapDumps.addUpload(req.file.path, req.file.originalname, req.user.username);
      heapDumps.analyze(meta.id);
      res.status(201).json(meta);
    } catch (e) {
      res.status(e.status || 500).json({ error: e.message });
    }
  });
});

api.post('/servers/:id/heapdump', requireAdmin, withServer(async (req, res, server, client) => {
  if (cfg.mock) throw Object.assign(new Error('Mock 모드에서는 힙 덤프 생성을 지원하지 않습니다. .hprof 파일을 업로드해 분석해 보세요'), { status: 400 });
  if (!server.allowLocalHeapDump) {
    throw Object.assign(new Error('이 서버는 원격 서버로 설정되어 있습니다. WildFly 호스트에서 jcmd <pid> GC.heap_dump 로 생성한 파일을 업로드하세요 (또는 allowLocalHeapDump 설정)'), { status: 400 });
  }
  const info = await collectors.serverInfo(client);
  const meta = await heapDumps.generate(server, info.jvm && info.jvm.pid, { live: req.body.live !== false, user: req.user.username });
  heapDumps.analyze(meta.id);
  res.status(201).json(meta);
}));

api.post('/heapdumps/:dumpId/analyze', handleErrors((req, res) => {
  const job = heapDumps.analyze(req.params.dumpId);
  res.status(202).json({ status: job.status, progress: job.progress });
}));

api.get('/heapdumps/:dumpId/analysis', handleErrors((req, res) => {
  const result = heapDumps.analysis(req.params.dumpId);
  if (!result) return res.status(404).json({ error: '아직 분석 결과가 없습니다' });
  res.json(result);
}));

api.get('/heapdumps/:dumpId/download', requireAdmin, handleErrors((req, res) => {
  const f = heapDumps.filePath(req.params.dumpId);
  res.download(f.path, f.name);
}));

api.delete('/heapdumps/:dumpId', requireAdmin, handleErrors((req, res) => {
  heapDumps.remove(req.params.dumpId);
  res.json({ ok: true });
}));

app.use('/api', api);
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

if (require.main === module) {
  const generated = users.ensureAdmin();
  runDiscovery();
  if (cfg.discovery.enabled && !cfg.mock) setInterval(runDiscovery, cfg.discovery.intervalSeconds * 1000).unref();
  app.listen(cfg.port, cfg.host, () => {
    console.log(`WildFly Dashboard: http://${cfg.host === '0.0.0.0' ? 'localhost' : cfg.host}:${cfg.port}${cfg.mock ? '  (MOCK 모드)' : ''}`);
    for (const s of allServers()) {
      console.log(`  - ${s.name} <${s.url}>${s.discovered ? `  (자동 탐지, PID ${s.pid}, ${s.user})` : ''}`);
    }
    if (cfg.discovery.enabled && !cfg.mock) {
      console.log(`WildFly 프로세스 자동 탐지: ${cfg.discovery.intervalSeconds}초마다${cfg.discovery.username ? '' : ' (관리 계정 미설정: config.json 의 discovery.username/password 설정 필요)'}`);
    }
    if (generated) {
      console.log('='.repeat(64));
      console.log(` 초기 관리자 계정이 생성되었습니다.  ID: admin   PW: ${generated}`);
      console.log(' 첫 로그인 시 비밀번호를 변경해야 합니다.');
      console.log('='.repeat(64));
    }
  });
}

module.exports = { app, users, cfg };
