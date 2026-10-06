'use strict';

/* global Chart */

// If the page and script ever disagree (e.g. a stale browser cache after an update),
// say so instead of sitting on "연결 확인 중".
window.addEventListener('error', (e) => {
  const banner = document.getElementById('error-banner');
  const pill = document.getElementById('conn-status');
  if (banner) {
    banner.hidden = false;
    banner.textContent = `화면 스크립트 오류: ${e.message} (${(e.filename || '').split('/').pop()}:${e.lineno || '?'}). 대시보드를 업데이트한 직후라면 Ctrl+F5 (강력 새로고침) 로 다시 불러오세요.`;
  }
  if (pill) pill.innerHTML = '<span class="dot critical"></span><span>화면 오류</span>';
});

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

// Must match <meta name="dashboard-build"> in app.html; a mismatch means the two files come from different versions.
const BUILD = '2026.10.06.3';
const missingElements = [];
/** addEventListener that tolerates a missing element (an out-of-date app.html must not stop the whole page). */
function on(sel, ev, fn) {
  const el = $(sel);
  if (el) el.addEventListener(ev, fn);
  else missingElements.push(sel);
}
const esc = (v) => String(v === undefined || v === null ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const state = {
  user: null,
  servers: [],
  server: null,
  view: 'overview',
  timer: null,
  history: [], // memory samples for the charts
  dsHistory: {}, // datasource name -> in-use connection samples
  charts: {},
  threads: null,
  heapPoll: null,
  currentAnalysis: null,
};
const HISTORY_MAX = 180;

// ---------------------------------------------------------------- utilities
async function api(path, opts = {}) {
  const headers = { 'X-Requested-With': 'wildfly-dashboard', ...(opts.headers || {}) };
  let body = opts.body;
  if (body && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs || 20000);
  let res;
  try {
    res = await fetch(`/api${path}`, { method: opts.method || 'GET', headers, body, signal: ctrl.signal });
  } catch (e) {
    throw new Error(e.name === 'AbortError' ? '대시보드 서버 응답 시간 초과' : `대시보드 서버에 연결할 수 없습니다 (${e.message})`);
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 401) { location.href = '/login'; throw new Error('로그인이 필요합니다'); }
  const data = await res.json().catch(() => ({}));
  if (res.status === 403 && data.mustChangePassword) { openPasswordModal(true); }
  if (!res.ok) throw new Error(data.error || `요청 실패 (HTTP ${res.status})`);
  return data;
}

function fmtBytes(n, digits = 1) {
  if (n === null || n === undefined || n < 0) return '-';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : digits)} ${u[i]}`;
}
function fmtAxisBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n < 10 && n % 1 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
const fmtClock = (t) => new Date(t).toTimeString().slice(0, 8);
const fmtNum = (n) => (n === null || n === undefined ? '-' : Number(n).toLocaleString('ko-KR'));
function fmtDuration(ms) {
  if (!ms && ms !== 0) return '-';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400); const h = Math.floor((s % 86400) / 3600); const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}일 ${h}시간 ${m}분`;
  if (h) return `${h}시간 ${m}분`;
  return `${m}분 ${s % 60}초`;
}
const fmtTime = (t) => (t ? new Date(t).toLocaleString('ko-KR') : '-');
const fmtMs = (ms) => (ms === null || ms === undefined ? '-' : `${fmtNum(ms)} ms`);

function level(pct) {
  if (pct === null || pct === undefined) return '';
  return pct >= 90 ? 'critical' : pct >= 75 ? 'warning' : '';
}
function levelLabel(pct) {
  const l = level(pct);
  return l === 'critical' ? '<span class="badge critical">● 위험</span>' : l === 'warning' ? '<span class="badge warning">▲ 주의</span>' : '';
}
function meter(label, used, total, valueText, noLevel = false) {
  const pct = total ? Math.min(100, (100 * used) / total) : 0;
  return `<div class="meter"><div class="row"><span>${label}</span><span class="num">${valueText || `${fmtBytes(used)} / ${fmtBytes(total)}`} ${total && !noLevel ? `(${pct.toFixed(0)}%)` : ''}</span></div>
    <div class="track" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct.toFixed(0)}" aria-label="${esc(label)}"><div class="fill ${noLevel ? '' : level(pct)}" style="width:${pct}%"></div></div></div>`;
}
function tile(label, value, sub = '', extra = '') {
  return `<div class="card stat"><div class="label">${label} ${extra}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
}
function kv(pairs) {
  return pairs.filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v, raw]) => `<dt>${esc(k)}</dt><dd>${raw ? v : esc(v)}</dd>`).join('');
}
function findingsHtml(list) {
  const icon = { critical: '!', warning: '!', info: 'i', ok: '✓' };
  return list.map((f) => `<li class="${f.level}"><span class="icon">${icon[f.level] || 'i'}</span><span>${esc(f.text)}</span></li>`).join('');
}
function toast(msg) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}
function showError(msg) {
  const b = $('#error-banner');
  b.hidden = !msg;
  b.textContent = msg || '';
  const pill = $('#conn-status');
  if (msg) pill.innerHTML = '<span class="dot critical"></span><span>연결 오류</span>';
}
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const isAdmin = () => state.user && state.user.role === 'admin';

// ---------------------------------------------------------------- navigation
const TITLES = {
  instances: '전체 인스턴스',
  xlog: 'XLog (트랜잭션)',
  overview: '대시보드', memory: '메모리 (Heap / Metaspace)', datasources: 'DB 데이터소스',
  threads: '쓰레드 덤프', heap: '힙 덤프 분석', users: '사용자 관리',
};
function setView(view) {
  if (state.xlog && view !== 'xlog') clearTimeout(state.xlog.timer);
  state.view = view;
  $$('.nav-item[data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $$('[data-view-panel]').forEach((p) => { p.hidden = p.dataset.viewPanel !== view; });
  $('#view-title').textContent = TITLES[view];
  $('#view-crumb').textContent = TITLES[view];
  try { sessionStorage.setItem('wfdash.view', view); } catch (_) { /* storage unavailable */ }
  refresh();
  schedule();
}

function schedule() {
  clearInterval(state.timer);
  const ms = Number($('#refresh-select').value);
  // Memory is sampled in the background on every view so the charts have history.
  if (ms) state.timer = setInterval(() => refresh(true), ms);
}

async function refresh(auto = false) {
  try {
    const v = state.view;
    if (v === 'instances') {
      await loadInstances();
      showError(null);
      $('#conn-status').innerHTML = '<span class="dot good"></span><span>연결됨</span>';
      return;
    }
    if (!state.server) { showError('모니터링할 WildFly 인스턴스가 없습니다. "전체 인스턴스" 화면을 확인하세요.'); return; }
    if (v === 'xlog') {
      if (!auto) await loadXlog(); // XLog polls on its own 2-second timer
      showError(null);
      $('#conn-status').innerHTML = '<span class="dot good"></span><span>연결됨</span>';
      return;
    }
    if (v === 'overview') await loadOverview();
    else if (v === 'memory') await loadMemory();
    else if (v === 'datasources') await loadDatasources();
    else if (v === 'heap' && !auto) await loadHeapList();
    else if (v === 'users' && !auto) await loadUsers();
    // Keep sampling memory on the other views so the charts have history.
    if (auto && v !== 'overview' && v !== 'memory') await sampleMemory();
    showError(null);
    $('#conn-status').innerHTML = '<span class="dot good"></span><span>연결됨</span>';
  } catch (e) {
    showError(state.server && state.view !== 'instances' ? `${state.server.name}: ${e.message}` : e.message);
  }
}

// ---------------------------------------------------------------- instances
function fmtShortDuration(ms) {
  if (!ms && ms !== 0) return '-';
  const m = Math.floor(ms / 60000); const h = Math.floor(m / 60); const d = Math.floor(h / 24);
  if (d) return `${d}일 ${h % 24}시간`;
  if (h) return `${h}시간 ${m % 60}분`;
  return `${m}분`;
}

/** Keeps the server drop-down in sync with the (possibly changing) instance list. */
function syncServers(list) {
  const ids = list.map((s) => s.id).join('|');
  if (ids === state.servers.map((s) => s.id).join('|')) { state.servers = list; return; }
  state.servers = list;
  const current = state.server && list.find((s) => s.id === state.server.id);
  $('#server-select').innerHTML = list.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
  if (current) {
    state.server = current;
    $('#server-select').value = current.id;
  } else if (list.length) {
    selectServer(list[0].id, false);
  } else {
    state.server = null;
  }
}

function selectServer(id, reload = true) {
  const server = state.servers.find((s) => s.id === id);
  if (!server) return;
  state.server = server;
  $('#server-select').value = id;
  state.history = [];
  state.dsHistory = {};
  state.threads = null;
  $('#thread-result').hidden = true;
  $('#thread-empty').hidden = false;
  resetCharts();
  xlogReset();
  if (reload) refresh();
}

function instanceCard(inst) {
  const s = inst.summary;
  const current = state.server && state.server.id === inst.id ? ' current' : '';
  const src = inst.source === 'discovered' ? '<span class="badge violet">자동 탐지</span>' : '<span class="badge blue">설정</span>';
  const head = (badge, color) => `<div class="inst-head"><div class="kpi-icon ${color}">${ICONS.server}</div>
      <div class="title"><b>${esc(inst.name)}</b><span>${esc(inst.url.replace(/\/management$/, ''))}</span></div>${badge}</div>`;
  if (!inst.ok) {
    return `<div class="card inst${current}" tabindex="0" role="button" data-inst="${esc(inst.id)}" aria-label="${esc(inst.name)} 상세 보기">
      ${head('<span class="badge critical">▲ 연결 실패</span>', 'pink')}
      <div class="inst-error">${esc(inst.error)}</div>
      <div class="inst-foot">${src}${inst.pid ? `<span class="muted">PID ${inst.pid}${inst.user ? ` · ${esc(inst.user)}` : ''}</span>` : ''}</div>
    </div>`;
  }
  const running = s.state === 'running';
  const badge = running ? '<span class="badge good">● running</span>'
    : `<span class="badge warning">▲ ${esc(s.state)}</span>`;
  const meta = s.metaspace;
  return `<div class="card inst${current}" tabindex="0" role="button" data-inst="${esc(inst.id)}" aria-label="${esc(inst.name)} 상세 보기">
    ${head(badge, running ? 'blue' : 'orange')}
    ${meter('Heap', s.heap.used, s.heap.max)}
    ${meta ? (meta.max ? meter('Metaspace', meta.used, meta.max)
    : meter('Metaspace (최대 무제한)', meta.used, meta.committed, `${fmtBytes(meta.used)} / committed ${fmtBytes(meta.committed)}`, true)) : ''}
    <div class="inst-stats">
      <div><span>쓰레드</span><b>${fmtNum(s.threads)}</b></div>
      <div><span>가동 시간</span><b>${esc(fmtShortDuration(s.uptime))}</b></div>
      <div><span>배포</span><b>${s.deployments ?? '-'}개</b></div>
      <div><span>PID</span><b>${s.pid ?? inst.pid ?? '-'}</b></div>
    </div>
    ${inst.warning ? `<div class="inst-warn">▲ ${esc(inst.warning)}</div>` : ''}
    <div class="inst-foot">${src}<span class="muted">${esc(s.name || '')} · WildFly ${esc((s.version || '').replace(/\.Final$/, ''))}${inst.user ? ` · ${esc(inst.user)}` : ''}</span>
      <button class="btn sm primary" tabindex="-1">상세 보기</button></div>
  </div>`;
}

async function loadInstances() {
  const data = await api('/instances');
  const list = data.instances;
  syncServers(list.map(({ ok, error, warning, summary, ...server }) => server));
  const okList = list.filter((i) => i.ok);
  const healthy = okList.filter((i) => i.summary.state === 'running' && !i.warning && !(i.summary.heap.percent >= 90));
  const failed = list.length - okList.length;
  const attention = okList.length - healthy.length;
  $('#inst-kpis').innerHTML = [
    kpi('server', 'blue', '전체 인스턴스', fmtNum(list.length), `자동 탐지 ${list.filter((i) => i.source === 'discovered').length} · 설정 ${list.filter((i) => i.source === 'config').length}`),
    kpi('heap', 'violet', '정상', fmtNum(healthy.length), 'running · Heap 90% 미만'),
    kpi('meta', 'orange', '주의', fmtNum(attention), 'running 아님 · Heap 90% 이상 · 포트 확인', attention ? '<span class="badge warning">▲</span>' : ''),
    kpi('threads', 'pink', '연결 실패', fmtNum(failed), '관리 API 응답 없음', failed ? '<span class="badge critical">▲</span>' : ''),
  ].join('');
  $('#inst-note').textContent = data.discoveryEnabled
    ? `이 서버에서 실행 중인 WildFly(standalone) 프로세스를 자동으로 찾습니다${data.lastDiscovery ? ` · 마지막 탐지 ${fmtClock(data.lastDiscovery)}` : ''}. 카드를 누르면 해당 인스턴스의 상세 대시보드로 이동합니다.`
    : 'config.json 에 등록된 인스턴스입니다. 카드를 누르면 해당 인스턴스의 상세 대시보드로 이동합니다.';
  $('#inst-grid').innerHTML = list.length ? list.map(instanceCard).join('')
    : `<div class="card empty" style="grid-column:1/-1">실행 중인 WildFly 인스턴스를 찾지 못했습니다.<br>
       WildFly 가 standalone 모드로 실행 중인지 확인하거나, config.json 의 servers 에 직접 등록하세요.</div>`;
}

document.addEventListener('click', (e) => {
  const card = e.target.closest('[data-inst]');
  if (!card) return;
  selectServer(card.dataset.inst, false);
  setView('overview');
});
document.addEventListener('keydown', (e) => {
  const card = e.target.closest && e.target.closest('[data-inst]');
  if (!card || (e.key !== 'Enter' && e.key !== ' ')) return;
  e.preventDefault();
  selectServer(card.dataset.inst, false);
  setView('overview');
});

// ---------------------------------------------------------------- overview
const ICONS = {
  server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>',
  heap: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="6" width="16" height="12" rx="1.5"/><path d="M8 2v4M12 2v4M16 2v4M8 18v4M12 18v4M16 18v4"/></svg>',
  meta: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/></svg>',
  threads: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h10M4 18h13"/></svg>',
};

function kpi(icon, color, label, value, sub, extra = '') {
  return `<div class="card kpi"><div class="kpi-icon ${color}">${ICONS[icon]}</div>
    <div class="body"><div class="label">${label} ${extra}</div><div class="value">${value}</div><div class="sub">${sub}</div></div></div>`;
}

/** Circular gauge; colour follows status thresholds, the value is always printed inside. */
function ring(pct, label, sub) {
  const r = 34; const c = 2 * Math.PI * r;
  const has = pct !== null && pct !== undefined && !Number.isNaN(pct);
  const v = has ? Math.max(0, Math.min(100, pct)) : 0;
  const color = !has ? 'var(--axis)' : v >= 90 ? 'var(--critical)' : v >= 75 ? 'var(--warning)' : 'var(--series-1)';
  return `<div><div class="ring" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${has ? v.toFixed(0) : ''}" aria-label="${esc(label)}">
      <svg viewBox="0 0 80 80"><circle cx="40" cy="40" r="${r}" fill="none" stroke="var(--track)" stroke-width="7"/>
      <circle cx="40" cy="40" r="${r}" fill="none" stroke="${color}" stroke-width="7" stroke-linecap="round"
        stroke-dasharray="${(c * v) / 100} ${c}"/></svg>
      <div class="val">${has ? `${v.toFixed(0)}%` : '-'}</div></div>
    <div class="ring-label">${esc(label)}</div><div class="ring-sub">${esc(sub)}</div></div>`;
}

/** Tiny area sparkline (single series, no axes) with a native tooltip. */
function sparkline(values, color = 'var(--series-1)', title = '') {
  const pts = values.filter((v) => v !== null && v !== undefined);
  if (pts.length < 2) return '<span class="muted" style="font-size:11.5px">수집 중…</span>';
  const w = 120; const h = 30; const max = Math.max(...pts); const min = Math.min(...pts);
  const span = max - min || 1;
  const xy = pts.map((v, i) => [((i / (pts.length - 1)) * w).toFixed(1), (h - 2 - ((v - min) / span) * (h - 6)).toFixed(1)]);
  const line = xy.map(([x, y], i) => `${i ? 'L' : 'M'}${x},${y}`).join('');
  const id = `sg${Math.random().toString(36).slice(2, 8)}`;
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="${esc(title)}">
    <title>${esc(title)}</title>
    <defs><linearGradient id="${id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".45"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    <path d="${line}L${w},${h}L0,${h}Z" fill="url(#${id})"/><path d="${line}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
}

const SKYLINE = '<svg class="skyline" viewBox="0 0 600 70" preserveAspectRatio="none" fill="currentColor"><path d="M0 70V48h18V36h14v12h10V22h20v26h12V40h16v30h8V30h12V14h6v16h10v40h14V44h22v26h10V34h18v36h8V20h4V8h4v12h6v50h16V42h12v28h20V30h24v40h8V50h16v20h10V26h14v44h12V38h18v32h10V18h6v52h18V46h14v24h22V34h16v36h12V44h20v26h16V28h12v42h26V40h12v30h18V50h20v20z"/></svg>';

async function loadOverview() {
  const [info, mem, ds] = await Promise.all([
    api(`/servers/${state.server.id}/info`),
    sampleMemory(),
    api(`/servers/${state.server.id}/datasources`).catch(() => null),
  ]);
  if (ds) recordDatasources(ds.datasources);
  const s = info.server; const j = info.jvm || {}; const os = info.os || {};
  const running = s.serverState === 'running';
  const stateCls = running ? 'good' : /required/.test(s.serverState) ? 'warning' : 'critical';
  const meta = mem.metaspace;
  const th = info.threads || {};

  $('#ov-kpis').innerHTML = [
    kpi('server', 'blue', '서버 상태', esc(s.serverState || '-'), `${esc(s.runningMode || '')} · ${esc(s.suspendState || '')}`, `<span class="dot ${stateCls}"></span>`),
    kpi('heap', 'violet', 'Heap 사용량', fmtBytes(mem.heap.used), `최대 ${fmtBytes(mem.heap.max)} · ${mem.heap.percent ?? '-'}%`, levelLabel(mem.heap.percent)),
    kpi('meta', 'pink', 'Metaspace', meta ? fmtBytes(meta.usage.used) : '-',
      meta ? (meta.usage.max ? `최대 ${fmtBytes(meta.usage.max)} · ${meta.usage.percent}%` : `committed ${fmtBytes(meta.usage.committed)} · 최대 무제한`) : '',
      meta && meta.usage.max ? levelLabel(meta.usage.percent) : ''),
    kpi('threads', 'orange', '쓰레드', fmtNum(th.count), `피크 ${fmtNum(th.peak)} · 데몬 ${fmtNum(th.daemon)}`),
  ].join('');

  // Hero: server identity with a strip of key numbers (the design's weather card).
  const version = (s.productVersion || '').replace(/\.Final$/, '');
  $('#ov-hero').innerHTML = `<div class="sky">${SKYLINE}
      <h3>${esc(s.productName || 'WildFly')} 서버</h3>
      <div class="tag" title="${esc(s.configFile || '')}">${esc((s.configFile || '').split(/[\\/]/).pop() || s.launchType || '')}</div>
      <div class="big">${esc(version || '-')} <small>${esc(s.launchType || '')}</small></div>
      <div class="hero-state"><span class="dot ${stateCls}"></span>${esc(s.serverState || '-')} · ${esc(s.hostName || s.name || '')}</div>
    </div>
    <div class="strip">
      <div><span>가동 시간</span><b>${esc(fmtDuration(j.uptime))}</b></div>
      <div><span>CPU 코어</span><b>${esc(os.availableProcessors ?? '-')}</b></div>
      <div><span>Load Avg</span><b>${os.systemLoadAverage >= 0 ? os.systemLoadAverage.toFixed(2) : 'N/A'}</b></div>
      <div><span>로드 클래스</span><b>${info.classLoading ? fmtNum(info.classLoading.loaded) : '-'}</b></div>
      <div><span>배포</span><b>${info.deployments.length}개</b></div>
    </div>`;

  // Resource rings.
  const dsList = ds ? ds.datasources.filter((d) => d.pool && d.pool.inUseCount !== undefined && d.maxPoolSize) : [];
  const dsMax = dsList.length ? Math.max(...dsList.map((d) => (100 * d.pool.inUseCount) / d.maxPoolSize)) : null;
  const dsWorst = dsList.length ? dsList.reduce((a, d) => ((d.pool.inUseCount / d.maxPoolSize) > (a.pool.inUseCount / a.maxPoolSize) ? d : a)) : null;
  const cpuPct = os.systemLoadAverage >= 0 && os.availableProcessors ? (100 * os.systemLoadAverage) / os.availableProcessors : null;
  $('#ov-rings').innerHTML = [
    ring(mem.heap.percent, 'Heap', `${fmtBytes(mem.heap.used)}`),
    ring(meta && meta.usage.max ? meta.usage.percent : null, 'Metaspace', meta && meta.usage.max ? fmtBytes(meta.usage.used) : '최대 무제한'),
    ring(dsMax, 'DB 풀', dsWorst ? dsWorst.name : '통계 없음'),
    ring(cpuPct, 'CPU 부하', cpuPct === null ? 'N/A' : `load ${os.systemLoadAverage.toFixed(2)}`),
  ].join('');

  $('#ov-jvm').innerHTML = kv([
    ['PID / 이름', j.name], ['VM', j.vmName], ['벤더', j.vmVendor], ['VM 버전', j.vmVersion],
    ['Java 버전', j.javaVersion || j.specVersion], ['JAVA_HOME', j.javaHome],
  ]);
  $('#ov-os').innerHTML = kv([
    ['OS', `${os.name || ''} ${os.version || ''}`.trim()], ['아키텍처', os.arch], ['CPU 코어', os.availableProcessors],
    ...info.interfaces.map((i) => [`인터페이스 ${i.name}`, i.address]),
    ['관리 API', state.server.url],
  ]);

  // Datasources with an in-use sparkline.
  $('#ov-ds').innerHTML = !ds ? '<div class="empty">데이터소스 정보를 읽을 수 없습니다</div>'
    : !ds.datasources.length ? '<div class="empty">설정된 데이터소스가 없습니다</div>'
      : `<table><thead><tr><th>이름</th><th>드라이버</th><th class="r">사용 / 최대</th><th>상태</th><th>추이</th></tr></thead><tbody>${
        ds.datasources.map((d) => {
          const p = d.pool;
          const health = dsHealth(d);
          const has = health.has;
          const badge = health.level === 'ok' && !health.badges.length ? '<span class="badge good">● 정상</span>'
            : health.badges.join(' ') || '<span class="badge good">● 정상</span>';
          return `<tr><td class="name">${esc(d.name)}${d.xa ? ' <span class="badge blue">XA</span>' : ''}<div class="muted" style="font-size:11.5px">${esc(d.jndiName)}</div></td>
            <td>${esc(d.driver)}</td><td class="r">${has ? `${fmtNum(p.inUseCount)} / ${fmtNum(d.maxPoolSize)}` : '-'}</td><td>${badge}</td>
            <td>${has ? sparkline(state.dsHistory[d.name] || [], 'var(--series-1)', `${d.name} 사용 중 커넥션`) : ''}</td></tr>`;
        }).join('')}</tbody></table>`;

  // Memory pools with a usage sparkline.
  $('#ov-pools').innerHTML = `<table><thead><tr><th>풀</th><th class="r">사용</th><th class="r">사용률</th><th>추이</th></tr></thead><tbody>${
    mem.pools.map((p) => {
      const pct = p.usage && p.usage.max ? (100 * p.usage.used) / p.usage.max : null;
      return `<tr><td class="name">${esc(p.name)}<div class="muted" style="font-size:11.5px">${esc(p.type || '')}</div></td>
        <td class="r">${fmtBytes(p.usage && p.usage.used)}</td><td class="r">${pct === null ? '-' : `${pct.toFixed(0)}%`}</td>
        <td>${sparkline(state.history.map((h) => h.pools && h.pools[p.name]), p.type === 'HEAP' ? 'var(--series-1)' : 'var(--series-4)', `${p.name} 사용량`)}</td></tr>`;
    }).join('')}</tbody></table>`;

  // Profile card (server identity).
  $('#ov-profile').innerHTML = `<div class="cover"></div><div class="avatar">WF</div>
    <div class="name">${esc(s.name || state.server.name)}</div><div class="role">${esc(state.server.name)}</div>
    <dl class="kv">${kv([
      ['호스트', s.hostName], ['제품', `${s.productName || ''} ${s.productVersion || ''}`.trim()], ['Core 버전', s.releaseVersion],
      ['설정 파일', s.configFile], ['Base 디렉터리', s.baseDir], ['로그 디렉터리', s.logDir], ['관리 API 버전', s.managementVersion],
    ])}</dl>`;

  $('#ov-dep-count').textContent = `${info.deployments.length}개`;
  $('#ov-deployments').innerHTML = info.deployments.length ? `<table><thead><tr><th>#</th><th>이름</th><th>상태</th><th>활성화 시각</th></tr></thead><tbody>${
    info.deployments.map((d, i) => {
      const cls = d.status === 'OK' ? 'good' : d.status === 'FAILED' ? 'critical' : '';
      return `<tr><td class="muted">${i + 1}</td><td class="name">${esc(d.name)}</td><td><span class="badge ${cls}">${d.status === 'OK' ? '● ' : d.status === 'FAILED' ? '▲ ' : ''}${esc(d.status || (d.enabled ? 'enabled' : 'disabled'))}</span></td><td class="muted">${esc(fmtTime(d.enabledTime))}</td></tr>`;
    }).join('')}</tbody></table>` : '<div class="empty">배포된 애플리케이션이 없습니다</div>';
  $('#ov-args').textContent = (j.inputArguments || []).join('\n') || '-';
  $('#footer-server').textContent = `${state.server.name} · ${state.server.url} · build ${BUILD}`;

  updateOverviewCharts(mem);
}

// ---------------------------------------------------------------- memory
const isYoung = (name) => /young|scavenge|copy|parnew|minor/i.test(name);

async function sampleMemory() {
  const mem = await api(`/servers/${state.server.id}/memory`);
  state.history.push({
    t: mem.timestamp,
    heapUsed: mem.heap.used, heapCommitted: mem.heap.committed, heapMax: mem.heap.max,
    metaUsed: mem.metaspace && mem.metaspace.usage.used,
    metaCommitted: mem.metaspace && mem.metaspace.usage.committed,
    metaMax: mem.metaspace && mem.metaspace.usage.max,
    pools: Object.fromEntries(mem.pools.map((p) => [p.name, p.usage ? p.usage.used : null])),
    gcYoung: mem.gc.filter((g) => isYoung(g.name)).reduce((a, g) => a + (g.count || 0), 0),
    gcOld: mem.gc.filter((g) => !isYoung(g.name)).reduce((a, g) => a + (g.count || 0), 0),
  });
  if (state.history.length > HISTORY_MAX) state.history.shift();
  state.lastMemory = mem;
  if (state.view === 'memory') updateCharts();
  return mem;
}

function recordDatasources(list) {
  const now = Date.now();
  state.dsFail = state.dsFail || {};
  for (const d of list) {
    if (!d.pool || d.pool.inUseCount === undefined) continue;
    const h = state.dsHistory[d.name] || (state.dsHistory[d.name] = []);
    h.push(d.pool.inUseCount);
    if (h.length > 40) h.shift();
    // BlockingFailureCount is cumulative since start: keep 10 minutes of samples to see whether it is growing now.
    const f = (state.dsFail[d.name] || []).filter((x) => x.t >= now - 10 * 60000);
    f.push({ t: now, v: d.pool.blockingFailureCount || 0 });
    state.dsFail[d.name] = f;
  }
}

/**
 * Pool health from the statistics that really indicate trouble:
 * - saturation: connections in use >= 90% of max-pool-size right now
 * - acquisition failures: BlockingFailureCount (IJ000453 "Unable to get managed connection") growing in the last 5 minutes
 * TimedOut is NOT a problem: it counts idle connections closed by idle-timeout-minutes.
 */
function dsHealth(d) {
  const p = d.pool;
  const has = d.statisticsEnabled && p && p.inUseCount !== undefined;
  if (!d.enabled) return { has, badges: ['<span class="badge">비활성</span>'], level: 'off' };
  if (!has) return { has, badges: ['<span class="badge violet">통계 꺼짐</span>'], level: 'off' };
  const pct = d.maxPoolSize ? (100 * p.inUseCount) / d.maxPoolSize : 0;
  const samples = (state.dsFail && state.dsFail[d.name]) || [];
  const base = samples.find((x) => x.t >= Date.now() - 5 * 60000) || samples[0];
  const recentFail = base ? Math.max(0, (p.blockingFailureCount || 0) - base.v) : 0;
  const badges = [];
  if (recentFail > 0) badges.push(`<span class="badge critical" title="최근 5분 동안 커넥션을 얻지 못한 요청 수 (IJ000453)">● 획득 실패 +${recentFail}</span>`);
  if (pct >= 90) badges.push(`<span class="badge warning" title="사용 중 커넥션이 max-pool-size 의 90% 이상">▲ 풀 포화 ${Math.round(pct)}%</span>`);
  if (!badges.length && p.blockingFailureCount > 0) {
    badges.push(`<span class="badge" title="서버 시작(또는 통계 초기화) 이후 누적. 최근 5분 동안은 늘지 않았습니다">획득 실패 누적 ${fmtNum(p.blockingFailureCount)}</span>`);
  }
  const level = recentFail > 0 ? 'critical' : pct >= 90 ? 'warning' : 'ok';
  return { has, badges, level, pct, recentFail };
}

async function loadMemory() {
  const mem = await sampleMemory();
  const meta = mem.metaspace;
  const ccs = mem.compressedClassSpace;
  const gcTime = mem.gc.reduce((a, g) => a + (g.time || 0), 0);
  const gcCount = mem.gc.reduce((a, g) => a + (g.count || 0), 0);
  $('#mem-tiles').innerHTML = [
    `<div class="card stat"><div class="label">Heap ${levelLabel(mem.heap.percent)}</div><div class="value">${fmtBytes(mem.heap.used)}</div>
      ${meter('사용 / 최대', mem.heap.used, mem.heap.max)}<div class="sub">committed ${fmtBytes(mem.heap.committed)} · init ${fmtBytes(mem.heap.init)}</div></div>`,
    `<div class="card stat"><div class="label">Metaspace ${meta ? levelLabel(meta.usage.max ? meta.usage.percent : null) : ''}</div><div class="value">${meta ? fmtBytes(meta.usage.used) : '-'}</div>
      ${meta ? (meta.usage.max ? meter('사용 / 최대', meta.usage.used, meta.usage.max)
    : meter('사용 / committed', meta.usage.used, meta.usage.committed, null, true) + '<div class="sub">MaxMetaspaceSize 미설정 (무제한)</div>') : ''}
      <div class="sub">${meta ? `peak ${fmtBytes(meta.peak && meta.peak.used)} · committed ${fmtBytes(meta.usage.committed)}` : 'Metaspace 풀 정보 없음'}</div></div>`,
    `<div class="card stat"><div class="label">Non-Heap 전체</div><div class="value">${fmtBytes(mem.nonHeap.used)}</div>
      <div class="sub">committed ${fmtBytes(mem.nonHeap.committed)}${ccs ? ` · Compressed Class ${fmtBytes(ccs.usage.used)}` : ''}</div></div>`,
    tile('GC 누적', `${fmtNum(gcCount)}회`, `총 ${fmtMs(gcTime)} · 대기 finalization ${fmtNum(mem.pendingFinalization)}`),
  ].join('');
  $('#mem-pools').innerHTML = `<table><thead><tr><th>풀</th><th>유형</th><th class="r">사용</th><th class="r">Committed</th><th class="r">최대</th><th>사용률</th></tr></thead><tbody>${
    mem.pools.map((p) => {
      const pct = p.usage && p.usage.max ? (100 * p.usage.used) / p.usage.max : null;
      return `<tr><td>${esc(p.name)}</td><td class="muted">${esc(p.type || '')}</td><td class="r">${fmtBytes(p.usage && p.usage.used)}</td><td class="r">${fmtBytes(p.usage && p.usage.committed)}</td><td class="r">${p.usage && p.usage.max ? fmtBytes(p.usage.max) : '무제한'}</td>
        <td class="bar-cell">${pct === null ? '<span class="muted">-</span>' : `<span class="num">${pct.toFixed(0)}%</span><div class="track" style="height:6px;background:var(--track);border-radius:3px"><div class="bar ${level(pct)}" style="width:${pct}%;margin:0;background:var(--${level(pct) || 'series-1'})"></div></div>`}</td></tr>`;
    }).join('')
  }</tbody></table>`;
  $('#mem-gc').innerHTML = `<table><thead><tr><th>컬렉터</th><th class="r">횟수</th><th class="r">누적 시간</th><th class="r">평균</th></tr></thead><tbody>${
    mem.gc.map((g) => `<tr><td>${esc(g.name)}</td><td class="r">${fmtNum(g.count)}</td><td class="r">${fmtMs(g.time)}</td><td class="r">${g.count ? `${(g.time / g.count).toFixed(1)} ms` : '-'}</td></tr>`).join('')
  }</tbody></table>`;
  $('#mem-classes').innerHTML = mem.classLoading ? kv([
    ['현재 로드된 클래스', fmtNum(mem.classLoading.loaded)], ['누적 로드', fmtNum(mem.classLoading.totalLoaded)],
    ['언로드', fmtNum(mem.classLoading.unloaded)],
  ]) : '';
}

function hexToRgba(hex, a) {
  const m = /^#?([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(hex.trim());
  return m ? `rgba(${parseInt(m[1], 16)},${parseInt(m[2], 16)},${parseInt(m[3], 16)},${a})` : hex;
}

/** Vertical gradient that fades the series colour into the card surface. */
function areaFill(color) {
  return (ctx) => {
    const { chart } = ctx;
    if (!chart.chartArea) return hexToRgba(color, 0.2);
    const g = chart.ctx.createLinearGradient(0, chart.chartArea.top, 0, chart.chartArea.bottom);
    g.addColorStop(0, hexToRgba(color, 0.45));
    g.addColorStop(1, hexToRgba(color, 0));
    return g;
  };
}

function baseScales(yFormat) {
  const muted = cssVar('--text-muted');
  return {
    x: { ticks: { color: muted, maxTicksLimit: 6, maxRotation: 0, font: { size: 11 } }, grid: { display: false }, border: { color: cssVar('--axis') } },
    y: { beginAtZero: true, ticks: { color: muted, callback: yFormat, font: { size: 11 }, maxTicksLimit: 6 }, grid: { color: cssVar('--grid') }, border: { display: false } },
  };
}

function tooltipStyle() {
  return { backgroundColor: cssVar('--surface-3'), titleColor: cssVar('--text-primary'), bodyColor: cssVar('--text-secondary'), borderColor: 'rgba(255,255,255,.08)', borderWidth: 1, padding: 10, boxPadding: 4 };
}

function makeLineChart(canvas, series) {
  return new Chart(canvas, {
    type: 'line',
    data: { labels: [], datasets: series.map((s) => {
      const color = cssVar(s.color);
      return {
        label: s.label, data: [], borderColor: color, backgroundColor: s.area ? areaFill(color) : color,
        borderWidth: 2, borderDash: s.dash ? [5, 4] : [], pointRadius: 0, pointHoverRadius: 4,
        pointHoverBackgroundColor: color, pointHoverBorderColor: cssVar('--surface-1'), pointHoverBorderWidth: 2,
        tension: 0.4, fill: s.area ? 'origin' : false,
      };
    }) },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { ...tooltipStyle(), callbacks: { label: (c) => ` ${c.dataset.label}: ${fmtBytes(c.parsed.y)}` } },
      },
      scales: baseScales((v) => fmtAxisBytes(v)),
    },
  });
}

function makeBarChart(canvas, series) {
  return new Chart(canvas, {
    type: 'bar',
    data: { labels: [], datasets: series.map((s) => {
      const color = cssVar(s.color);
      return {
        label: s.label, data: [], borderRadius: { topLeft: 4, topRight: 4 }, borderSkipped: 'start',
        maxBarThickness: 8, categoryPercentage: 0.6, barPercentage: 0.8,
        backgroundColor: (ctx) => {
          const { chart } = ctx;
          if (!chart.chartArea) return color;
          const g = chart.ctx.createLinearGradient(0, chart.chartArea.top, 0, chart.chartArea.bottom);
          g.addColorStop(0, color);
          g.addColorStop(1, hexToRgba(color, 0.35));
          return g;
        },
      };
    }) },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false }, tooltip: { ...tooltipStyle(), callbacks: { label: (c) => ` ${c.dataset.label}: ${c.parsed.y}회` } } },
      scales: baseScales((v) => (Number.isInteger(v) ? v : '')),
    },
  });
}

function makeDonut(canvas) {
  return new Chart(canvas, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: cssVar('--surface-1'), borderWidth: 2, hoverOffset: 4 }] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false, cutout: '78%',
      plugins: { legend: { display: false }, tooltip: { ...tooltipStyle(), callbacks: { label: (c) => ` ${c.label}: ${fmtBytes(c.parsed)}` } } },
    },
  });
}

function legendHtml(series) {
  return series.map((s) => `<span class="${s.dash ? 'dashed' : ''}" style="--c:var(${s.color})">${esc(s.label)}</span>`).join('');
}

const HEAP_SERIES = [
  { label: '사용', color: '--series-1', key: 'heapUsed', area: true },
  { label: 'Committed', color: '--series-2', key: 'heapCommitted' },
  { label: '최대 (Xmx)', color: '--text-muted', key: 'heapMax', dash: true },
];
const META_SERIES = [
  { label: '사용', color: '--series-1', key: 'metaUsed', area: true },
  { label: 'Committed', color: '--series-2', key: 'metaCommitted' },
  { label: 'MaxMetaspaceSize', color: '--text-muted', key: 'metaMax', dash: true },
];
const GC_SERIES = [
  { label: 'Young GC', color: '--series-1', key: 'gcYoung' },
  { label: 'Old / Concurrent GC', color: '--series-2', key: 'gcOld' },
];
const DONUT_COLORS = ['--series-1', '--series-2', '--series-3'];

function fillLine(chart, series) {
  chart.data.labels = state.history.map((h) => fmtClock(h.t));
  series.forEach((s, i) => { chart.data.datasets[i].data = state.history.map((h) => (h[s.key] ?? null)); });
  chart.update();
}

function historyRange() {
  const h = state.history;
  return h.length > 1 ? `최근 ${fmtDuration(h[h.length - 1].t - h[0].t)}` : '';
}

function ensureCharts() {
  if (state.charts.heap) return;
  $('#heap-legend').innerHTML = legendHtml(HEAP_SERIES);
  $('#meta-legend').innerHTML = legendHtml(META_SERIES);
  state.charts.heap = makeLineChart($('#heap-chart'), HEAP_SERIES);
  state.charts.meta = makeLineChart($('#meta-chart'), META_SERIES);
}

function updateCharts() {
  if (typeof Chart === 'undefined') return;
  ensureCharts();
  fillLine(state.charts.heap, HEAP_SERIES);
  fillLine(state.charts.meta, META_SERIES);
  $('#heap-chart-range').textContent = historyRange();
}

function updateOverviewCharts(mem) {
  if (typeof Chart === 'undefined') return;
  if (!state.charts.ovHeap) {
    $('#ov-heap-legend').innerHTML = legendHtml(HEAP_SERIES);
    $('#ov-gc-legend').innerHTML = legendHtml(GC_SERIES).replace(/<span /g, '<span class="dot-key" ');
    state.charts.ovHeap = makeLineChart($('#ov-heap-chart'), HEAP_SERIES);
    state.charts.ovGc = makeBarChart($('#ov-gc-chart'), GC_SERIES);
    state.charts.ovDonut = makeDonut($('#ov-donut'));
  }
  fillLine(state.charts.ovHeap, HEAP_SERIES);
  $('#ov-heap-range').textContent = historyRange();

  // GC collections per refresh interval (difference of the cumulative counters).
  const h = state.history.slice(-13);
  const gc = state.charts.ovGc;
  gc.data.labels = h.slice(1).map((x) => fmtClock(x.t));
  GC_SERIES.forEach((s, i) => { gc.data.datasets[i].data = h.slice(1).map((x, k) => Math.max(0, x[s.key] - h[k][s.key])); });
  gc.update();

  // Heap composition by pool (max 3 slots; anything else folds into "기타").
  // Colour follows the pool (Eden / Old / Survivor), never its rank by size.
  const rank = (n) => (/eden/i.test(n) ? 0 : /old|tenured/i.test(n) ? 1 : /survivor/i.test(n) ? 2 : 3);
  const heapPools = mem.pools.filter((p) => p.type === 'HEAP' && p.usage).sort((a, b) => rank(a.name) - rank(b.name));
  const slices = heapPools.slice(0, 3).map((p, i) => ({ label: p.name, value: p.usage.used, color: DONUT_COLORS[i] }));
  const rest = heapPools.slice(3).reduce((a, p) => a + p.usage.used, 0);
  if (rest > 0) slices.push({ label: '기타', value: rest, color: '--text-muted' });
  const donut = state.charts.ovDonut;
  donut.data.labels = slices.map((x) => x.label);
  donut.data.datasets[0].data = slices.map((x) => x.value);
  donut.data.datasets[0].backgroundColor = slices.map((x) => cssVar(x.color));
  donut.update();
  const total = slices.reduce((a, x) => a + x.value, 0);
  $('#ov-donut-center').innerHTML = `<div><b>${fmtBytes(total)}</b><span>Heap 사용</span></div>`;
  $('#ov-donut-legend').innerHTML = slices.map((x) => `<div><i style="--c:var(${x.color})"></i>${esc(x.label)}<span>${fmtBytes(x.value)} · ${total ? ((100 * x.value) / total).toFixed(0) : 0}%</span></div>`).join('');
}

function resetCharts() {
  Object.values(state.charts).forEach((c) => c.destroy());
  state.charts = {};
  if (state.view === 'memory') updateCharts();
}

// ---------------------------------------------------------------- XLog
const XL_POLL_MS = 2000;
const SLOW_MS = 3000;

function xlogReset() {
  clearTimeout(state.xlog && state.xlog.timer);
  state.xlog = { txns: [], seq: 0, timer: null, paused: false, now: Date.now(), selection: null, serverId: state.server && state.server.id };
  if (state.charts.xlog) { state.charts.xlog.destroy(); delete state.charts.xlog; }
  const selBox = $('#xl-selected');
  const pause = $('#xl-pause');
  if (selBox) selBox.hidden = true;
  if (pause) pause.textContent = '일시정지';
}

const xlWindow = () => Number($('#xl-window').value);
const xlFilter = () => $('#xl-filter').value.trim().toLowerCase();
const xlVisible = () => {
  const f = xlFilter();
  const min = state.xlog.now - xlWindow();
  return state.xlog.txns.filter((t) => t.end >= min && (!f || `${t.method} ${t.uri}`.toLowerCase().includes(f)));
};

function serviceOf(t) {
  const p = String(t.uri || '-').split('?')[0].split(';')[0]
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/{uuid}')
    .replace(/\/\d+(?=\/|$)/g, '/{id}');
  return `${t.method} ${p}`;
}

function fmtClockMs(t) {
  const d = new Date(t);
  return `${d.toTimeString().slice(0, 8)}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

async function loadXlog() {
  if (!state.xlog || state.xlog.serverId !== (state.server && state.server.id)) xlogReset();
  clearTimeout(state.xlog.timer);
  const xl = state.xlog;
  const data = await api(`/servers/${state.server.id}/xlog?since=${xl.seq}&window=${xlWindow()}`);
  if (xl !== state.xlog) return; // server switched meanwhile
  xl.seq = data.seq;
  xl.now = data.now;
  if (data.txns.length) xl.txns.push(...data.txns);
  const keep = xl.now - 30 * 60000;
  if (xl.txns.length && xl.txns[0].end < keep) xl.txns = xl.txns.filter((t) => t.end >= keep);
  if (xl.txns.length > 60000) xl.txns = xl.txns.slice(-60000);
  renderXlogSetup(data.status);
  renderXlog();
  if (state.view === 'xlog' && !xl.paused) xl.timer = setTimeout(() => loadXlog().catch((e) => showError(e.message)), XL_POLL_MS);
}

function renderXlogSetup(st) {
  const box = $('#xl-setup');
  const notes = [];
  const reloadCmd = `${'$'}JBOSS_HOME/bin/jboss-cli.sh -c --controller=127.0.0.1:${(state.server.url.match(/:(\d+)\//) || [])[1] || 9990} --user=<관리계정> --password=<비밀번호> --command=':reload'`;
  if (st.ready && (st.noElapsed > 0 || st.reloadRequired)) {
    notes.push(`<p>▲ ${st.noElapsed > 0 ? `최근 요청 ${fmtNum(st.noElapsed)}건은 access log 에 처리시간이 없어(<code>-</code>) 표시하지 못했습니다. ` : ''}`
      + `${st.reloadRequired ? `WildFly 가 <b>${esc(st.serverState)}</b> 상태입니다. ` : ''}`
      + '처리시간 기록(record-request-start-time)은 <b>WildFly reload 후</b> 적용됩니다. 점검 시간에 reload 하세요:</p>'
      + `<pre>${esc(reloadCmd)}</pre>`);
  }
  if (st.ready && st.notRecording && st.notRecording.length) {
    notes.push(`<p>▲ 처리시간 기록(record-request-start-time)이 아직 적용되지 않은 리스너가 있습니다: <code>${esc(st.notRecording.join(', '))}</code>. 설정 후 WildFly reload 가 필요합니다. 그 전까지의 요청은 처리시간이 없어 표시되지 않습니다.</p>`);
  }
  if (st.ready && st.sharedWith && st.sharedWith.length) {
    notes.push(`<p>▲ 이 access log 파일을 다른 인스턴스(${esc(st.sharedWith.join(', '))})도 사용합니다. 두 인스턴스의 요청이 섞여 보일 수 있습니다. access log 의 prefix 를 인스턴스마다 다르게 설정하세요.</p>`);
  }
  if (st.readError) notes.push(`<p class="muted">${esc(st.readError)}</p>`);
  if (st.ready) {
    box.hidden = !notes.length;
    box.innerHTML = notes.length ? `<h3>XLog 수집 상태</h3>${notes.join('')}${st.notRecording && st.notRecording.length ? enableHelp() : ''}` : '';
    return;
  }
  box.hidden = false;
  box.innerHTML = `<h3>XLog 수집 설정이 필요합니다</h3>
    <p>${esc(st.reason)}</p>
    <p>XLog 는 WildFly(Undertow) access log 에 기록된 요청별 처리시간으로 그립니다. 필요한 설정:
      access log 활성화(처리시간 <code>%D</code> 포함 패턴), HTTP 리스너의 <code>record-request-start-time=true</code>.</p>
    ${st.pattern ? `<p>현재 패턴: <code>${esc(st.pattern)}</code></p>` : ''}
    ${st.code === 'unreadable' ? '' : enableHelp(st.code === 'pattern')}`;
}

function enableHelp(patternChange = false) {
  const cli = `/subsystem=undertow/server=default-server/host=default-host/setting=access-log:add(pattern="%h %{time,yyyy-MM-dd'T'HH:mm:ss.SSSZ} \\"%r\\" %s %b %D \\"%I\\"", prefix="access_log_${(state.server.name || 'wildfly').replace(/[^A-Za-z0-9._-]/g, '_')}.")
/subsystem=undertow/server=default-server/http-listener=default:write-attribute(name=record-request-start-time, value=true)
:reload`;
  return isAdmin()
    ? `<p><button class="btn primary" id="xl-enable" data-pattern="${patternChange}">XLog 수집 설정</button>
       <span class="muted"> access log 설정과 처리시간 기록을 켭니다. 처리시간 기록은 WildFly reload 후 적용됩니다 (reload 는 자동으로 하지 않습니다).</span></p>
       <details><summary class="muted">직접 설정하려면 (jboss-cli)</summary><pre>${esc(cli)}</pre></details>`
    : `<p class="muted">관리자가 설정할 수 있습니다. jboss-cli 로 직접 설정하려면:</p><pre>${esc(cli)}</pre>`;
}

function renderXlog() {
  const xl = state.xlog;
  const list = xlVisible();
  const win = xlWindow();
  const ymaxSel = $('#xl-ymax').value;
  const elapsedSorted = list.map((t) => t.elapsed).sort((a, b) => a - b);
  const p99 = elapsedSorted.length ? elapsedSorted[Math.floor(elapsedSorted.length * 0.99)] : 0;
  const yMax = ymaxSel === 'auto' ? Math.max(500, Math.ceil((Math.max(p99, ...elapsedSorted.slice(-5)) * 1.1) / 500) * 500) : Number(ymaxSel);
  xl.yMax = yMax;

  // KPIs
  const last10 = list.filter((t) => t.end >= xl.now - 10000).length;
  const errors = list.filter((t) => t.status >= 500).length;
  const slow = list.filter((t) => t.elapsed >= SLOW_MS).length;
  const avg = list.length ? Math.round(list.reduce((a, t) => a + t.elapsed, 0) / list.length) : 0;
  $('#xl-kpis').innerHTML = [
    kpi('server', 'blue', 'TPS', (last10 / 10).toFixed(1), '최근 10초 초당 처리 건수'),
    kpi('threads', 'violet', '평균 응답시간', `${fmtNum(avg)} ms`, `표시 범위 ${fmtNum(list.length)}건`),
    kpi('meta', 'pink', '오류율 (5xx)', list.length ? `${((100 * errors) / list.length).toFixed(1)}%` : '-', `${fmtNum(errors)}건`, errors ? '<span class="badge critical">●</span>' : ''),
    kpi('heap', 'orange', '느린 요청', fmtNum(slow), `${SLOW_MS / 1000}초 이상`, slow ? '<span class="badge warning">▲</span>' : ''),
  ].join('');
  $('#xl-count').textContent = `${fmtNum(list.length)}건 · ${xl.paused ? '일시정지됨' : '2초마다 갱신'}`;

  // Scatter
  if (typeof Chart !== 'undefined') {
    if (!state.charts.xlog) state.charts.xlog = makeXlogChart($('#xl-chart'));
    const ch = state.charts.xlog;
    const pt = (t) => ({ x: t.end, y: Math.min(t.elapsed, yMax), t });
    ch.data.datasets[0].data = list.filter((t) => t.status < 400).map(pt);
    ch.data.datasets[1].data = list.filter((t) => t.status >= 400 && t.status < 500).map(pt);
    ch.data.datasets[2].data = list.filter((t) => t.status >= 500).map(pt);
    ch.options.scales.x.min = xl.now - win;
    ch.options.scales.x.max = xl.now;
    ch.options.scales.y.max = yMax;
    ch.update('none');
  }
  renderServiceStats(list);
}

function makeXlogChart(canvas) {
  const muted = cssVar('--text-muted');
  const ds = (label, color, radius) => ({
    label, data: [], backgroundColor: hexToRgba(cssVar(color), 0.75), borderWidth: 0,
    pointRadius: radius, pointHoverRadius: radius + 2, pointHitRadius: 4,
  });
  return new Chart(canvas, {
    type: 'scatter',
    data: { datasets: [ds('정상', '--series-1', 2), ds('4xx', '--warning', 2.5), ds('5xx 오류', '--critical', 3)] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false, parsing: false, normalized: true,
      events: ['mousemove', 'mouseout'],
      plugins: {
        legend: { display: false },
        tooltip: {
          ...tooltipStyle(),
          callbacks: {
            title: (items) => (items[0] ? fmtClockMs(items[0].raw.t.end) : ''),
            label: (c) => {
              const t = c.raw.t;
              return ` ${t.method} ${t.uri.length > 70 ? `${t.uri.slice(0, 70)}…` : t.uri}  ${fmtNum(t.elapsed)} ms  [${t.status}]`;
            },
          },
        },
      },
      scales: {
        x: { type: 'linear', ticks: { color: muted, maxTicksLimit: 7, maxRotation: 0, callback: (v) => fmtClock(v), font: { size: 11 } }, grid: { color: cssVar('--grid') }, border: { color: cssVar('--axis') } },
        y: { min: 0, ticks: { color: muted, callback: (v) => (v >= 1000 ? `${(v / 1000).toFixed(v % 1000 ? 1 : 0)}s` : `${v}ms`), font: { size: 11 } }, grid: { color: cssVar('--grid') }, border: { display: false } },
      },
    },
  });
}

function renderServiceStats(list) {
  const groups = new Map();
  for (const t of list) {
    const k = serviceOf(t);
    let g = groups.get(k);
    if (!g) { g = { name: k, n: 0, sum: 0, max: 0, err: 0, times: [] }; groups.set(k, g); }
    g.n++; g.sum += t.elapsed; g.max = Math.max(g.max, t.elapsed); g.times.push(t.elapsed);
    if (t.status >= 500) g.err++;
  }
  const total = list.reduce((a, t) => a + t.elapsed, 0) || 1;
  const winSec = xlWindow() / 1000;
  const rows = [...groups.values()].sort((a, b) => b.sum - a.sum).slice(0, 30);
  $('#xl-services').innerHTML = rows.length ? `<table><thead><tr><th>서비스</th><th class="r">건수</th><th class="r">TPS</th><th class="r">평균</th><th class="r">95%</th><th class="r">최대</th><th class="r">오류</th><th>처리시간 비중</th></tr></thead><tbody>${
    rows.map((g) => {
      g.times.sort((a, b) => a - b);
      const p95 = g.times[Math.floor(g.times.length * 0.95)] || 0;
      const avg = Math.round(g.sum / g.n);
      const share = (100 * g.sum) / total;
      return `<tr class="xl-svc-row" data-svc="${esc(g.name.split(' ').slice(1).join(' ').replace(/\{(id|uuid)\}.*$/, ''))}">
        <td class="xl-uri">${esc(g.name)}</td><td class="r">${fmtNum(g.n)}</td><td class="r">${(g.n / winSec).toFixed(2)}</td>
        <td class="r ${avg >= SLOW_MS ? 'xl-slow' : ''}">${fmtNum(avg)} ms</td><td class="r">${fmtNum(p95)} ms</td>
        <td class="r ${g.max >= SLOW_MS ? 'xl-slow' : ''}">${fmtNum(g.max)} ms</td>
        <td class="r">${g.err ? `<span class="badge critical">${g.err}</span>` : '0'}</td>
        <td class="bar-cell"><span class="num">${share.toFixed(1)}%</span><div class="bar" style="width:${share}%"></div></td></tr>`;
    }).join('')}</tbody></table>` : '<div class="empty">표시 범위에 트랜잭션이 없습니다</div>';
}

function showSelection(x1, x2, y1, y2) {
  const xl = state.xlog;
  const yMax = xl.yMax;
  const picked = xlVisible().filter((t) => t.end >= x1 && t.end <= x2 && Math.min(t.elapsed, yMax) >= y1 && Math.min(t.elapsed, yMax) <= y2)
    .sort((a, b) => b.elapsed - a.elapsed);
  const box = $('#xl-selected');
  box.hidden = false;
  $('#xl-selected-info').textContent = `${fmtClock(x1)} ~ ${fmtClock(x2)} · ${fmtNum(Math.round(y1))}~${y2 >= yMax ? '' : fmtNum(Math.round(y2))} ms · ${fmtNum(picked.length)}건${picked.length > 500 ? ' (처리시간 상위 500건 표시)' : ''}`;
  $('#xl-selected-table').innerHTML = picked.length ? `<table><thead><tr><th>종료 시각</th><th>서비스</th><th class="r">처리시간</th><th>상태</th><th>클라이언트</th><th>쓰레드</th><th class="r">응답 크기</th></tr></thead><tbody>${
    picked.slice(0, 500).map((t) => {
      const cls = t.status >= 500 ? 'critical' : t.status >= 400 ? 'warning' : 'good';
      return `<tr><td class="mono">${fmtClockMs(t.end)}</td><td class="xl-uri"><b>${esc(t.method)}</b> ${esc(t.uri)}</td>
        <td class="r ${t.elapsed >= SLOW_MS ? 'xl-slow' : ''}">${fmtNum(t.elapsed)} ms</td>
        <td><span class="badge ${cls}">${t.status >= 500 ? '● ' : t.status >= 400 ? '▲ ' : ''}${t.status}</span></td>
        <td>${esc(t.ip || '-')}</td><td>${esc(t.thread || '-')}</td><td class="r">${fmtBytes(t.bytes)}</td></tr>`;
    }).join('')}</tbody></table>` : '<div class="empty">선택한 영역에 트랜잭션이 없습니다</div>';
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Drag-to-select on the scatter (Scouter style).
(() => {
  const boxEl = $('#xl-box') || document.createElement('div');
  const sel = $('#xl-sel') || document.createElement('div');
  let start = null;
  const local = (e) => { const r = boxEl.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
  const clampToArea = (p) => {
    const a = state.charts.xlog.chartArea;
    return { x: Math.min(Math.max(p.x, a.left), a.right), y: Math.min(Math.max(p.y, a.top), a.bottom) };
  };
  boxEl.addEventListener('mousedown', (e) => {
    if (!state.charts.xlog || e.button !== 0) return;
    start = clampToArea(local(e));
    Object.assign(sel.style, { left: `${start.x}px`, top: `${start.y}px`, width: '0px', height: '0px' });
    sel.hidden = false;
    e.preventDefault();
  });
  window.addEventListener('mousemove', (e) => {
    if (!start) return;
    const p = clampToArea(local(e));
    Object.assign(sel.style, {
      left: `${Math.min(start.x, p.x)}px`, top: `${Math.min(start.y, p.y)}px`,
      width: `${Math.abs(p.x - start.x)}px`, height: `${Math.abs(p.y - start.y)}px`,
    });
  });
  window.addEventListener('mouseup', (e) => {
    if (!start) return;
    const p = clampToArea(local(e));
    sel.hidden = true;
    const s0 = start; start = null;
    const pad = Math.abs(p.x - s0.x) < 4 && Math.abs(p.y - s0.y) < 4 ? 6 : 0; // a click picks nearby points
    const { x, y } = state.charts.xlog.scales;
    const xs = [x.getValueForPixel(Math.min(s0.x, p.x) - pad), x.getValueForPixel(Math.max(s0.x, p.x) + pad)];
    const ys = [y.getValueForPixel(Math.max(s0.y, p.y) + pad), y.getValueForPixel(Math.min(s0.y, p.y) - pad)];
    showSelection(xs[0], xs[1], Math.max(0, ys[0]), ys[1]);
  });
})();

on('#xl-window', 'change', () => { if (state.xlog) { state.xlog.seq = 0; state.xlog.txns = []; loadXlog().catch((e) => showError(e.message)); } });
on('#xl-ymax', 'change', () => state.xlog && renderXlog());
on('#xl-filter', 'input', () => state.xlog && renderXlog());
on('#xl-pause', 'click', () => {
  const xl = state.xlog;
  if (!xl) return;
  xl.paused = !xl.paused;
  $('#xl-pause').textContent = xl.paused ? '다시 시작' : '일시정지';
  if (xl.paused) { clearTimeout(xl.timer); renderXlog(); } else loadXlog().catch((e) => showError(e.message));
});
on('#xl-selected-close', 'click', () => { $('#xl-selected').hidden = true; });
document.addEventListener('click', async (e) => {
  const row = e.target.closest('.xl-svc-row');
  if (row) { $('#xl-filter').value = row.dataset.svc; renderXlog(); return; }
  const btn = e.target.closest('#xl-enable');
  if (!btn) return;
  const patternChange = btn.dataset.pattern === 'true';
  if (patternChange && !confirm('기존 access log 패턴을 XLog 용 패턴으로 바꿉니다. access log 를 다른 도구에서 분석하고 있다면 영향이 있을 수 있습니다. 계속할까요?')) return;
  btn.disabled = true;
  try {
    let r = await api(`/servers/${state.server.id}/xlog/enable`, { method: 'POST', body: { overwritePattern: patternChange } });
    if (r.needsPatternChange) {
      if (!confirm(`현재 access log 패턴(${r.currentPattern})에 처리시간이 없습니다. XLog 용 패턴으로 바꿀까요?`)) return;
      r = await api(`/servers/${state.server.id}/xlog/enable`, { method: 'POST', body: { overwritePattern: true } });
    }
    toast(r.reloadRequired
      ? '설정했습니다. 처리시간 기록은 WildFly reload 후 적용됩니다 (jboss-cli: :reload).'
      : '설정했습니다. 새 요청부터 XLog 에 표시됩니다.');
    await loadXlog();
  } catch (ex) {
    toast(ex.message);
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- datasources
async function loadDatasources() {
  const { datasources, drivers } = await api(`/servers/${state.server.id}/datasources`);
  recordDatasources(datasources);
  $('#ds-list').innerHTML = datasources.length ? datasources.map((d) => {
    const p = d.pool;
    const hasStats = d.statisticsEnabled && p && p.activeCount !== undefined;
    const inUse = hasStats ? p.inUseCount : null;
    const health = dsHealth(d);
    return `<div class="card">
      <h3>${esc(d.name)} ${d.xa ? '<span class="badge">XA</span>' : ''}
        ${d.enabled ? (health.level === 'ok' ? '<span class="badge good">● 정상</span>' : '') : ''}
        ${health.badges.join(' ')}
        <span class="right">${isAdmin() ? `<button class="btn sm" data-ds-test="${esc(d.name)}" data-xa="${d.xa}">연결 테스트</button>` : ''}</span></h3>
      <dl class="kv">${kv([
        ['JNDI', d.jndiName], ['URL', d.connectionUrl], ['드라이버', d.driver], ['DB 사용자', d.userName],
        ['풀 크기', `min ${d.minPoolSize ?? 0} / max ${d.maxPoolSize ?? '-'}`], ['Blocking timeout', d.blockingTimeout !== undefined ? fmtMs(d.blockingTimeout) : null],
        ['유효성 검사', d.validConnectionSql ? `${d.validConnectionSql}${d.backgroundValidation ? ' (background)' : ''}` : null],
      ])}</dl>
      ${hasStats ? `
        ${meter('사용 중 커넥션 / 최대', inUse, d.maxPoolSize, `${fmtNum(inUse)} / ${fmtNum(d.maxPoolSize)}`)}
        ${meter('생성된(Active) 커넥션 / 최대 (유휴 포함)', p.activeCount, d.maxPoolSize, `${fmtNum(p.activeCount)} / ${fmtNum(d.maxPoolSize)}`, true)}
        <div class="table-wrap section"><table><tbody>
          <tr><td>가용(Available)</td><td class="r">${fmtNum(p.availableCount)}</td><td>최대 사용(MaxUsed)</td><td class="r">${fmtNum(p.maxUsedCount)}</td></tr>
          <tr><td title="커넥션이 모두 사용 중이라 기다려야 했던 요청 수 (누적)">대기 발생(WaitCount)</td><td class="r">${fmtNum(p.waitCount)}</td><td title="오래 쓰이지 않아 idle-timeout 으로 정리된 커넥션 수. 정상 동작입니다">유휴 정리(TimedOut)</td><td class="r">${fmtNum(p.timedOut)}</td></tr>
          <tr><td>평균 대기 시간</td><td class="r">${fmtMs(p.averageBlockingTime)}</td><td>최대 대기 시간</td><td class="r">${fmtMs(p.maxWaitTime)}</td></tr>
          <tr><td>평균 사용 시간</td><td class="r">${fmtMs(p.averageUsageTime)}</td><td>평균 생성 시간</td><td class="r">${fmtMs(p.averageCreationTime)}</td></tr>
          <tr><td>생성 / 제거</td><td class="r">${fmtNum(p.createdCount)} / ${fmtNum(p.destroyedCount)}</td><td title="blocking-timeout 안에 커넥션을 얻지 못해 실패한 요청 수 (누적, IJ000453)">획득 실패(BlockingFailure)</td><td class="r ${health.recentFail ? 'xl-slow' : ''}">${fmtNum(p.blockingFailureCount)}</td></tr>
          ${d.jdbc && d.jdbc.preparedStatementCacheHitCount !== undefined ? `<tr><td>PS 캐시 hit / miss</td><td class="r">${fmtNum(d.jdbc.preparedStatementCacheHitCount)} / ${fmtNum(d.jdbc.preparedStatementCacheMissCount)}</td><td></td><td></td></tr>` : ''}
        </tbody></table></div>
        <p class="muted" style="font-size:11.5px;margin:8px 0 0">대기 발생·획득 실패·유휴 정리는 서버 시작(또는 통계 초기화) 이후 누적값입니다. 경고는 <b>지금</b> 사용률 90% 이상이거나 획득 실패가 <b>최근 5분</b> 안에 늘었을 때만 표시합니다.</p>`
      : `<p class="muted" style="font-size:12.5px;margin-bottom:0">풀 통계가 비활성화되어 있습니다. 활성화: <code>/subsystem=datasources/${d.xa ? 'xa-data-source' : 'data-source'}=${esc(d.name)}:write-attribute(name=statistics-enabled,value=true)</code></p>`}
    </div>`;
  }).join('') : '<div class="card empty">설정된 데이터소스가 없습니다</div>';
  $('#ds-drivers').innerHTML = `<table><thead><tr><th>이름</th><th>모듈</th><th>클래스</th><th>버전</th></tr></thead><tbody>${
    drivers.map((d) => `<tr><td>${esc(d.name)}</td><td class="mono">${esc(d.module || d.deployment || '-')}</td><td class="mono">${esc(d.className || '-')}</td>
      <td title="${esc(d.versionSource || '')}">${esc(d.version || '-')}</td></tr>`).join('')
  }</tbody></table>`;
}

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-ds-test]');
  if (!btn) return;
  btn.disabled = true;
  try {
    const r = await api(`/servers/${state.server.id}/datasources/${encodeURIComponent(btn.dataset.dsTest)}/test?xa=${btn.dataset.xa}`, { method: 'POST' });
    toast(r.ok ? `${btn.dataset.dsTest}: 연결 성공 (${r.elapsedMs} ms)` : `${btn.dataset.dsTest}: 연결 실패`);
  } catch (ex) {
    toast(`${btn.dataset.dsTest}: ${ex.message}`);
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- threads
const STATE_ORDER = ['RUNNABLE', 'BLOCKED', 'WAITING', 'TIMED_WAITING', 'NEW', 'TERMINATED'];
const STATE_COLOR = { RUNNABLE: '--series-1', BLOCKED: '--critical', WAITING: '--series-4', TIMED_WAITING: '--series-3', NEW: '--text-muted', TERMINATED: '--text-muted' };

function frameText(f) {
  const loc = f.nativeMethod ? 'Native Method' : f.fileName ? (f.lineNumber >= 0 ? `${f.fileName}:${f.lineNumber}` : f.fileName) : 'Unknown Source';
  return `${f.className}.${f.methodName}(${loc})`;
}

async function takeThreadDump() {
  const btn = $('#btn-thread-dump');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 수집 중...';
  try {
    state.threads = await api(`/servers/${state.server.id}/threads`, { timeoutMs: 90000 });
    renderThreads();
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '쓰레드 덤프 수집';
  }
}

function renderThreads() {
  const d = state.threads;
  const a = d.analysis;
  $('#thread-empty').hidden = true;
  $('#thread-result').hidden = false;
  $('#thread-time').textContent = `수집 시각: ${fmtTime(d.timestamp)}`;
  const dl = $('#btn-thread-download');
  dl.hidden = false;
  dl.href = `/api/servers/${state.server.id}/threads.txt`;
  const sum = d.summary || {};
  $('#th-tiles').innerHTML = [
    tile('전체 쓰레드', fmtNum(a.total), `피크 ${fmtNum(sum.peakThreadCount)} · 데몬 ${fmtNum(sum.daemonThreadCount)}`),
    tile('RUNNABLE', fmtNum(a.states.RUNNABLE || 0), '실행 중 (I/O 대기 포함)'),
    tile('BLOCKED', fmtNum(a.states.BLOCKED || 0), '모니터 락 대기', a.states.BLOCKED ? '<span class="badge warning">▲</span>' : ''),
    tile('데드락', fmtNum(a.deadlocks.length), a.deadlocks.length ? '즉시 확인 필요' : '없음', a.deadlocks.length ? '<span class="badge critical">● 위험</span>' : '<span class="badge good">✓</span>'),
  ].join('');
  $('#th-findings').innerHTML = findingsHtml(a.findings) + a.deadlocks.map((chain) => `<li class="critical"><span class="icon">!</span><span>데드락: ${
    chain.map((c) => `"${esc(c.name)}" → ${esc(c.waitingFor || '?')} (보유: ${esc(c.heldBy || '?')})`).join('<br>')}</span></li>`).join('');

  const max = Math.max(1, ...Object.values(a.states));
  $('#th-states').innerHTML = STATE_ORDER.filter((s) => a.states[s]).map((s) => `
    <div class="meter"><div class="row"><span class="state ${s}">${s}</span><span class="num">${fmtNum(a.states[s])} (${((100 * a.states[s]) / a.total).toFixed(0)}%)</span></div>
    <div class="track"><div class="fill" style="width:${(100 * a.states[s]) / max}%;background:var(${STATE_COLOR[s]})"></div></div></div>`).join('');

  $('#th-pools').innerHTML = `<table><thead><tr><th>풀 (이름 패턴)</th><th class="r">전체</th><th class="r">유휴</th><th class="r">작업 중</th><th>상태</th></tr></thead><tbody>${
    a.pools.map((p) => `<tr><td>${esc(p.name)}</td><td class="r">${p.total}</td><td class="r">${p.idle}</td><td class="r">${p.total - p.idle}</td><td>${
      Object.entries(p.states).map(([s, n]) => `<span class="state ${s}">${s.replace('TIMED_WAITING', 'TIMED_W')} ${n}</span>`).join(' ')}</td></tr>`).join('')
  }</tbody></table>`;

  $('#th-locks').innerHTML = a.locks.length ? a.locks.map((l) => `<div class="stack-group">
      <div><code>${esc(l.lock)}</code></div>
      <div class="secondary" style="font-size:13px">소유: <strong>${esc(l.ownerName || '-')}</strong> · 대기 ${l.waiters.length}개</div>
      <div class="muted" style="font-size:12.5px">${l.waiters.map((w) => esc(w.name)).join(', ')}</div></div>`).join('')
    : '<div class="empty">락 경합이 없습니다</div>';

  $('#th-hot').innerHTML = a.hotStacks.length ? a.hotStacks.map((s) => `<div class="stack-group">
      <div><span class="badge">${s.threads.length}개 쓰레드</span> <span class="state ${s.state}">${s.state}</span>
      <span class="muted" style="font-size:12.5px">${esc(s.threads.slice(0, 6).join(', '))}${s.threads.length > 6 ? ' ...' : ''}</span></div>
      <pre class="mono">${esc(s.frames.join('\n'))}</pre></div>`).join('')
    : '<div class="empty">여러 쓰레드가 공유하는 활성 스택이 없습니다</div>';

  const sel = $('#th-state-filter');
  sel.innerHTML = '<option value="">모든 상태</option>' + STATE_ORDER.filter((s) => a.states[s]).map((s) => `<option>${s}</option>`).join('');
  renderThreadList();
}

function renderThreadList() {
  const q = $('#th-filter').value.trim().toLowerCase();
  const st = $('#th-state-filter').value;
  const list = state.threads.threads.filter((t) => (!st || t.state === st) &&
    (!q || t.name.toLowerCase().includes(q) || t.stack.some((f) => f.className.toLowerCase().includes(q))));
  $('#th-list').innerHTML = list.length ? list.map((t) => `<details class="thread">
    <summary><span class="state ${t.state}">${t.state}</span><span class="name">${esc(t.name)}</span><span class="muted mono">#${t.id}</span></summary>
    <pre class="mono">${t.lockName ? `- ${t.state === 'BLOCKED' ? 'waiting to lock' : 'waiting on'} &lt;${esc(t.lockName)}&gt;${t.lockOwnerName ? ` owned by "${esc(t.lockOwnerName)}"` : ''}\n` : ''}${
      esc(t.stack.map((f) => `at ${frameText(f)}`).join('\n') || '(스택 없음)')}${
      t.lockedMonitors.length ? `\n\nLocked monitors:\n${esc(t.lockedMonitors.map((m) => `- ${m.className}@${Number(m.identityHashCode).toString(16)} (depth ${m.depth})`).join('\n'))}` : ''}</pre>
  </details>`).join('') : '<div class="empty">조건에 맞는 쓰레드가 없습니다</div>';
}

// ---------------------------------------------------------------- heap dumps
async function loadHeapList() {
  const list = await api('/heapdumps');
  const canGen = state.server.allowLocalHeapDump;
  $('#btn-heap-generate').disabled = !isAdmin() || !canGen;
  $('#heap-generate-note').textContent = !isAdmin() ? '관리자만 힙 덤프를 생성할 수 있습니다.'
    : !canGen ? '이 서버는 원격 서버로 설정되어 있어 생성 기능이 꺼져 있습니다 (allowLocalHeapDump). WildFly 호스트에서 생성한 파일을 업로드하세요.' : '';
  $('#heap-upload-card').querySelector('input').disabled = !isAdmin();
  $('#heap-list').innerHTML = list.length ? `<table><thead><tr><th>파일</th><th>유형</th><th class="r">크기</th><th>생성</th><th>상태</th><th></th></tr></thead><tbody>${
    list.map((d) => {
      const job = d.job;
      let status;
      if (job && job.status === 'running') status = `<div class="progress" title="${job.progress}%"><div style="width:${job.progress}%"></div></div><span class="muted" style="font-size:12px">분석 중 ${job.progress}%</span>`;
      else if (job && job.status === 'error') status = `<span class="badge critical">● 실패</span> <span class="muted" style="font-size:12px">${esc(job.error)}</span>`;
      else if (d.analyzed) status = '<span class="badge good">✓ 분석 완료</span>';
      else status = '<span class="badge">미분석</span>';
      return `<tr><td>${esc(d.name)}<div class="muted" style="font-size:12px">${esc(d.source)} · ${esc(d.createdBy || '')}</div></td>
        <td>${d.kind === 'hprof' ? 'HPROF' : '히스토그램'}</td><td class="r">${fmtBytes(d.size)}</td><td class="muted">${esc(fmtTime(d.createdAt))}</td><td>${status}</td>
        <td style="white-space:nowrap">
          ${d.analyzed ? `<button class="btn sm" data-heap-view="${d.id}">결과 보기</button>` : ''}
          ${!(job && job.status === 'running') ? `<button class="btn sm" data-heap-analyze="${d.id}">${d.analyzed ? '재분석' : '분석'}</button>` : ''}
          ${isAdmin() ? `<a class="btn sm" href="/api/heapdumps/${d.id}/download">다운로드</a> <button class="btn sm danger" data-heap-delete="${d.id}">삭제</button>` : ''}
        </td></tr>`;
    }).join('')
  }</tbody></table>` : '<div class="empty">아직 힙 덤프가 없습니다. 파일을 업로드하거나 서버에서 생성하세요.</div>';

  const running = list.some((d) => d.job && d.job.status === 'running');
  clearTimeout(state.heapPoll);
  if (running && state.view === 'heap') state.heapPoll = setTimeout(loadHeapList, 1500);
  // Auto-open a freshly finished analysis.
  if (state.pendingOpen) {
    const d = list.find((x) => x.id === state.pendingOpen);
    if (d && d.analyzed && !(d.job && d.job.status === 'running')) { state.pendingOpen = null; showAnalysis(d.id, d.name); }
    if (d && d.job && d.job.status === 'error') state.pendingOpen = null;
  }
}

async function uploadHeap(file) {
  const box = $('#upload-progress');
  const bar = box.querySelector('.progress > div');
  const text = box.querySelector('.muted');
  box.hidden = false;
  const form = new FormData();
  form.append('file', file);
  await new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/heapdumps/upload');
    xhr.setRequestHeader('X-Requested-With', 'wildfly-dashboard');
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      const pct = (100 * e.loaded) / e.total;
      bar.style.width = `${pct}%`;
      text.textContent = `업로드 중 ${fmtBytes(e.loaded)} / ${fmtBytes(e.total)}`;
    };
    xhr.onload = () => {
      let body = {};
      try { body = JSON.parse(xhr.responseText); } catch (_) { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300) {
        text.textContent = '업로드 완료 - 분석을 시작했습니다';
        state.pendingOpen = body.id;
      } else {
        text.textContent = body.error || `업로드 실패 (HTTP ${xhr.status})`;
      }
      resolve();
    };
    xhr.onerror = () => { text.textContent = '업로드 중 네트워크 오류'; resolve(); };
    xhr.send(form);
  });
  await loadHeapList();
}

async function showAnalysis(id, name) {
  const r = await api(`/heapdumps/${id}/analysis`);
  state.currentAnalysis = r;
  $('#heap-analysis').hidden = false;
  $('#ha-title').textContent = `분석 결과: ${name}`;
  const t = r.totals;
  $('#ha-tiles').innerHTML = [
    tile('힙 사용량 (추정)', fmtBytes(t.bytes), r.format === 'class-histogram' ? '클래스 히스토그램 기준' : `파일 ${fmtBytes(r.fileSize)} · 분석 ${fmtDuration(r.durationMs)}`),
    tile('객체 수', fmtNum(t.objects), t.instances !== undefined ? `인스턴스 ${fmtNum(t.instances)} · 배열 ${fmtNum(t.arrays)}` : ''),
    tile('클래스 수', fmtNum(t.classes || r.histogramSize), r.idSize ? `${r.idSize * 8}-bit 덤프` : ''),
    tile('클래스로더', t.classLoaders !== undefined ? fmtNum(t.classLoaders) : '-', t.gcRoots !== undefined ? `GC 루트 ${fmtNum(t.gcRoots)}` : ''),
  ].join('');
  $('#ha-findings').innerHTML = findingsHtml(r.findings);
  $('#ha-hist-count').textContent = `상위 ${r.histogram.length} / ${fmtNum(r.histogramSize)}개 클래스`;
  $('#ha-filter').value = '';
  renderHistogram();
  $('#ha-extra').hidden = !r.largestObjects.length && !r.classLoaders.length;
  $('#ha-largest').innerHTML = r.largestObjects.length ? `<table><thead><tr><th>클래스</th><th class="r">길이</th><th class="r">크기</th><th class="mono">주소</th></tr></thead><tbody>${
    r.largestObjects.slice(0, 20).map((o) => `<tr><td class="mono">${esc(o.className)}</td><td class="r">${o.length !== undefined ? fmtNum(o.length) : '-'}</td><td class="r">${fmtBytes(o.size)}</td><td class="mono muted">${esc(o.id)}</td></tr>`).join('')
  }</tbody></table>` : '<div class="empty">-</div>';
  $('#ha-loaders').innerHTML = r.classLoaders.length ? `<table><thead><tr><th>클래스로더</th><th class="r">정의한 클래스</th></tr></thead><tbody>${
    r.classLoaders.map((l) => `<tr><td class="mono">${esc(l.loaderClass)}<div class="muted">${esc(l.id)}</div></td><td class="r">${fmtNum(l.classCount)}</td></tr>`).join('')
  }</tbody></table>` : '<div class="empty">-</div>';
  $('#heap-analysis').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderHistogram() {
  const r = state.currentAnalysis;
  const q = $('#ha-filter').value.trim().toLowerCase();
  const rows = r.histogram.filter((h) => !q || h.className.toLowerCase().includes(q));
  const max = Math.max(1, ...r.histogram.map((h) => h.bytes));
  $('#ha-histogram').innerHTML = `<table><thead><tr><th>#</th><th>클래스</th><th class="r">인스턴스</th><th class="r">Shallow 크기</th><th class="r">비율</th><th></th></tr></thead><tbody>${
    rows.map((h, i) => `<tr><td class="muted">${i + 1}</td><td class="mono">${esc(h.className)}</td><td class="r">${fmtNum(h.count)}</td><td class="r">${fmtBytes(h.bytes)}</td><td class="r">${h.percent}%</td>
      <td class="bar-cell"><div class="bar" style="width:${(100 * h.bytes) / max}%"></div></td></tr>`).join('')
  }</tbody></table>`;
}

document.addEventListener('click', async (e) => {
  const view = e.target.closest('[data-heap-view]');
  const analyze = e.target.closest('[data-heap-analyze]');
  const del = e.target.closest('[data-heap-delete]');
  try {
    if (view) {
      const name = view.closest('tr').querySelector('td').firstChild.textContent;
      await showAnalysis(view.dataset.heapView, name);
    } else if (analyze) {
      await api(`/heapdumps/${analyze.dataset.heapAnalyze}/analyze`, { method: 'POST' });
      state.pendingOpen = analyze.dataset.heapAnalyze;
      await loadHeapList();
    } else if (del) {
      if (!confirm('이 힙 덤프와 분석 결과를 삭제할까요?')) return;
      await api(`/heapdumps/${del.dataset.heapDelete}`, { method: 'DELETE' });
      $('#heap-analysis').hidden = true;
      await loadHeapList();
    }
  } catch (ex) {
    toast(ex.message);
  }
});

// ---------------------------------------------------------------- users
async function loadUsers() {
  if (!isAdmin()) return;
  const list = await api('/users');
  $('#user-list').innerHTML = `<table><thead><tr><th>아이디</th><th>역할</th><th>마지막 로그인</th><th></th></tr></thead><tbody>${
    list.map((u) => `<tr><td>${esc(u.username)} ${u.mustChangePassword ? '<span class="badge warning">비밀번호 변경 필요</span>' : ''}</td><td>${esc(u.role)}</td>
      <td class="muted">${esc(fmtTime(u.lastLoginAt))}</td>
      <td>${u.username !== state.user.username ? `<button class="btn sm danger" data-user-delete="${esc(u.username)}">삭제</button>` : ''}</td></tr>`).join('')
  }</tbody></table>`;
}

on('#user-form', 'submit', async (e) => {
  e.preventDefault();
  try {
    await api('/users', { method: 'POST', body: { username: $('#nu-name').value.trim(), password: $('#nu-pw').value, role: $('#nu-role').value } });
    e.target.reset();
    toast('사용자를 추가했습니다');
    await loadUsers();
  } catch (ex) {
    toast(ex.message);
  }
});

document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-user-delete]');
  if (!b || !confirm(`${b.dataset.userDelete} 사용자를 삭제할까요?`)) return;
  try {
    await api(`/users/${encodeURIComponent(b.dataset.userDelete)}`, { method: 'DELETE' });
    await loadUsers();
  } catch (ex) {
    toast(ex.message);
  }
});

// ---------------------------------------------------------------- password
function openPasswordModal(forced) {
  $('#pw-modal').hidden = false;
  $('#pw-reason').textContent = forced ? '보안을 위해 처음 로그인하면 비밀번호를 변경해야 합니다.' : '';
  $('#pw-cancel').hidden = Boolean(forced);
  $('#pw-error').textContent = '';
  $('#pw-cur').focus();
}

on('#pw-cancel', 'click', () => { $('#pw-modal').hidden = true; });
on('#pw-form', 'submit', async (e) => {
  e.preventDefault();
  if ($('#pw-new').value !== $('#pw-new2').value) { $('#pw-error').textContent = '새 비밀번호가 일치하지 않습니다'; return; }
  try {
    await api('/auth/password', { method: 'POST', body: { currentPassword: $('#pw-cur').value, newPassword: $('#pw-new').value } });
    e.target.reset();
    $('#pw-modal').hidden = true;
    toast('비밀번호를 변경했습니다');
    if (state.user.mustChangePassword) { state.user.mustChangePassword = false; await start(); }
  } catch (ex) {
    $('#pw-error').textContent = ex.message;
  }
});

// ---------------------------------------------------------------- bootstrap
$$('.nav-item[data-view]').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
on('#btn-refresh', 'click', () => refresh());
on('#refresh-select', 'change', schedule);
on('#server-select', 'change', (e) => selectServer(e.target.value));
on('#btn-thread-dump', 'click', takeThreadDump);
on('#btn-quick-thread', 'click', () => { setView('threads'); takeThreadDump(); });
on('#th-filter', 'input', renderThreadList);
on('#th-state-filter', 'change', renderThreadList);
on('#ha-filter', 'input', renderHistogram);
on('#btn-password', 'click', () => openPasswordModal(false));
on('#btn-logout', 'click', async () => {
  await api('/auth/logout', { method: 'POST' }).catch(() => {});
  location.href = '/login';
});
on('#heap-file', 'change', (e) => { if (e.target.files[0]) uploadHeap(e.target.files[0]); e.target.value = ''; });
on('#btn-heap-generate', 'click', async () => {
  if (!confirm('힙 덤프 생성 중에는 WildFly JVM 이 잠시 멈춥니다. 계속할까요?')) return;
  const btn = $('#btn-heap-generate');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 생성 중...';
  try {
    const meta = await api(`/servers/${state.server.id}/heapdump`, { method: 'POST', body: { live: $('#heap-live').checked }, timeoutMs: 35 * 60000 });
    state.pendingOpen = meta.id;
    toast(`힙 덤프 생성 완료 (${fmtBytes(meta.size)}) - 분석을 시작했습니다`);
  } catch (ex) {
    toast(ex.message);
  } finally {
    btn.textContent = '힙 덤프 생성';
    await loadHeapList();
  }
});
const dz = $('#dropzone') || document.createElement('div');
['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); if (isAdmin()) dz.classList.add('drag'); }));
['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
dz.addEventListener('drop', (e) => {
  if (!isAdmin()) { toast('관리자만 업로드할 수 있습니다'); return; }
  const f = e.dataTransfer.files[0];
  if (f) uploadHeap(f);
});

function checkBuild() {
  const meta = document.querySelector('meta[name="dashboard-build"]');
  const htmlBuild = meta ? meta.content : '(없음)';
  if (htmlBuild === BUILD && !missingElements.length) return;
  // Built here (not taken from app.html) so it also shows with an old page, and kept apart from #error-banner,
  // which successful refreshes clear.
  const b = document.createElement('div');
  b.className = 'banner error';
  b.id = 'build-banner';
  ($('.content') || document.body).prepend(b);
  b.textContent = `화면 파일 버전이 맞지 않습니다: app.html ${htmlBuild} / app.js ${BUILD}. `
    + '대시보드 서버의 public 폴더 전체(public/app.html 포함)가 새 버전으로 복사되었는지 확인한 뒤 Ctrl+F5 로 새로고침하세요.'
    + (missingElements.length ? ` (화면에 없는 요소: ${missingElements.slice(0, 5).join(', ')}${missingElements.length > 5 ? ' …' : ''})` : '');
}

async function start() {
  checkBuild();
  const me = await api('/auth/me').catch(() => null);
  if (!me) return;
  const foot = $('#footer-server');
  if (me.build !== BUILD) {
    // The page files are newer (or older) than the running server process: it was not restarted after an update.
    const b = document.createElement('div');
    b.className = 'banner error';
    b.textContent = `대시보드 서버 프로세스가 화면 파일과 다른 버전으로 실행 중입니다 (서버 build ${me.build || '이전 버전'}, 화면 build ${BUILD}). `
      + 'src, server.js 를 포함해 복사한 뒤 대시보드를 재시작하세요 (예: sudo systemctl restart wildfly-dashboard).';
    ($('.content') || document.body).prepend(b);
  }
  if (foot) foot.dataset.build = `build ${me.build || '?'}`;
  state.user = me.user;
  $('#user-avatar').textContent = me.user.username.slice(0, 2);
  $('#user-name').textContent = me.user.username;
  $('#user-role').textContent = me.user.role === 'admin' ? '관리자' : '조회 전용';
  $('#mock-banner').hidden = !me.mock;
  $('#nav-users').hidden = me.user.role !== 'admin';
  if (me.user.mustChangePassword) { openPasswordModal(true); return; }
  syncServers(await api('/servers'));
  // With several instances, start on the multi-instance overview.
  let view = state.servers.length === 1 ? 'overview' : 'instances';
  try { view = sessionStorage.getItem('wfdash.view') || view; } catch (_) { /* storage unavailable */ }
  if (!TITLES[view] || (view === 'users' && me.user.role !== 'admin')) view = 'overview';
  setView(view);
}

start();
