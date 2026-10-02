'use strict';

/* global Chart */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const esc = (v) => String(v === undefined || v === null ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const state = {
  user: null,
  servers: [],
  server: null,
  view: 'overview',
  timer: null,
  history: [], // memory samples for the charts
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
  const res = await fetch(`/api${path}`, { method: opts.method || 'GET', headers, body });
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
  return `<div class="meter"><div class="row"><span>${label}</span><span class="num">${valueText || `${fmtBytes(used)} / ${fmtBytes(total)}`} ${total ? `(${pct.toFixed(0)}%)` : ''}</span></div>
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
  overview: '서버 정보', memory: '메모리 (Heap / Metaspace)', datasources: 'DB 데이터소스',
  threads: '쓰레드 덤프', heap: '힙 덤프 분석', users: '사용자 관리',
};
function setView(view) {
  state.view = view;
  $$('.nav-item[data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $$('[data-view-panel]').forEach((p) => { p.hidden = p.dataset.viewPanel !== view; });
  $('#view-title').textContent = TITLES[view];
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
  if (!state.server) return;
  try {
    const v = state.view;
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
    showError(`${state.server.name}: ${e.message}`);
  }
}

// ---------------------------------------------------------------- overview
async function loadOverview() {
  const [info, mem] = await Promise.all([
    api(`/servers/${state.server.id}/info`),
    sampleMemory(),
  ]);
  const s = info.server; const j = info.jvm || {}; const os = info.os || {};
  const running = s.serverState === 'running';
  const heapPct = mem.heap.percent;
  const meta = mem.metaspace;
  $('#ov-tiles').innerHTML = [
    tile('서버 상태', `<span class="dot ${running ? 'good' : /required/.test(s.serverState) ? 'warning' : 'critical'}"></span> ${esc(s.serverState || '-')}`,
      `${esc(s.runningMode || '')} · ${esc(s.suspendState || '')}`),
    tile('가동 시간', esc(fmtDuration(j.uptime)), `시작: ${esc(fmtTime(j.startTime))}`),
    tile('Heap 사용률', `${heapPct ?? '-'}%`, `${fmtBytes(mem.heap.used)} / ${fmtBytes(mem.heap.max)}`, levelLabel(heapPct)),
    tile('Metaspace', meta ? fmtBytes(meta.usage.used) : '-',
      meta ? `committed ${fmtBytes(meta.usage.committed)}${meta.usage.max ? ` / max ${fmtBytes(meta.usage.max)}` : ' / max 무제한'}` : '', meta ? levelLabel(meta.usage.max ? meta.usage.percent : null) : ''),
  ].join('');
  $('#ov-server').innerHTML = kv([
    ['서버 이름', s.name], ['제품', `${s.productName || ''} ${s.productVersion || ''}`.trim()],
    ['Core 버전', s.releaseVersion], ['실행 형태', `${s.launchType || ''} ${s.processType ? `(${s.processType})` : ''}`],
    ['호스트', s.hostName], ['설정 파일', s.configFile], ['Base 디렉터리', s.baseDir], ['로그 디렉터리', s.logDir], ['관리 API 버전', s.managementVersion], ['UUID', s.uuid],
  ]);
  $('#ov-jvm').innerHTML = kv([
    ['PID / 이름', j.name], ['VM', j.vmName], ['벤더', j.vmVendor], ['VM 버전', j.vmVersion],
    ['Java 버전', j.javaVersion || j.specVersion], ['JAVA_HOME', j.javaHome],
    ['로드된 클래스', info.classLoading ? fmtNum(info.classLoading.loaded) : null],
  ]);
  $('#ov-os').innerHTML = kv([
    ['OS', `${os.name || ''} ${os.version || ''}`.trim()], ['아키텍처', os.arch], ['CPU 코어', os.availableProcessors],
    ['Load Average', os.systemLoadAverage >= 0 ? os.systemLoadAverage : 'N/A'],
    ...info.interfaces.map((i) => [`인터페이스 ${i.name}`, i.address]),
    ['관리 API', state.server.url],
  ]);
  $('#ov-dep-count').textContent = `${info.deployments.length}개`;
  $('#ov-deployments').innerHTML = info.deployments.length ? `<table><thead><tr><th>이름</th><th>상태</th><th>활성화 시각</th></tr></thead><tbody>${
    info.deployments.map((d) => `<tr><td>${esc(d.name)}</td><td><span class="badge ${d.status === 'OK' ? 'good' : d.status === 'FAILED' ? 'critical' : ''}">${d.status === 'OK' ? '● ' : ''}${esc(d.status || (d.enabled ? 'enabled' : 'disabled'))}</span></td><td class="muted">${esc(fmtTime(d.enabledTime))}</td></tr>`).join('')
  }</tbody></table>` : '<div class="empty">배포된 애플리케이션이 없습니다</div>';
  $('#ov-args').textContent = (j.inputArguments || []).join('\n') || '-';
}

// ---------------------------------------------------------------- memory
async function sampleMemory() {
  const mem = await api(`/servers/${state.server.id}/memory`);
  state.history.push({
    t: mem.timestamp,
    heapUsed: mem.heap.used, heapCommitted: mem.heap.committed, heapMax: mem.heap.max,
    metaUsed: mem.metaspace && mem.metaspace.usage.used,
    metaCommitted: mem.metaspace && mem.metaspace.usage.committed,
    metaMax: mem.metaspace && mem.metaspace.usage.max,
  });
  if (state.history.length > HISTORY_MAX) state.history.shift();
  state.lastMemory = mem;
  if (state.view === 'memory') updateCharts();
  return mem;
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

function makeLineChart(canvas, series) {
  const grid = cssVar('--grid'); const muted = cssVar('--text-muted');
  return new Chart(canvas, {
    type: 'line',
    data: { labels: [], datasets: series.map((s) => ({
      label: s.label, data: [], borderColor: cssVar(s.color), backgroundColor: cssVar(s.color),
      borderWidth: 2, borderDash: s.dash ? [5, 4] : [], pointRadius: 0, pointHoverRadius: 4, tension: 0.2, fill: false,
    })) },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${fmtBytes(c.parsed.y)}` } },
      },
      scales: {
        x: { ticks: { color: muted, maxTicksLimit: 6, maxRotation: 0 }, grid: { display: false }, border: { color: cssVar('--axis') } },
        y: { beginAtZero: true, ticks: { color: muted, callback: (v) => fmtAxisBytes(v) }, grid: { color: grid }, border: { display: false } },
      },
    },
  });
}

function legendHtml(series) {
  return series.map((s) => `<span class="${s.dash ? 'dashed' : ''}" style="--c:var(${s.color})">${esc(s.label)}</span>`).join('');
}

const HEAP_SERIES = [
  { label: '사용', color: '--series-1', key: 'heapUsed' },
  { label: 'Committed', color: '--series-2', key: 'heapCommitted' },
  { label: '최대 (Xmx)', color: '--text-muted', key: 'heapMax', dash: true },
];
const META_SERIES = [
  { label: '사용', color: '--series-1', key: 'metaUsed' },
  { label: 'Committed', color: '--series-2', key: 'metaCommitted' },
  { label: 'MaxMetaspaceSize', color: '--text-muted', key: 'metaMax', dash: true },
];

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
  const labels = state.history.map((h) => fmtClock(h.t));
  for (const [chart, series] of [[state.charts.heap, HEAP_SERIES], [state.charts.meta, META_SERIES]]) {
    chart.data.labels = labels;
    series.forEach((s, i) => { chart.data.datasets[i].data = state.history.map((h) => (h[s.key] ?? null)); });
    chart.update();
  }
  const h = state.history;
  $('#heap-chart-range').textContent = h.length > 1 ? `최근 ${fmtDuration(h[h.length - 1].t - h[0].t)}` : '';
}

function resetCharts() {
  Object.values(state.charts).forEach((c) => c.destroy());
  state.charts = {};
  if (state.view === 'memory') updateCharts();
}

// ---------------------------------------------------------------- datasources
async function loadDatasources() {
  const { datasources, drivers } = await api(`/servers/${state.server.id}/datasources`);
  $('#ds-list').innerHTML = datasources.length ? datasources.map((d) => {
    const p = d.pool;
    const hasStats = d.statisticsEnabled && p && p.activeCount !== undefined;
    const inUse = hasStats ? p.inUseCount : null;
    const warn = hasStats && (p.timedOut > 0 || p.blockingFailureCount > 0 || (d.maxPoolSize && p.inUseCount >= d.maxPoolSize));
    return `<div class="card">
      <h3>${esc(d.name)} ${d.xa ? '<span class="badge">XA</span>' : ''}
        <span class="badge ${d.enabled ? 'good' : ''}">${d.enabled ? '● 활성' : '비활성'}</span>
        ${warn ? '<span class="badge warning">▲ 풀 포화/타임아웃</span>' : ''}
        <span class="right">${isAdmin() ? `<button class="btn sm" data-ds-test="${esc(d.name)}" data-xa="${d.xa}">연결 테스트</button>` : ''}</span></h3>
      <dl class="kv">${kv([
        ['JNDI', d.jndiName], ['URL', d.connectionUrl], ['드라이버', d.driver], ['DB 사용자', d.userName],
        ['풀 크기', `min ${d.minPoolSize ?? 0} / max ${d.maxPoolSize ?? '-'}`], ['Blocking timeout', d.blockingTimeout !== undefined ? fmtMs(d.blockingTimeout) : null],
        ['유효성 검사', d.validConnectionSql ? `${d.validConnectionSql}${d.backgroundValidation ? ' (background)' : ''}` : null],
      ])}</dl>
      ${hasStats ? `
        ${meter('사용 중 커넥션 / 최대', inUse, d.maxPoolSize, `${fmtNum(inUse)} / ${fmtNum(d.maxPoolSize)}`)}
        ${meter('생성된(Active) 커넥션 / 최대', p.activeCount, d.maxPoolSize, `${fmtNum(p.activeCount)} / ${fmtNum(d.maxPoolSize)}`)}
        <div class="table-wrap section"><table><tbody>
          <tr><td>가용(Available)</td><td class="r">${fmtNum(p.availableCount)}</td><td>최대 사용(MaxUsed)</td><td class="r">${fmtNum(p.maxUsedCount)}</td></tr>
          <tr><td>대기 횟수(Wait)</td><td class="r">${fmtNum(p.waitCount)}</td><td>타임아웃(TimedOut)</td><td class="r">${fmtNum(p.timedOut)}</td></tr>
          <tr><td>평균 대기 시간</td><td class="r">${fmtMs(p.averageBlockingTime)}</td><td>최대 대기 시간</td><td class="r">${fmtMs(p.maxWaitTime)}</td></tr>
          <tr><td>평균 사용 시간</td><td class="r">${fmtMs(p.averageUsageTime)}</td><td>평균 생성 시간</td><td class="r">${fmtMs(p.averageCreationTime)}</td></tr>
          <tr><td>생성 / 제거</td><td class="r">${fmtNum(p.createdCount)} / ${fmtNum(p.destroyedCount)}</td><td>획득 실패</td><td class="r">${fmtNum(p.blockingFailureCount)}</td></tr>
          ${d.jdbc && d.jdbc.preparedStatementCacheHitCount !== undefined ? `<tr><td>PS 캐시 hit / miss</td><td class="r">${fmtNum(d.jdbc.preparedStatementCacheHitCount)} / ${fmtNum(d.jdbc.preparedStatementCacheMissCount)}</td><td></td><td></td></tr>` : ''}
        </tbody></table></div>`
      : `<p class="muted" style="font-size:12.5px;margin-bottom:0">풀 통계가 비활성화되어 있습니다. 활성화: <code>/subsystem=datasources/${d.xa ? 'xa-data-source' : 'data-source'}=${esc(d.name)}:write-attribute(name=statistics-enabled,value=true)</code></p>`}
    </div>`;
  }).join('') : '<div class="card empty">설정된 데이터소스가 없습니다</div>';
  $('#ds-drivers').innerHTML = `<table><thead><tr><th>이름</th><th>모듈</th><th>클래스</th><th>버전</th></tr></thead><tbody>${
    drivers.map((d) => `<tr><td>${esc(d.name)}</td><td class="mono">${esc(d.module)}</td><td class="mono">${esc(d.className || '-')}</td><td>${esc(d.version || '-')}</td></tr>`).join('')
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
const STATE_COLOR = { RUNNABLE: '--series-3', BLOCKED: '--critical', WAITING: '--series-1', TIMED_WAITING: '--series-4', NEW: '--text-muted', TERMINATED: '--text-muted' };

function frameText(f) {
  const loc = f.nativeMethod ? 'Native Method' : f.fileName ? (f.lineNumber >= 0 ? `${f.fileName}:${f.lineNumber}` : f.fileName) : 'Unknown Source';
  return `${f.className}.${f.methodName}(${loc})`;
}

async function takeThreadDump() {
  const btn = $('#btn-thread-dump');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 수집 중...';
  try {
    state.threads = await api(`/servers/${state.server.id}/threads`);
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

$('#user-form').addEventListener('submit', async (e) => {
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

$('#pw-cancel').addEventListener('click', () => { $('#pw-modal').hidden = true; });
$('#pw-form').addEventListener('submit', async (e) => {
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
$('#btn-refresh').addEventListener('click', () => refresh());
$('#refresh-select').addEventListener('change', schedule);
$('#server-select').addEventListener('change', (e) => {
  state.server = state.servers.find((s) => s.id === e.target.value);
  state.history = [];
  state.threads = null;
  $('#thread-result').hidden = true;
  $('#thread-empty').hidden = false;
  resetCharts();
  refresh();
});
$('#btn-thread-dump').addEventListener('click', takeThreadDump);
$('#th-filter').addEventListener('input', renderThreadList);
$('#th-state-filter').addEventListener('change', renderThreadList);
$('#ha-filter').addEventListener('input', renderHistogram);
$('#btn-password').addEventListener('click', () => openPasswordModal(false));
$('#btn-logout').addEventListener('click', async () => {
  await api('/auth/logout', { method: 'POST' }).catch(() => {});
  location.href = '/login';
});
$('#heap-file').addEventListener('change', (e) => { if (e.target.files[0]) uploadHeap(e.target.files[0]); e.target.value = ''; });
$('#btn-heap-generate').addEventListener('click', async () => {
  if (!confirm('힙 덤프 생성 중에는 WildFly JVM 이 잠시 멈춥니다. 계속할까요?')) return;
  const btn = $('#btn-heap-generate');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 생성 중...';
  try {
    const meta = await api(`/servers/${state.server.id}/heapdump`, { method: 'POST', body: { live: $('#heap-live').checked } });
    state.pendingOpen = meta.id;
    toast(`힙 덤프 생성 완료 (${fmtBytes(meta.size)}) - 분석을 시작했습니다`);
  } catch (ex) {
    toast(ex.message);
  } finally {
    btn.textContent = '힙 덤프 생성';
    await loadHeapList();
  }
});
const dz = $('#dropzone');
['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); if (isAdmin()) dz.classList.add('drag'); }));
['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
dz.addEventListener('drop', (e) => {
  if (!isAdmin()) { toast('관리자만 업로드할 수 있습니다'); return; }
  const f = e.dataTransfer.files[0];
  if (f) uploadHeap(f);
});
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', resetCharts);

async function start() {
  const me = await api('/auth/me').catch(() => null);
  if (!me) return;
  state.user = me.user;
  $('#who').textContent = `${me.user.username} (${me.user.role})`;
  $('#mock-banner').hidden = !me.mock;
  $('#nav-users').hidden = me.user.role !== 'admin';
  if (me.user.mustChangePassword) { openPasswordModal(true); return; }
  state.servers = await api('/servers');
  $('#server-select').innerHTML = state.servers.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
  state.server = state.servers[0];
  let view = 'overview';
  try { view = sessionStorage.getItem('wfdash.view') || view; } catch (_) { /* storage unavailable */ }
  if (!TITLES[view] || (view === 'users' && me.user.role !== 'admin')) view = 'overview';
  setView(view);
}

start();
