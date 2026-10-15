/* Apache 사전점검 대시보드 화면 스크립트 (외부 라이브러리 없음, 모든 값은 textContent 로만 넣음) */
(function () {
  'use strict';

  const STATUS = {
    compromise: { label: '침해 의심', icon: '✖', rank: 0 },
    risk: { label: '위험', icon: '▲', rank: 1 },
    warn: { label: '주의', icon: '◆', rank: 2 },
    ok: { label: '양호', icon: '✔', rank: 3 },
    info: { label: '정보', icon: 'i', rank: 4 }
  };
  const SEVERITY = {
    critical: { label: 'critical', color: 'c-critical', rank: 0 },
    important: { label: 'important', color: 'c-serious', rank: 1 },
    moderate: { label: 'moderate', color: 'c-warning', rank: 2 },
    low: { label: 'low', color: 'c-info', rank: 3 }
  };
  const SECTION_TITLE = {
    '1': '[1] 버전 및 설치 방식',
    '2': '[2] CVE 판정',
    '3': '[3] 위험 설정',
    '4': '[4] 침해 흔적'
  };

  const state = { me: null, reports: [], sort: { key: 'status', asc: true } };
  const $ = (s, root) => (root || document).querySelector(s);
  const $$ = (s, root) => Array.from((root || document).querySelectorAll(s));

  /** 안전한 DOM 생성 도우미: h('div', {class:'x'}, '텍스트', 자식...) */
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else if (k === 'dataset') Object.assign(el.dataset, v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function badge(kind, text) {
    const s = STATUS[kind];
    return h('span', { class: 'badge b-' + kind }, s ? h('span', { class: 'ic', 'aria-hidden': 'true' }, s.icon) : null, text || (s ? s.label : kind));
  }
  function sevBadge(sev) {
    return h('span', { class: 'badge b-' + sev }, sev);
  }

  async function api(path, opts) {
    opts = opts || {};
    const headers = Object.assign({}, opts.headers || {});
    if (opts.method && opts.method !== 'GET' && state.me) headers['X-CSRF-Token'] = state.me.csrf;
    const res = await fetch('api/' + path, Object.assign({}, opts, { headers, credentials: 'same-origin' }));
    if (res.status === 401) { location.href = 'login'; throw new Error('로그인이 필요합니다.'); }
    if (res.status === 403 && /비밀번호/.test(await res.clone().text())) { location.href = 'password'; }
    const body = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
    if (!res.ok) throw new Error((body && body.error) || ('요청 실패 (' + res.status + ')'));
    return body;
  }

  function showAlert(msg) {
    const a = $('#alert');
    a.textContent = msg;
    a.hidden = !msg;
  }

  // ---------------------------------------------------------------- 데이터
  function cveTotal(r) {
    return Object.values(r.cveUnpatched).reduce((a, b) => a + b, 0);
  }

  function filtered() {
    const q = $('#f-q').value.trim().toLowerCase();
    const st = $('#f-status').value;
    const latestOnly = $('#f-latest').checked;
    const dqOnly = $('#f-dq').checked;
    let list = state.reports;
    if (latestOnly) {
      const seen = new Set();
      list = list.filter(r => { // 서버에서 최신순 정렬되어 옴
        if (seen.has(r.instanceKey)) return false;
        seen.add(r.instanceKey);
        return true;
      });
    }
    return list.filter(r => {
      if (st && r.status !== st) return false;
      if (dqOnly && !r.dataQuality.length) return false;
      if (!q) return true;
      const hay = [r.host, r.version, r.versionLine, r.binary, r.id, r.cveList.map(c => c.id).join(' ')].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  function sortList(list) {
    const { key, asc } = state.sort;
    const val = r => {
      switch (key) {
        case 'status': return STATUS[r.status].rank * 1000 - r.counts.risk;
        case 'host': return r.host;
        case 'version': return (r.version || '').split('.').map(n => n.padStart(4, '0')).join('.');
        case 'checkedAt': return r.checkedAt || '';
        case 'cve': return cveTotal(r);
        default: return r.counts[key];
      }
    };
    return list.slice().sort((a, b) => {
      const x = val(a), y = val(b);
      const c = x < y ? -1 : x > y ? 1 : 0;
      return asc ? c : -c;
    });
  }

  // ---------------------------------------------------------------- 렌더링
  function render() {
    const list = sortList(filtered());
    $('#empty').hidden = state.reports.length > 0;
    $('#f-count').textContent = state.reports.length ? `${list.length}건 표시 / 전체 리포트 ${state.reports.length}건` : '';
    renderKpis(list);
    renderTable(list);
    renderFindingsChart(list);
    renderCveChart(list);
    renderConfigChart(list);
  }

  function kpi(label, value, unit, hint, kind, onclick) {
    return h('div', { class: 'kpi' + (onclick ? ' clickable' : ''), onclick, role: onclick ? 'button' : null, tabindex: onclick ? '0' : null },
      h('div', { class: 'label' }, kind ? badge(kind, STATUS[kind].label) : null, label),
      h('div', { class: 'value' }, String(value), unit ? h('small', null, unit) : null),
      hint ? h('div', { class: 'hint' }, hint) : null);
  }

  function setStatusFilter(v) {
    $('#f-status').value = v;
    render();
  }

  function renderKpis(list) {
    const n = list.length;
    const count = s => list.filter(r => r.status === s).length;
    const below = list.filter(r => r.below2469).length;
    const eol = list.filter(r => r.eol).length;
    const unpatched = list.filter(r => cveTotal(r) > 0).length;
    const dq = list.filter(r => r.dataQuality.length).length;
    $('#kpis').replaceChildren(
      kpi('점검 인스턴스', n, '개', '필터 조건 기준'),
      kpi('', count('compromise'), '대', '[4] 침해 흔적에 [위험] 있음 → 사고 대응 우선', 'compromise', () => setStatusFilter('compromise')),
      kpi('', count('risk'), '대', '침해 흔적 외 [위험] 항목 보유', 'risk', () => setStatusFilter('risk')),
      kpi('2.4.69 미만', below, '대', eol ? `이 중 EOL(2.2 이하) ${eol}대` : '업그레이드 대상'),
      kpi('미조치 CVE 보유', unpatched, '대', '모듈 조건 충족 + 백포트 기록 없음'),
      kpi('데이터 경고', dq, '대', '점검이 불완전해 수동 확인 필요', null, dq ? () => { $('#f-dq').checked = true; render(); } : null)
    );
  }

  function renderTable(list) {
    $$('#servers th[data-sort]').forEach(th => {
      th.classList.toggle('sorted', th.dataset.sort === state.sort.key);
      th.classList.toggle('asc', th.dataset.sort === state.sort.key && state.sort.asc);
    });
    const rows = list.map(r => {
      const num = v => h('td', { class: 'num' + (v ? '' : ' zero') }, String(v));
      const chips = Object.entries(r.cveUnpatched).filter(([, v]) => v > 0)
        .map(([sev, v]) => h('span', { class: 'badge b-' + sev, title: sev }, `${sev[0].toUpperCase()} ${v}`));
      const tr = h('tr', { class: 'row', tabindex: '0', onclick: () => openDetail(r.id),
        onkeydown: e => { if (e.key === 'Enter') openDetail(r.id); } },
        h('td', null, badge(r.status)),
        h('td', null, h('div', null, r.host), h('div', { class: 'sub mono' }, (r.binary || '') + (r.pid ? ` · PID ${r.pid}` : ''))),
        h('td', null, h('div', null, r.version || '확인 불가'),
          r.eol ? h('div', { class: 'sub' }, 'EOL') : r.below2469 ? h('div', { class: 'sub' }, '2.4.69 미만') : h('div', { class: 'sub' }, '2.4.69 이상')),
        h('td', null, r.installType || '-'),
        h('td', null, r.checkedAt || '-'),
        num(r.counts.risk), num(r.counts.warn), num(r.counts.ok),
        h('td', { class: 'num' }, chips.length ? h('div', { class: 'cve-chips' }, chips)
          : r.version && !r.version.startsWith('2.4.') ? h('span', { class: 'badge b-warn', title: '2.4.x 가 아니라 스크립트가 CVE 판정을 하지 않았습니다. EOL 버전은 교체가 근본 대책입니다.' }, '판정 제외')
          : h('span', { class: 'zero' }, '0')),
        h('td', null, r.dataQuality.length ? h('span', { class: 'badge b-warn', title: r.dataQuality.join('\n') }, h('span', { class: 'ic' }, '!'), `${r.dataQuality.length}건`) : h('span', { class: 'zero' }, '-'))
      );
      return tr;
    });
    if (!rows.length) rows.push(h('tr', null, h('td', { colspan: '10', class: 'muted' }, state.reports.length ? '조건에 맞는 결과가 없습니다.' : '등록된 리포트가 없습니다.')));
    $('#servers tbody').replaceChildren(...rows);
  }

  function legend(target, items) {
    $(target).replaceChildren(...items.map(([cls, label]) => h('span', null, h('i', { class: 'dot ' + cls, 'aria-hidden': 'true' }), label)));
  }

  /** 가로 막대 1줄: segs = [{cls, value, label}] */
  function hbar(name, segs, max, tipTitle, onclick) {
    const total = segs.reduce((a, s) => a + s.value, 0);
    const track = h('div', { class: 'track' });
    segs.filter(s => s.value > 0).forEach(s => {
      const seg = h('div', { class: 'seg ' + s.cls });
      seg.style.width = (s.value / max * 100) + '%';
      track.append(seg);
    });
    const row = h('div', { class: 'hbar', role: onclick ? 'button' : null, tabindex: onclick ? '0' : null, onclick },
      h('div', { class: 'name', title: name }, name), track, h('div', { class: 'val' }, String(total)));
    tip(row, () => [tipTitle || name, ...segs.map(s => `${s.label}: ${s.value}`)]);
    return row;
  }

  function renderFindingsChart(list) {
    legend('#legend-findings', [['c-critical', '위험'], ['c-warning', '주의'], ['c-good', '양호']]);
    const rows = list.slice().sort((a, b) => b.counts.risk - a.counts.risk || b.counts.warn - a.counts.warn).slice(0, 20);
    const max = Math.max(1, ...rows.map(r => r.counts.risk + r.counts.warn + r.counts.ok));
    const el = $('#chart-findings');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '데이터 없음')); return; }
    el.replaceChildren(...rows.map(r => hbar(r.host + (r.pid ? ` (PID ${r.pid})` : ''), [
      { cls: 'c-critical', value: r.counts.risk, label: '위험' },
      { cls: 'c-warning', value: r.counts.warn, label: '주의' },
      { cls: 'c-good', value: r.counts.ok, label: '양호' }
    ], max, `${r.host} · Apache ${r.version || '?'}`, () => openDetail(r.id))));
    if (list.length > rows.length) el.append(h('div', { class: 'none' }, `상위 ${rows.length}개만 표시 (위험 많은 순)`));
  }

  function renderCveChart(list) {
    legend('#legend-cve', [['c-critical', '미조치 추정(막대 색=등급)'], ['c-backport', '백포트 추정']]);
    const agg = new Map();
    list.forEach(r => r.cveList.forEach(c => {
      const a = agg.get(c.id) || { id: c.id, open: 0, bp: 0, sev: SEVERITY[c.severity] ? c.severity : 'low', desc: c.description };
      if (c.backported) a.bp++; else a.open++;
      agg.set(c.id, a);
    }));
    const rows = Array.from(agg.values())
      .sort((a, b) => (b.open - a.open) || SEVERITY[a.sev].rank - SEVERITY[b.sev].rank || (b.bp - a.bp)).slice(0, 15);
    const el = $('#chart-cve');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '해당 CVE 없음')); return; }
    const max = Math.max(1, ...rows.map(a => a.open + a.bp));
    el.replaceChildren(...rows.map(a => hbar(`${a.id} · ${a.sev}`, [
      { cls: SEVERITY[a.sev].color, value: a.open, label: '미조치 추정 서버' },
      { cls: 'c-backport', value: a.bp, label: '백포트 추정 서버' }
    ], max, `${a.id} [${a.sev}] ${a.desc || ''}`, () => { $('#f-q').value = a.id; render(); })));
  }

  function renderConfigChart(list) {
    legend('#legend-config', [['c-critical', '위험'], ['c-warning', '주의']]);
    const agg = new Map();
    list.forEach(r => {
      const seen = new Set();
      r.configIssues.forEach(ci => {
        const key = ci.text.split(/ → | \(/)[0].trim();
        if (seen.has(key)) return;
        seen.add(key);
        const a = agg.get(key) || { key, risk: 0, warn: 0, full: ci.text };
        a[ci.level]++;
        agg.set(key, a);
      });
    });
    const rows = Array.from(agg.values()).sort((a, b) => (b.risk + b.warn) - (a.risk + a.warn) || b.risk - a.risk).slice(0, 12);
    const el = $('#chart-config');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '위험·주의 설정 없음')); return; }
    const max = Math.max(1, ...rows.map(a => a.risk + a.warn));
    el.replaceChildren(...rows.map(a => hbar(a.key, [
      { cls: 'c-critical', value: a.risk, label: '위험 서버' },
      { cls: 'c-warning', value: a.warn, label: '주의 서버' }
    ], max, a.full)));
  }

  // ---------------------------------------------------------------- 툴팁
  function tip(el, lines) {
    const t = $('#tooltip');
    const show = e => {
      const [title, ...rest] = lines();
      t.replaceChildren(h('b', null, title), ...rest.map(l => h('div', null, l)));
      t.hidden = false;
      move(e);
    };
    const move = e => {
      const x = Math.min(e.clientX + 14, window.innerWidth - t.offsetWidth - 8);
      const y = Math.min(e.clientY + 14, window.innerHeight - t.offsetHeight - 8);
      t.style.left = x + 'px';
      t.style.top = y + 'px';
    };
    el.addEventListener('mouseenter', show);
    el.addEventListener('mousemove', move);
    el.addEventListener('mouseleave', () => { t.hidden = true; });
  }

  // ---------------------------------------------------------------- 상세
  let current = null;

  async function openDetail(id) {
    let r;
    try { r = await api('reports/' + encodeURIComponent(id)); } catch (e) { showAlert(e.message); return; }
    current = r;
    const dlg = $('#detail');
    $('#d-title').replaceChildren(badge(r.status), r.host, h('span', { class: 'muted' }, `Apache ${r.version || '?'}`));
    $('#d-sub').textContent = [r.checkedAt, r.binary, r.pid ? 'PID ' + r.pid : null, r.installType ? r.installType + ' 설치' : null,
      r.runUser ? '실행계정 ' + r.runUser : null, r.moduleCount !== null ? `모듈 ${r.moduleCount}개` : null, r.id].filter(Boolean).join(' · ');
    $('#d-raw').href = 'api/reports/' + encodeURIComponent(r.id) + '/raw';

    $('#d-dq').replaceChildren(...(r.dataQuality.length ? [h('div', { class: 'alert warn dq' },
      h('b', null, '데이터 품질 경고 — 아래 결과를 그대로 믿기 전에 확인하세요'), ...r.dataQuality.map(d => h('div', null, '· ' + d)))] : []),
      ...(r.compromise ? [h('div', { class: 'alert' }, h('b', null, '침해 의심: '), '[4] 침해 흔적 점검에 [위험] 항목이 있습니다. 설정 보완·패치보다 침해사고 대응(격리·증거 보존·분석)이 우선입니다.')] : []));

    const un = Object.values(r.cveUnpatched).reduce((a, b) => a + b, 0);
    const ap = r.cves.filter(c => c.applicable).length;
    $('#d-kpis').replaceChildren(
      kpi('', r.counts.risk, '건', null, 'risk'),
      kpi('', r.counts.warn, '건', null, 'warn'),
      kpi('', r.counts.ok, '건', null, 'ok'),
      kpi('해당 CVE', ap, '건', `미조치 추정 ${un} / 백포트 추정 ${ap - un}`),
      kpi('미해당 CVE', r.cves.length - ap, '건', '필요 모듈 미사용')
    );

    renderFindings(r);
    renderCves(r);
    renderHistory(r);
    $('#d-rawtext').textContent = r.raw;
    selectTab('findings');
    if (!dlg.open) dlg.showModal();
  }

  function renderFindings(r) {
    const panel = $('[data-panel="findings"]');
    const out = [];
    ['4', '3', '1', '2'].forEach(sec => { // 침해 흔적을 가장 먼저
      const items = r.findings.filter(f => f.section === sec)
        .sort((a, b) => STATUS[a.level].rank - STATUS[b.level].rank);
      if (!items.length) return;
      out.push(h('div', { class: 'sec' }, h('h3', null, SECTION_TITLE[sec] || sec),
        ...items.map(f => h('div', { class: 'finding' },
          h('div', null, badge(f.level)),
          h('div', null, f.text,
            f.details.length ? h('details', { open: f.level === 'risk' || null },
              h('summary', null, `상세 ${f.details.length}줄`), h('pre', { class: 'details' }, f.details.join('\n'))) : null)))));
    });
    panel.replaceChildren(...(out.length ? out : [h('p', { class: 'muted' }, '점검 항목이 없습니다.')]));
  }

  function renderCves(r) {
    const panel = $('[data-panel="cves"]');
    const rows = r.cves.slice().sort((a, b) =>
      (b.applicable - a.applicable) || (a.backported - b.backported) || SEVERITY[a.severity].rank - SEVERITY[b.severity].rank);
    if (!rows.length) {
      panel.replaceChildren(h('p', { class: 'muted' }, 'CVE 판정 결과가 없습니다. (2.4.69 이상이거나 2.4.x 가 아님)'));
      return;
    }
    panel.replaceChildren(
      h('p', { class: 'muted' }, '판정은 업스트림 버전 기준입니다. 패키지 설치본의 "백포트 추정"은 changelog 에 CVE 번호가 있다는 뜻일 뿐이므로 배포판 보안 공지로 최종 확인하세요.'),
      h('div', { class: 'table-scroll' }, h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['판정', 'CVE', '등급', '설명', '영향 버전', '필요 모듈'].map(t => h('th', null, t)))),
        h('tbody', null, ...rows.map(c => h('tr', null,
          h('td', null, !c.applicable ? h('span', { class: 'badge b-skip' }, '미해당')
            : c.backported ? h('span', { class: 'badge b-backport' }, '백포트 추정') : badge('risk', '해당')),
          h('td', { class: 'mono' }, h('a', { href: 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(c.id), target: '_blank', rel: 'noopener noreferrer' }, c.id)),
          h('td', null, sevBadge(c.severity)),
          h('td', null, c.description || h('span', { class: 'muted' }, '(미해당 항목은 리포트에 설명 없음)')),
          h('td', { class: 'mono' }, c.affected || '-'),
          h('td', { class: 'mono' }, c.condition || '-'))))))
    );
  }

  function renderHistory(r) {
    const panel = $('[data-panel="history"]');
    const same = state.reports.filter(x => x.instanceKey === r.instanceKey);
    panel.replaceChildren(
      h('p', { class: 'muted' }, '같은 호스트·실행파일·PID 의 점검 기록입니다. 패치 전/후 비교에 사용하세요. (재기동으로 PID 가 바뀌면 다른 인스턴스로 보입니다)'),
      h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['점검 일시', '판정', '버전', '위험', '주의', '양호', '미조치 CVE', '파일'].map(t => h('th', null, t)))),
        h('tbody', null, ...same.map(x => h('tr', { class: 'row', onclick: () => openDetail(x.id) },
          h('td', null, x.checkedAt + (x.id === r.id ? ' (현재)' : '')),
          h('td', null, badge(x.status)), h('td', null, x.version || '-'),
          h('td', { class: 'num' }, String(x.counts.risk)), h('td', { class: 'num' }, String(x.counts.warn)),
          h('td', { class: 'num' }, String(x.counts.ok)), h('td', { class: 'num' }, String(cveTotal(x))),
          h('td', { class: 'mono' }, x.id))))));
  }

  function selectTab(name) {
    $$('#detail .tab').forEach(t => t.setAttribute('aria-selected', String(t.dataset.tab === name)));
    $$('#detail .tabpanel').forEach(p => { p.hidden = p.dataset.panel !== name; });
  }

  // ---------------------------------------------------------------- 업로드
  async function uploadFiles(files) {
    if (!files.length) return;
    const fd = new FormData();
    Array.from(files).forEach(f => fd.append('files', f, f.name));
    const ul = $('#u-results');
    ul.replaceChildren(h('li', null, '업로드 중...'));
    try {
      const results = await api('reports', { method: 'POST', body: fd });
      ul.replaceChildren(...results.map(x => h('li', { class: x.ok ? 'ok' : 'fail' },
        x.ok ? `✔ ${x.file} → 등록됨` : `✖ ${x.file} : ${x.error}`)));
      await load();
    } catch (e) {
      ul.replaceChildren(h('li', { class: 'fail' }, '✖ ' + e.message));
    }
    $('#u-files').value = '';
  }

  // ---------------------------------------------------------------- 사용자 관리
  async function loadUsers() {
    const users = await api('users');
    $('#user-rows').replaceChildren(...users.map(u => h('tr', null,
      h('td', null, u.name + (u.name === state.me.user ? ' (나)' : '')),
      h('td', null, u.role === 'admin' ? '관리자' : '조회 전용'),
      h('td', null, u.mustChange ? h('span', { class: 'badge b-warn' }, '비밀번호 변경 대기') : h('span', { class: 'badge b-ok' }, '정상')),
      h('td', null, u.name === state.me.user ? null : h('span', { class: 'dialog-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: () => resetUser(u.name) }, '비밀번호 초기화'),
        h('button', { class: 'btn small btn-danger', type: 'button', onclick: () => deleteUser(u.name) }, '삭제'))))));
  }
  function showTemp(res) {
    const box = $('#user-temp');
    box.replaceChildren(h('b', null, `${res.name} 임시 비밀번호: `), h('code', null, res.tempPassword),
      h('div', { class: 'muted' }, '이 화면을 닫으면 다시 볼 수 없습니다. 안전한 경로로 전달하세요.'));
    box.hidden = false;
  }
  async function resetUser(name) {
    if (!confirm(`${name} 의 비밀번호를 초기화할까요?`)) return;
    try { showTemp(await api('users/' + encodeURIComponent(name) + '/reset', { method: 'POST' })); await loadUsers(); }
    catch (e) { alert(e.message); }
  }
  async function deleteUser(name) {
    if (!confirm(`${name} 사용자를 삭제할까요?`)) return;
    try { await api('users/' + encodeURIComponent(name), { method: 'DELETE' }); await loadUsers(); }
    catch (e) { alert(e.message); }
  }

  // ---------------------------------------------------------------- 시작
  async function load() {
    try {
      state.reports = await api('reports');
      showAlert('');
    } catch (e) {
      showAlert('리포트를 불러오지 못했습니다: ' + e.message);
      state.reports = [];
    }
    render();
  }

  async function init() {
    try {
      state.me = await api('me');
    } catch (e) {
      showAlert(e.message);
      return;
    }
    document.body.classList.toggle('is-admin', !!state.me.admin);
    $('#who').textContent = `${state.me.user} (${state.me.admin ? '관리자' : '조회 전용'})`;
    $('#logout-csrf').value = state.me.csrf;
    if (state.me.reportDir) $('#report-dir').textContent = `(리포트 폴더: ${state.me.reportDir})`;

    ['#f-q', '#f-status', '#f-latest', '#f-dq'].forEach(s => $(s).addEventListener('input', render));
    $('#btn-refresh').addEventListener('click', load);
    $$('#servers th[data-sort]').forEach(th => th.addEventListener('click', () => {
      const k = th.dataset.sort;
      state.sort = { key: k, asc: state.sort.key === k ? !state.sort.asc : k === 'status' || k === 'host' };
      render();
    }));
    $$('dialog [data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
    $$('#detail .tab').forEach(t => t.addEventListener('click', () => selectTab(t.dataset.tab)));
    $('#d-delete').addEventListener('click', async () => {
      if (!current || !confirm(`${current.id} 리포트를 삭제할까요? 되돌릴 수 없습니다.`)) return;
      try { await api('reports/' + encodeURIComponent(current.id), { method: 'DELETE' }); $('#detail').close(); await load(); }
      catch (e) { alert(e.message); }
    });

    $('#btn-upload').addEventListener('click', () => { $('#u-results').replaceChildren(); $('#upload').showModal(); });
    $('#u-files').addEventListener('change', e => uploadFiles(e.target.files));
    const drop = $('#drop');
    ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', e => uploadFiles(e.dataTransfer.files));

    $('#btn-users').addEventListener('click', async () => {
      $('#user-temp').hidden = true;
      try { await loadUsers(); $('#users').showModal(); } catch (e) { alert(e.message); }
    });
    $('#user-form').addEventListener('submit', async e => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        showTemp(await api('users', { method: 'POST', body: new URLSearchParams(fd) }));
        e.target.reset();
        await loadUsers();
      } catch (err) { alert(err.message); }
    });

    await load();
  }

  init();
})();
