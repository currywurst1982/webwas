/* WildFly 사전점검 대시보드 화면 스크립트 (외부 라이브러리 없음, 모든 값은 textContent 로만 넣음) */
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
    high: { label: 'high', color: 'c-serious', rank: 1 },
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

  const SVGNS = 'http://www.w3.org/2000/svg';
  /** SVG 요소 생성: svg('rect', {x:1}, 자식...) */
  function svg(tag, attrs, ...children) {
    const el = document.createElementNS(SVGNS, tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v);
      }
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  /** 아이콘: index.html 의 <symbol id="i-이름"> 사용 */
  function icon(name) {
    const el = document.createElementNS(SVGNS, 'svg');
    el.setAttribute('aria-hidden', 'true');
    const u = document.createElementNS(SVGNS, 'use');
    u.setAttribute('href', '#i-' + name);
    el.append(u);
    return el;
  }
  /** 상태색 (화면 위젯용, CSS 토큰과 같은 값) */
  const TONE = { compromise: '#e5484d', risk: '#ec835a', warn: '#fab219', ok: '#22c55e', none: '#7088ab' };

  /** "호스트 (IP)" — IP 기록이 없는 이전 리포트는 에이전트 접속 IP 를 "접속 IP"로 표시 */
  function hostLabel(r) {
    const s = r.ip ? `${r.host} (${r.ip}${r.ipFromAgent ? ', 접속 IP' : ''})` : r.host;
    // 한 서버에 WildFly 가 여러 개면 인스턴스 구분(서버 폴더·설정 파일), 없으면 설치 폴더 이름으로 구분 (IntrusionPdf.hostLabel 과 같은 규칙)
    if (r.confArg) return `${s} [${r.confArg.length <= 40 ? r.confArg : '…' + r.confArg.slice(-39)}]`;
    return r.binary ? `${s} [${r.binary.slice(r.binary.lastIndexOf('/') + 1)}]` : s;
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
    const src = state.sourceFilter;
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
      if (src && r.source !== src) return false;
      if (!q) return true;
      const hay = [r.host, ...(r.ips || []), r.version, r.versionLine, r.binary, r.id, r.cveList.map(c => c.id).join(' ')].join(' ').toLowerCase();
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
  /** 개요 화면용: 인스턴스별 최신 리포트 (에이전트를 고르면 그 에이전트 것만) */
  function overviewList() {
    const seen = new Set();
    return state.reports.filter(r => {
      if (seen.has(r.instanceKey)) return false;
      seen.add(r.instanceKey);
      return !state.sourceFilter || r.source === state.sourceFilter;
    });
  }

  function render() {
    const list = sortList(filtered());
    const ov = overviewList();
    $('#empty').hidden = state.reports.length > 0;
    $('#f-count').textContent = state.reports.length ? `${list.length}건 표시 / 전체 리포트 ${state.reports.length}건` : '';
    const chip = $('#f-source');
    chip.hidden = !state.sourceFilter;
    if (state.sourceFilter) {
      chip.replaceChildren(`에이전트: ${state.sourceFilter} `,
        h('button', { class: 'btn-link', type: 'button', 'aria-label': '에이전트 필터 해제', onclick: () => { state.sourceFilter = null; render(); renderSideAgents(); } }, '✕'));
    }
    // 개요
    renderKpis(ov);
    renderHeroMap(ov);
    renderTrend();
    renderLatestDonut(ov);
    renderStatusDonut(ov);
    renderSuspects();
    renderCveChart(ov);
    renderConfigChart(ov);
    // 서버 목록
    renderTable(list);
    renderFindingsChart(list);
  }

  function kpi(label, value, unit, hint, kind, onclick) {
    return h('div', { class: 'kpi' + (onclick ? ' clickable' : ''), onclick, role: onclick ? 'button' : null, tabindex: onclick ? '0' : null },
      h('div', { class: 'label' }, kind ? badge(kind, STATUS[kind].label) : null, label),
      h('div', { class: 'value' }, String(value), unit ? h('small', null, unit) : null),
      hint ? h('div', { class: 'hint' }, hint) : null);
  }

  /** 개요 상단 카드: 아이콘 타일 + 이름 + 큰 숫자 + 설명 */
  function statCard({ ico, tone, label, value, unit, hint, hintTone, onclick }) {
    return h('div', { class: 'kpi' + (tone ? ' t-' + tone : '') + (onclick ? ' clickable' : ''), onclick,
      role: onclick ? 'button' : null, tabindex: onclick ? '0' : null,
      onkeydown: onclick ? e => { if (e.key === 'Enter') onclick(); } : null },
      h('div', { class: 'ico' }, icon(ico)),
      h('div', { class: 'label' }, label),
      h('div', { class: 'value' }, String(value), unit ? h('small', null, unit) : null),
      hint ? h('div', { class: 'hint' + (hintTone ? ' ' + hintTone : '') }, hint) : null);
  }

  function setStatusFilter(v) {
    $('#f-status').value = v;
    render();
    showView('servers');
  }

  function renderKpis(list) {
    const n = list.length;
    const count = s => list.filter(r => r.status === s).length;
    const below = list.filter(r => r.belowLatest).length;
    const eol = list.filter(r => r.eol).length;
    const unpatched = list.filter(r => cveTotal(r) > 0).length;
    const dq = list.filter(r => r.dataQuality.length).length;
    const comp = count('compromise');
    $('#kpis').replaceChildren(
      statCard({ ico: 'server', label: '점검 서버', value: n, unit: '대', hint: state.sourceFilter ? `에이전트 ${state.sourceFilter} 수집분` : '서버별 최신 점검 기준',
        onclick: () => { $('#f-status').value = ''; render(); showView('servers'); } }),
      statCard({ ico: 'shield', tone: 'critical', label: '침해 의심', value: comp, unit: '대',
        hint: comp ? '사고 대응 우선 — [4] 침해 흔적 [위험]' : '침해 흔적 [위험] 없음', hintTone: comp ? 'up' : 'good', onclick: () => setStatusFilter('compromise') }),
      statCard({ ico: 'alert', tone: 'serious', label: '위험', value: count('risk'), unit: '대', hint: '침해 흔적 외 [위험] 항목 보유', onclick: () => setStatusFilter('risk') }),
      statCard({ ico: 'up', tone: 'warning', label: `최신(${latestVer()}) 미만`, value: below, unit: '대',
        hint: eol ? `이 중 javax 계열(26 이하) ${eol}대` : (n ? `${n - below}대 최신 버전` : '업그레이드 대상') }),
      statCard({ ico: 'bug', tone: 'serious', label: 'CVE 해당', value: unpatched, unit: '대', hint: '설치된 구성요소(jar) 버전이 OSV 영향 구간' }),
      statCard({ ico: 'data', tone: 'warning', label: '데이터 경고', value: dq, unit: '대', hint: dq ? '점검 불완전 — 수동 확인 필요' : '이상 없음', hintTone: dq ? '' : 'good',
        onclick: dq ? () => { $('#f-dq').checked = true; render(); showView('servers'); } : null })
    );
    // 머리글 알림 종: 침해 의심 수 (에이전트 필터와 관계없이 전체)
    const allComp = (() => { const seen = new Set(); return state.reports.filter(r => { if (seen.has(r.instanceKey)) return false; seen.add(r.instanceKey); return r.intrusion === 'compromise'; }).length; })();
    const bell = $('#bell-count');
    bell.hidden = !allComp;
    bell.textContent = String(allComp);
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
        h('td', null, h('div', null, r.host), h('div', { class: 'sub mono' }, [r.ip ? (r.ipFromAgent ? `${r.ip}(접속 IP)` : r.ips.join(', ')) : null, r.binary, r.confArg].filter(Boolean).join(' · ')),
          h('div', { class: 'sub' }, r.source ? `에이전트 ${r.source} 수집` : '수동 업로드')),
        h('td', null, h('div', null, r.version || '확인 불가'),
          r.eol ? h('div', { class: 'sub nowrap', title: 'Java EE 8(javax) 계열 — 최신으로 올릴 때 앱의 javax → jakarta 변경 필요' }, 'javax 계열') : r.belowLatest ? h('div', { class: 'sub nowrap', title: `최신 ${latestVer()} 미만` }, '최신 미만') : r.version ? h('div', { class: 'sub' }, '최신 버전') : null),
        h('td', null, r.installType || '-'),
        h('td', { class: 'nowrap' }, r.checkedAt || '-'),
        num(r.counts.risk), num(r.counts.warn), num(r.counts.ok),
        h('td', { class: 'num' }, chips.length ? h('div', { class: 'cve-chips' }, chips) : h('span', { class: 'zero' }, '0')),
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
  /** extraLines: 툴팁에 덧붙일 줄 (문자열, 또는 {text, level, head}) */
  function hbar(name, segs, max, tipTitle, onclick, extraLines, valText) {
    const total = segs.reduce((a, s) => a + s.value, 0);
    const track = h('div', { class: 'track' });
    segs.filter(s => s.value > 0).forEach(s => {
      const seg = h('div', { class: 'seg ' + s.cls });
      seg.style.width = (s.value / max * 100) + '%';
      track.append(seg);
    });
    const row = h('div', { class: 'hbar', role: onclick ? 'button' : null, tabindex: onclick ? '0' : null, onclick },
      h('div', { class: 'name', title: name }, name), track, h('div', { class: 'val' }, valText || String(total)));
    tip(row, () => [tipTitle || name, ...segs.map(s => `${s.label}: ${s.value}`), ...(extraLines ? extraLines() : [])]);
    return row;
  }

  function renderFindingsChart(list) {
    legend('#legend-findings', [['c-critical', '위험'], ['c-warning', '주의'], ['c-good', '양호']]);
    const rows = list.slice().sort((a, b) => b.counts.risk - a.counts.risk || b.counts.warn - a.counts.warn).slice(0, 20);
    const max = Math.max(1, ...rows.map(r => r.counts.risk + r.counts.warn + r.counts.ok));
    const el = $('#chart-findings');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '데이터 없음')); return; }
    el.replaceChildren(...rows.map(r => hbar(hostLabel(r), [
      { cls: 'c-critical', value: r.counts.risk, label: '위험' },
      { cls: 'c-warning', value: r.counts.warn, label: '주의' },
      { cls: 'c-good', value: r.counts.ok, label: '양호' }
    ], max, `${r.host} · WildFly ${r.version || '?'}`, () => openDetail(r.id))));
    if (list.length > rows.length) el.append(h('div', { class: 'none' }, `상위 ${rows.length}개만 표시 (위험 많은 순)`));
  }

  function renderCveChart(list) {
    legend('#legend-cve', [['c-critical', 'critical'], ['c-serious', 'high'], ['c-warning', 'moderate']]);
    $('#btn-cve-pdf').href = 'api/cve.pdf' + (state.sourceFilter ? '?source=' + encodeURIComponent(state.sourceFilter) : '');
    $('#chart-cve').dataset.total = list.length;
    const agg = new Map();
    list.forEach(r => r.cveList.forEach(c => {
      const a = agg.get(c.id) || { id: c.id, open: 0, bp: 0, sev: SEVERITY[c.severity] ? c.severity : 'low', desc: c.description,
        affected: c.affected, advisory: c.advisory, servers: [] };
      a.open++;
      a.servers.push({ r, condition: c.condition, affected: c.affected });
      agg.set(c.id, a);
    }));
    // CveIssues.group() 과 같은 순서: 대상 서버 수 → 등급, 서버는 호스트 이름 순
    agg.forEach(a => a.servers.sort((x, y) => x.r.host.localeCompare(y.r.host)));
    const rows = Array.from(agg.values())
      .sort((a, b) => (b.open - a.open) || SEVERITY[a.sev].rank - SEVERITY[b.sev].rank || a.id.localeCompare(b.id)).slice(0, 15);
    const el = $('#chart-cve');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '해당 CVE 없음')); return; }
    const max = Math.max(1, list.length);
    const LIMIT = 12;
    el.replaceChildren(...rows.map(a => hbar(`${a.id} · ${a.sev}`, [
      { cls: SEVERITY[a.sev].color, value: a.open, label: '대상 서버' }
    ], max, `${a.id} [${a.sev}] ${a.desc || ''}`, () => openCveItem(a), () => [
      { head: true, text: '대상 서버 (설치된 구성요소)' },
      ...a.servers.slice(0, LIMIT).map(s => ({ level: a.sev === 'critical' || a.sev === 'high' ? 'risk' : 'warn', text: `${serverLabel(s.r)} · ${(s.condition || '').replace(/ 설치됨$/, '')}` })),
      ...(a.servers.length > LIMIT ? [`외 ${a.servers.length - LIMIT}대 — 눌러서 전체 보기`] : [])
    ], `${a.open}/${list.length}대`)));
  }

  /** CVE 1건의 대상 서버 목록 창 */
  function openCveItem(a) {
    $('#cfg-title').textContent = `${a.id} [${a.sev}]`;
    $('#cfg-sub').textContent = `대상 서버 ${a.servers.length}대`;
    $('#cfg-body').replaceChildren(
      h('p', null, a.desc || ''),
      h('p', { class: 'muted' }, `영향 구간(첫 대상 서버 기준): ${a.affected || '-'} · `,
        h('a', { href: 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(a.id), target: '_blank', rel: 'noopener noreferrer' }, 'cve.org 상세'),
        a.advisory ? ' · ' : null,
        a.advisory ? h('a', { href: 'https://osv.dev/vulnerability/' + encodeURIComponent(a.advisory), target: '_blank', rel: 'noopener noreferrer' }, 'OSV 권고') : null),
      h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['판정', '서버', '설치된 구성요소', '점검 일시', '수집'].map(t => h('th', null, t)))),
        h('tbody', null, ...a.servers.map(s => h('tr', { class: 'row', tabindex: '0', onclick: () => { $('#cfg-dlg').close(); openDetail(s.r.id); } },
          h('td', null, h('span', { class: 'badge b-' + a.sev }, a.sev)),
          h('td', null, h('div', null, hostLabel(s.r)), h('div', { class: 'sub' }, `WildFly ${s.r.version || '?'}`)),
          h('td', { class: 'mono' }, (s.condition || '-').replace(/ 설치됨$/, '')),
          h('td', { class: 'nowrap' }, s.r.checkedAt || '-'),
          h('td', null, s.r.source ? `에이전트 ${s.r.source}` : '수동 업로드'))))),
      h('p', { class: 'dialog-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: () => { $('#cfg-dlg').close(); $('#f-q').value = a.id; render(); showView('servers'); } }, '이 CVE로 서버 목록 거르기'),
        h('span', { class: 'muted' }, '서버를 누르면 그 서버의 상세 결과가 열립니다. 판정은 설치 폴더의 구성요소(jar) 버전과 OSV 영향 구간 기준입니다.')));
    $('#cfg-dlg').showModal();
  }

  function renderConfigChart(list) {
    legend('#legend-config', [['c-critical', '위험'], ['c-warning', '주의']]);
    const pdf = $('#btn-config-pdf');
    pdf.href = 'api/config.pdf' + (state.sourceFilter ? '?source=' + encodeURIComponent(state.sourceFilter) : '');
    const agg = new Map();
    list.forEach(r => {
      const seen = new Set();
      r.configIssues.forEach(ci => {
        const key = ci.text.split(/ → | \(|: /)[0].trim(); // ConfigIssues.key() 와 같은 규칙
        if (seen.has(key)) return;
        seen.add(key);
        const a = agg.get(key) || { key, risk: 0, warn: 0, full: ci.text, servers: [] };
        a[ci.level]++;
        a.servers.push({ r, level: ci.level, text: ci.text });
        agg.set(key, a);
      });
    });
    agg.forEach(a => a.servers.sort((x, y) => (x.level === 'risk' ? 0 : 1) - (y.level === 'risk' ? 0 : 1) || x.r.host.localeCompare(y.r.host)));
    const rows = Array.from(agg.values()).sort((a, b) => (b.risk + b.warn) - (a.risk + a.warn) || b.risk - a.risk).slice(0, 12);
    const el = $('#chart-config');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '위험·주의 설정 없음')); return; }
    const max = Math.max(1, list.length);
    const LIMIT = 12;
    el.replaceChildren(...rows.map(a => hbar(a.key, [
      { cls: 'c-critical', value: a.risk, label: '위험 서버' },
      { cls: 'c-warning', value: a.warn, label: '주의 서버' }
    ], max, a.full, () => openConfigItem(a), () => [
      { head: true, text: '대상 서버' },
      ...a.servers.slice(0, LIMIT).map(s => ({ level: s.level, text: serverLabel(s.r) })),
      ...(a.servers.length > LIMIT ? [`외 ${a.servers.length - LIMIT}대 — 눌러서 전체 보기`] : [])
    ], `${a.risk + a.warn}/${list.length}대`)));
  }

  function serverLabel(r) {
    return `${hostLabel(r)} · WildFly ${r.version || '?'}`;
  }

  /** 설정 취약 항목 1개의 대상 서버 목록 창 (터치 화면에서도 볼 수 있게) */
  function openConfigItem(a) {
    $('#cfg-title').textContent = a.key;
    $('#cfg-sub').textContent = `대상 서버 ${a.servers.length}대 (위험 ${a.risk} · 주의 ${a.warn})`;
    $('#cfg-body').replaceChildren(
      h('p', null, a.full),
      h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['등급', '서버', '점검 일시', '수집'].map(t => h('th', null, t)))),
        h('tbody', null, ...a.servers.map(s => h('tr', { class: 'row', tabindex: '0', onclick: () => { $('#cfg-dlg').close(); openDetail(s.r.id); } },
          h('td', null, badge(s.level)),
          h('td', null, h('div', null, hostLabel(s.r)), h('div', { class: 'sub' }, `WildFly ${s.r.version || '?'}`)),
          h('td', { class: 'nowrap' }, s.r.checkedAt || '-'),
          h('td', null, s.r.source ? `에이전트 ${s.r.source}` : '수동 업로드'))))),
      h('p', { class: 'muted' }, '서버를 누르면 그 서버의 상세 결과(근거가 된 설정 줄·옵션 포함)가 열립니다.'));
    $('#cfg-dlg').showModal();
  }

  // ---------------------------------------------------------------- 툴팁
  function tip(el, lines) {
    const t = $('#tooltip');
    const show = e => {
      const [title, ...rest] = lines();
      t.replaceChildren(h('b', null, title), ...rest.map(l => typeof l === 'string' ? h('div', null, l)
        : l.head ? h('div', { class: 'tip-head' }, l.text)
          : h('div', { class: 'tip-item' }, h('span', { class: 'tip-lv tip-' + l.level }, l.label || (STATUS[l.level] ? STATUS[l.level].label : l.level)), l.text)));
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
    el.addEventListener('focus', () => {
      const b = el.getBoundingClientRect();
      show({ clientX: b.left + 40, clientY: b.bottom });
    });
    el.addEventListener('blur', () => { t.hidden = true; });
  }

  // ---------------------------------------------------------------- 상세
  let current = null;

  async function openDetail(id) {
    let r;
    try { r = await api('reports/' + encodeURIComponent(id)); } catch (e) { showAlert(e.message); return; }
    current = r;
    const dlg = $('#detail');
    $('#d-title').replaceChildren(badge(r.status), r.host, h('span', { class: 'muted' }, `WildFly ${r.version || '?'}`));
    $('#d-sub').textContent = [r.checkedAt, r.ips.length ? 'IP ' + r.ips.join(', ') + (r.ipFromAgent ? '(접속 IP)' : '') : null, r.binary, r.confArg,
      r.installType ? r.installType + ' 설치' : null, r.runMode, r.runUser ? '실행계정 ' + r.runUser : null,
      r.javaVersion ? 'Java ' + r.javaVersion.replace(/^openjdk version |"/g, '') : null, r.moduleCount !== null ? `구성요소 ${r.moduleCount}개` : null,
      `설정 ${r.confMethodShort}`, r.id].filter(Boolean).join(' · ');
    $('#d-raw').href = 'api/reports/' + encodeURIComponent(r.id) + '/raw';
    $('#d-pdf').href = 'api/reports/' + encodeURIComponent(r.id) + '/intrusion.pdf';

    $('#d-dq').replaceChildren(...(r.dataQuality.length ? [h('div', { class: 'alert warn dq' },
      h('b', null, '데이터 품질 경고 — 아래 결과를 그대로 믿기 전에 확인하세요'), ...r.dataQuality.map(d => h('div', null, '· ' + d)))] : []),
      ...(r.compromise ? [h('div', { class: 'alert' }, h('b', null, '침해 의심: '), '[4] 침해 흔적 점검에 [위험] 항목이 있습니다. 설정 보완·패치보다 침해사고 대응(격리·증거 보존·분석)이 우선입니다.')] : []));

    const un = Object.values(r.cveUnpatched).reduce((a, b) => a + b, 0);
    const ap = r.cves.filter(c => c.applicable).length;
    $('#d-kpis').replaceChildren(
      kpi('', r.counts.risk, '건', null, 'risk'),
      kpi('', r.counts.warn, '건', null, 'warn'),
      kpi('', r.counts.ok, '건', null, 'ok'),
      kpi('해당 CVE', ap, '건', `critical ${r.cveApplicable.critical || 0} · high ${r.cveApplicable.high || 0}`),
      kpi('미해당 CVE', r.cves.length - ap, '건', '구성요소 없음/다른 프로젝트')
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
      panel.replaceChildren(h('p', { class: 'muted' }, 'CVE 판정 결과가 없습니다. (스크립트의 CVE 목록 기준으로 해당 없음)'));
      return;
    }
    panel.replaceChildren(
      h('p', { class: 'muted' }, '판정은 이 서버 설치 폴더(modules)의 실제 구성요소(jar) 버전을 OSV 취약점 DB 의 영향 구간과 비교한 결과입니다. 설명은 OSV 원문(영문)입니다. '
        + '해당 기능(AJP·OIDC·HTTP/2 등)을 쓰지 않으면 실제 악용 가능성은 낮을 수 있습니다.'),
      h('div', { class: 'table-scroll' }, h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['판정', 'CVE', '등급', '설명', '영향 구간', '설치된 구성요소'].map(t => h('th', null, t)))),
        h('tbody', null, ...rows.map(c => h('tr', null,
          h('td', null, !c.applicable ? h('span', { class: 'badge b-skip' }, '미해당') : badge(c.severity === 'critical' || c.severity === 'high' ? 'risk' : 'warn', '해당')),
          h('td', { class: 'mono nowrap' }, h('a', { href: 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(c.id), target: '_blank', rel: 'noopener noreferrer' }, c.id),
            c.advisory ? h('div', { class: 'sub' }, h('a', { href: 'https://osv.dev/vulnerability/' + encodeURIComponent(c.advisory), target: '_blank', rel: 'noopener noreferrer' }, c.advisory)) : null),
          h('td', null, sevBadge(c.severity)),
          h('td', null, c.description || h('span', { class: 'muted' }, '(미해당 항목은 리포트에 설명 없음 — 필요한 구성요소가 없거나 같은 이름의 다른 프로젝트)')),
          h('td', { class: 'mono' }, c.affected || '-'),
          h('td', { class: 'mono' }, c.applicable ? (c.condition || '-').replace(/ 설치됨$/, '') : '없음: ' + (c.condition || '-')))))))
    );
  }

  function renderHistory(r) {
    const panel = $('[data-panel="history"]');
    const same = state.reports.filter(x => x.instanceKey === r.instanceKey);
    panel.replaceChildren(
      h('p', { class: 'muted' }, '같은 호스트·실행파일·설정 파일(-f)의 점검 기록입니다. 재시작해도 같은 서버로 묶입니다. 패치 전/후 비교에 사용하세요.'),
      h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['점검 일시', '판정', '버전', '위험', '주의', '양호', '해당 CVE', '파일'].map(t => h('th', null, t)))),
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

  // ---------------------------------------------------------------- 최신 버전 / 사이드바 / 침해 의심
  function latestVer() {
    return state.latest ? state.latest.version : '?';
  }

  function versionCell(a) {
    if (!a.wildflyVersion) return h('span', { class: 'zero' }, '미확인');
    return h('span', null, a.wildflyVersion, ' ',
      a.upToDate ? h('span', { class: 'badge b-ok' }, '최신') : h('span', { class: 'badge b-warn' }, '최신 미만'));
  }

  async function loadLatest() {
    try { state.latest = await api('latest-version'); } catch (e) { return; }
    const l = state.latest;
    $('#latest-ver').textContent = l.version;
    $('#latest-ver-pill').textContent = l.version;
    $('#brand-sub').textContent = `WildFly 최신 Final ${l.version} 기준 · wildfly_precheck.sh 결과`;
    const host = (() => { try { return new URL(l.source).host; } catch (e) { return l.source; } })();
    let origin;
    if (l.origin === 'manual') origin = '관리자가 직접 지정한 값';
    else if (l.origin === 'auto') origin = `자동 확인 · ${host} · ${rel(l.autoSuccessAt)}`;
    else origin = '자동 확인 전/실패 → 점검 스크립트 기준값 사용';
    $('#latest-origin').textContent = origin;
    $('#latest-origin').title = l.autoCheckedAt ? `마지막 확인 시도: ${abs(l.autoCheckedAt)}` : '';
    const warns = [];
    if (l.autoError && l.origin !== 'manual') {
      warns.push(h('div', { class: 'side-warn' }, `자동 확인 실패: ${l.autoError}`,
        h('div', { class: 'muted' }, '내부망이라 인터넷이 막혀 있으면 [직접 지정]으로 버전을 넣으세요.')));
    }
    if (l.newerThanScript) {
      warns.push(h('div', { class: 'side-warn' },
        `점검 스크립트의 CVE 목록은 ${l.scriptBaseline} 기준입니다. ${l.scriptBaseline} 이후 공개된 취약점은 판정되지 않으니 스크립트 업데이트가 필요합니다.`));
    }
    $('#latest-warn').replaceChildren(...warns);
    $('#btn-latest-auto').hidden = l.mode !== 'manual';
    $('#latest-skip').checked = !!l.skipUpToDate;
  }

  async function latestAction(params) {
    try { state.latest = await api('latest-version', { method: 'POST', body: new URLSearchParams(params) }); }
    catch (e) { alert(e.message); }
    await refreshAll();
  }

  /** 에이전트별 최신 리포트 (source 기준) */
  function latestReportOf(agentName) {
    return state.reports.find(r => r.source === agentName); // reports 는 최신순
  }

  function renderSideAgents() {
    const ul = $('#side-agents');
    if (!state.agents) return;
    const list = state.agents.agents;
    const now = state.agents.now;
    $('#side-agents-count').textContent = list.length ? `${list.length}대` : '';
    if (!list.length) {
      ul.replaceChildren(h('li', { class: 'side-empty' }, state.me.admin ? '등록된 에이전트가 없습니다. [에이전트 관리]에서 추가하세요.' : '등록된 에이전트가 없습니다.'));
      return;
    }
    // 침해 의심 → 문제 상태 → 다음 점검이 빠른 순
    const order = { offline: 0, running: 1, requested: 2, online: 3, never: 4 };
    const nextAt = a => a.intervalHours === 0 || a.autoSkipped ? Infinity : (a.nextRunAt || 0);
    const sorted = list.slice().sort((a, b) => {
      const ra = latestReportOf(a.name), rb = latestReportOf(b.name);
      const ca = ra && ra.intrusion === 'compromise' ? 0 : 1, cb = rb && rb.intrusion === 'compromise' ? 0 : 1;
      return ca - cb || (order[a.state] ?? 9) - (order[b.state] ?? 9) || nextAt(a) - nextAt(b) || a.name.localeCompare(b.name);
    });
    ul.replaceChildren(...sorted.map(a => {
      const st = AGENT_STATE[a.state] || AGENT_STATE.never;
      const rep = latestReportOf(a.name);
      const selected = state.sourceFilter === a.name;
      let when;
      if (a.state === 'running') when = '점검 중';
      else if (a.state === 'requested') when = '곧 시작';
      else if (a.intervalHours === 0) when = '수동';
      else if (a.autoSkipped) when = '제외';
      else if (!a.lastReportAt) when = '설치 후';
      else when = new Date(a.nextRunAt).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false });
      const meta = [a.hostname, a.ip].filter(Boolean).join(' · ') || '아직 접속 안 함';
      return h('li', null, h('button', {
        class: 'sched-item' + (selected ? ' selected' : ''), type: 'button', 'aria-pressed': String(selected),
        title: `다음 자동 점검: ${a.intervalHours === 0 ? '수동만' : a.autoSkipped ? '최신 버전이라 제외' : a.lastReportAt ? abs(a.nextRunAt) + ' (' + rel(a.nextRunAt, now) + ')' : '설치 후 바로'}\n누르면 이 에이전트 결과만 표시`,
        onclick: () => { state.sourceFilter = selected ? null : a.name; render(); renderSideAgents(); }
      },
        h('span', { class: 'sched-time' }, when),
        h('span', { class: 'sched-ico' }, icon('server')),
        h('span', { class: 'sched-name' }, a.name,
          h('span', { class: 'sched-meta' }, meta + (a.wildflyVersion ? ` · WildFly ${a.wildflyVersion}` : '') + (rep ? ` · 점검 ${rel(rep.fileModified, now)}` : ''))),
        rep && rep.intrusion === 'compromise' ? badge('compromise')
          : h('span', { class: 'badge ' + st.cls }, h('span', { class: 'ic', 'aria-hidden': 'true' }, st.icon), st.label)));
    }));
  }

  /** 인스턴스별 최신 리포트 중 [4] 침해 흔적에 위험/주의가 있는 것 */
  function renderSuspects() {
    const seen = new Set();
    const latest = state.reports.filter(r => { if (seen.has(r.instanceKey)) return false; seen.add(r.instanceKey); return true; });
    const comp = latest.filter(r => r.intrusion === 'compromise');
    const check = latest.filter(r => r.intrusion === 'check');
    $('#btn-suspects-pdf').hidden = comp.length === 0;
    const last = state.reports[0];
    $('#intrusion-status').className = 'istatus ' + (comp.length ? 'bad' : 'ok');
    $('#intrusion-status').replaceChildren(
      h('div', { class: 'i-ico' }, icon(comp.length ? 'shield' : 'activity')),
      h('div', null,
        h('div', { class: 'i-main' }, comp.length ? `침해 의심 ${comp.length}대` : (state.reports.length ? '안정' : '점검 전')),
        h('div', { class: 'i-sub' }, `확인 필요 ${check.length}대 · 서버 ${latest.length}대 기준` + (last ? ` · 마지막 수신 ${rel(last.fileModified)}` : ''))));
    renderIntrusionArea();
    const row = r => h('div', { class: 'suspect' },
      h('div', { class: 'suspect-main' },
        h('div', { class: 'suspect-title' }, badge(r.intrusion === 'compromise' ? 'compromise' : 'warn', r.intrusion === 'compromise' ? '침해 의심' : '확인 필요'),
          h('b', null, r.host), r.ip ? h('span', { class: 'muted mono' }, r.ip + (r.ipFromAgent ? '(접속 IP)' : '')) : null,
          h('span', { class: 'muted' }, `WildFly ${r.version || '?'}`), h('span', { class: 'muted' }, r.checkedAt || ''),
          h('span', { class: 'muted' }, r.source ? `에이전트 ${r.source}` : '수동 업로드')),
        h('ul', { class: 'suspect-findings' }, ...r.intrusionFindings.slice(0, 3).map(f => h('li', null, badge(f.level), ' ', f.text)),
          r.intrusionFindings.length > 3 ? h('li', { class: 'muted' }, `외 ${r.intrusionFindings.length - 3}건`) : null)),
      h('div', { class: 'suspect-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: () => openDetail(r.id) }, '상세'),
        h('a', { class: 'btn small' + (r.intrusion === 'compromise' ? ' btn-danger' : ''), href: 'api/reports/' + encodeURIComponent(r.id) + '/intrusion.pdf', download: '' }, 'PDF')));
    const out = [];
    if (!comp.length) out.push(h('p', { class: 'muted none-msg' }, state.reports.length ? '침해 의심 서버가 없습니다. (서버별 최신 점검 기준)' : '점검 결과가 아직 없습니다.'));
    out.push(...comp.map(row));
    if (check.length) {
      out.push(h('details', { class: 'check-group' }, h('summary', null, `확인 필요 ${check.length}대 — [4]에 [주의] 항목(스캔 시도, 최근 변경 파일 등)`), ...check.map(row)));
    }
    $('#suspects').replaceChildren(...out);
  }

  // ---------------------------------------------------------------- 에이전트
  const AGENT_STATE = {
    online: { label: '온라인', cls: 'b-ok', icon: '✔' },
    running: { label: '점검 중', cls: 'b-running', icon: '↻' },
    requested: { label: '점검 요청됨', cls: 'b-warn', icon: '◆' },
    offline: { label: '오프라인', cls: 'b-risk', icon: '✖' },
    never: { label: '설치 대기', cls: 'b-info', icon: '…' }
  };
  const INTERVALS = [[24, '24시간'], [12, '12시간'], [6, '6시간'], [72, '3일'], [168, '7일'], [0, '수동만']];

  function rel(ms, now) {
    if (!ms) return '-';
    const d = Math.round(((now || Date.now()) - ms) / 1000);
    if (d < 0) { const f = -d; return f < 3600 ? `${Math.ceil(f / 60)}분 후` : f < 86400 ? `${Math.round(f / 3600)}시간 후` : `${Math.round(f / 86400)}일 후`; }
    if (d < 60) return '방금';
    if (d < 3600) return `${Math.floor(d / 60)}분 전`;
    if (d < 86400) return `${Math.floor(d / 3600)}시간 전`;
    return `${Math.floor(d / 86400)}일 전`;
  }
  function abs(ms) { return ms ? new Date(ms).toLocaleString('ko-KR') : ''; }

  async function loadAgents() {
    let data;
    try { data = await api('agents'); } catch (e) { $('#agents tbody').replaceChildren(h('tr', null, h('td', { colspan: '9', class: 'muted' }, '에이전트 목록을 불러오지 못했습니다: ' + e.message))); return; }
    state.agents = data;
    const now = data.now;
    const count = {};
    data.agents.forEach(a => { count[a.state] = (count[a.state] || 0) + 1; });
    $('#agents-summary').textContent = data.agents.length
      ? Object.entries(AGENT_STATE).filter(([k]) => count[k]).map(([k, v]) => `${v.label} ${count[k]}`).join(' · ')
      : '';
    const rows = data.agents.map(a => {
      const st = AGENT_STATE[a.state] || AGENT_STATE.never;
      const next = a.intervalHours === 0 ? '수동만' : a.lastReportAt ? rel(a.nextRunAt, now) : '설치 후 바로';
      const scriptCell = a.scriptMatches === null || a.scriptMatches === undefined ? h('span', { class: 'zero' }, '-')
        : a.scriptMatches ? h('span', { class: 'badge b-ok' }, '대시보드와 같음')
          : h('span', { class: 'badge b-warn', title: `에이전트: ${a.scriptSha256}\n대시보드: ${data.expectedScriptSha256}` }, h('span', { class: 'ic' }, '!'), '다름');
      const lastRun = a.lastRunAt
        ? h('div', null, h('span', { title: abs(a.lastRunAt) }, rel(a.lastRunAt, now)), ' ',
          a.lastExit === 0 || (a.lastReportCount > 0 && a.lastExit !== 124) ? null : h('span', { class: 'badge b-risk' }, `실패(exit ${a.lastExit})`),
          a.lastMessage ? h('div', { class: 'msg' }, a.lastMessage) : null)
        : h('span', { class: 'zero' }, '아직 없음');
      const actions = h('td', { class: 'admin-only' }, h('div', { class: 'row-actions' },
        h('button', { class: 'btn small', type: 'button', disabled: a.state === 'running' || a.state === 'requested' || null, onclick: () => agentRun(a.name) }, '지금 점검'),
        h('select', { 'aria-label': `${a.name} 점검 주기`, onchange: e => agentInterval(a.name, e.target.value) },
          ...INTERVALS.map(([v, l]) => h('option', { value: String(v), selected: v === a.intervalHours || null }, l))),
        h('button', { class: 'btn small', type: 'button', onclick: () => agentToken(a.name) }, '토큰 재발급'),
        h('button', { class: 'btn small btn-danger', type: 'button', onclick: () => agentDelete(a.name) }, '삭제')));
      return h('tr', null,
        h('td', null, h('span', { class: 'badge ' + st.cls }, h('span', { class: 'ic', 'aria-hidden': 'true' }, st.icon), st.label)),
        h('td', null, h('div', null, a.name), h('div', { class: 'sub mono' }, [a.hostname, a.ip].filter(Boolean).join(' · ') || '아직 접속 안 함')),
        h('td', { title: abs(a.lastSeen) }, rel(a.lastSeen, now)),
        h('td', null, lastRun),
        h('td', null, versionCell(a)),
        h('td', null, a.autoSkipped && a.intervalHours > 0 ? h('span', { class: 'muted', title: '최신 버전이라 자동 점검 제외 (지금 점검은 가능)' }, '제외(최신)') : next),
        h('td', null, (INTERVALS.find(([v]) => v === a.intervalHours) || [0, `${a.intervalHours}시간`])[1]),
        h('td', null, scriptCell),
        actions);
    });
    if (!rows.length) rows.push(h('tr', null, h('td', { colspan: '9', class: 'muted' },
      state.me.admin ? '등록된 에이전트가 없습니다. [에이전트 추가]로 WildFly 서버에 에이전트를 설치하세요.' : '등록된 에이전트가 없습니다.')));
    $('#agents tbody').replaceChildren(...rows);
    renderSideAgents();
    renderAgentTiles();
  }

  function dashboardUrl() {
    return new URL('.', location.href).href.replace(/\/$/, '');
  }

  function codeBox(text) {
    const pre = h('pre', { class: 'mono' }, text);
    const btn = h('button', { class: 'btn small', type: 'button' }, '복사');
    btn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); btn.textContent = '복사됨'; }
      catch (e) { // http 접속 등으로 클립보드 API 를 못 쓰면 텍스트를 선택해 줌
        const r = document.createRange(); r.selectNodeContents(pre);
        const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
        btn.textContent = 'Ctrl+C 로 복사';
      }
    });
    return h('div', { class: 'codebox' }, pre, btn);
  }

  function showInstall(name, token, rotated) {
    const url = dashboardUrl();
    const box = $('#agent-install');
    box.replaceChildren(
      h('div', { class: 'alert info' }, h('b', null, rotated ? `${name} 토큰을 재발급했습니다. ` : `${name} 에이전트를 등록했습니다. `),
        '토큰은 이 창을 닫으면 다시 볼 수 없습니다. (잃어버리면 [토큰 재발급])'),
      h('ol', { class: 'steps' },
        rotated
          ? h('li', null, h('p', null, 'WildFly 서버에서 아래 명령으로 설정 파일의 토큰만 바꿉니다. (또는 아래 2~3단계로 다시 설치)'),
            codeBox(`sudo sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN='${token}'|" /etc/wfprecheck-agent.conf && sudo /opt/wfprecheck-agent/wfprecheck-agent.sh test`))
          : null,
        h('li', null, h('p', null, '점검할 WildFly 서버에 root 권한이 있는 계정으로 접속해 설치 파일을 받습니다.'),
          codeBox(`curl -fsSo /tmp/wfprecheck-install.sh ${url}/agent-api/files/install.sh`)),
        h('li', null, h('p', null, '설치를 실행합니다. 토큰을 물어보면 아래 3번의 토큰을 붙여 넣고 Enter 를 누릅니다.'),
          codeBox(`sudo bash /tmp/wfprecheck-install.sh ${url} ${name}`)),
        h('li', null, h('p', null, '에이전트 토큰'), codeBox(token)),
        h('li', null, h('p', null, '"설치 완료"가 나오면 1~2분 안에 이 화면의 상태가 "온라인"이 되고, 첫 점검이 자동으로 시작됩니다.'))),
      h('p', { class: 'muted' }, `※ WildFly 서버에서 ${url} 로 접속할 수 있어야 합니다(방화벽 확인). 서버에서 보이는 주소가 다르면 명령의 주소를 바꿔서 실행하세요. `
        + '인터넷이 안 되는 서버는 wfprecheck-agent.sh, wildfly_precheck.sh, install.sh 세 파일을 같은 폴더에 복사한 뒤 그 폴더에서 install.sh 를 실행하면 됩니다.'));
    box.hidden = false;
  }

  async function agentRun(name) {
    try { await api('agents/' + encodeURIComponent(name) + '/run', { method: 'POST' }); await loadAgents(); }
    catch (e) { alert(e.message); }
  }
  async function agentInterval(name, hours) {
    try { await api('agents/' + encodeURIComponent(name) + '/interval', { method: 'POST', body: new URLSearchParams({ hours }) }); await loadAgents(); }
    catch (e) { alert(e.message); }
  }
  async function agentToken(name) {
    if (!confirm(`${name} 토큰을 재발급할까요? 기존 토큰은 바로 사용할 수 없게 되어, WildFly 서버의 설정을 바꾸기 전까지 에이전트가 접속하지 못합니다.`)) return;
    try {
      const r = await api('agents/' + encodeURIComponent(name) + '/token', { method: 'POST' });
      $('#ag-title').textContent = '토큰 재발급';
      $('#agent-form').hidden = true;
      showInstall(r.name, r.token, true);
      $('#agent-dlg').showModal();
    } catch (e) { alert(e.message); }
  }
  async function agentDelete(name) {
    if (!confirm(`${name} 에이전트를 삭제할까요? 이미 받은 리포트는 남습니다. WildFly 서버의 에이전트는 'sudo bash /tmp/wfprecheck-install.sh --uninstall' 로 따로 삭제하세요.`)) return;
    try { await api('agents/' + encodeURIComponent(name), { method: 'DELETE' }); await loadAgents(); }
    catch (e) { alert(e.message); }
  }

  // ---------------------------------------------------------------- 화면 전환 · 시계
  const VIEWS = ['overview', 'servers', 'agents', 'settings'];
  function showView(name, fromHash) {
    if (!VIEWS.includes(name)) name = 'overview';
    $$('section.view').forEach(v => { v.hidden = v.dataset.view !== name; });
    $$('.rail-btn, .tab-btn').forEach(b => {
      if (b.dataset.view === name) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    $('#tooltip').hidden = true;
    if (!fromHash && location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
    if (!fromHash) window.scrollTo({ top: 0 });
  }

  function tickClock() {
    const d = new Date();
    $('#clock-date').textContent = d.toLocaleDateString('ko-KR', { month: 'long', day: 'numeric', weekday: 'short' });
    $('#clock-time').textContent = d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false });
  }

  /** 최근 n일 날짜 키 (YYYY-MM-DD, 오래된 날 → 오늘) */
  function dayKeys(n) {
    const out = [];
    const d = new Date();
    for (let i = n - 1; i >= 0; i--) {
      const x = new Date(d.getFullYear(), d.getMonth(), d.getDate() - i);
      out.push(`${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`);
    }
    return out;
  }
  function reportsInScope() {
    return state.reports.filter(r => !state.sourceFilter || r.source === state.sourceFilter);
  }

  // ---------------------------------------------------------------- 서버 배치도 (등각 투영)
  function renderHeroMap(list) {
    const box = $('#hero-map');
    legend('#legend-hero', [['c-critical', '침해 의심'], ['c-serious', '위험'], ['c-warning', '주의'], ['c-good', '양호']]);
    const MAX = 24;
    const items = list.slice().sort((a, b) => STATUS[a.status].rank - STATUS[b.status].rank || a.host.localeCompare(b.host)).slice(0, MAX);
    const n = items.length;
    const cols = Math.max(2, Math.ceil(Math.sqrt(n || 1)));
    const rows = Math.max(2, Math.ceil((n || 1) / cols));
    const W = 132, H = 66;                       // 바닥 칸 하나의 폭·높이 (2:1 등각)
    const SP = 2.3;                              // 서버 사이 간격 (칸 단위). 뒤 서버 이름표(3줄)가 대각선 앞 상자 윗면과 겹치지 않는 값
    const P = (gx, gy) => [(gx - gy) * W / 2, (gx + gy) * H / 2];
    const pts = a => a.map(p => p.join(',')).join(' ');
    const agentsByName = new Map(((state.agents && state.agents.agents) || []).map(a => [a.name, a]));

    // 바닥판: 서버 칸 + 뒤쪽에 대시보드 자리
    const g0 = -2.3, gx1 = (cols - 1) * SP + 0.9, gy1 = (rows - 1) * SP + 0.9;
    const floor = [P(g0, g0), P(gx1, g0), P(gx1, gy1), P(g0, gy1)];
    const T = 14; // 바닥판 두께
    const els = [];
    const defs = svg('defs', null,
      svg('linearGradient', { id: 'hubTop', x1: '0', y1: '0', x2: '1', y2: '1' },
        svg('stop', { offset: '0', 'stop-color': '#60a5fa' }), svg('stop', { offset: '1', 'stop-color': '#22d3ee' })),
      svg('filter', { id: 'isoGlow', x: '-50%', y: '-50%', width: '200%', height: '200%' },
        svg('feGaussianBlur', { stdDeviation: '5', result: 'b' }),
        svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))));
    els.push(defs);
    els.push(svg('polygon', { class: 'iso-edge', points: pts([floor[3], floor[2], [floor[2][0], floor[2][1] + T], [floor[3][0], floor[3][1] + T]]) }));
    els.push(svg('polygon', { class: 'iso-edge', points: pts([floor[2], floor[1], [floor[1][0], floor[1][1] + T], [floor[2][0], floor[2][1] + T]]) }));
    els.push(svg('polygon', { class: 'iso-floor', points: pts(floor) }));
    for (let x = Math.ceil(g0); x <= gx1; x++) els.push(svg('line', { class: 'iso-grid', x1: P(x, g0)[0], y1: P(x, g0)[1], x2: P(x, gy1)[0], y2: P(x, gy1)[1] }));
    for (let y = Math.ceil(g0); y <= gy1; y++) els.push(svg('line', { class: 'iso-grid', x1: P(g0, y)[0], y1: P(g0, y)[1], x2: P(gx1, y)[0], y2: P(gx1, y)[1] }));

    // 등각 상자 (서버 랙 모양): 바닥 중심 c, 반폭 w·반높이 h, 높이 z
    function cube(c, w, h, z, topFill, slots) { // 옆면 색은 CSS(--rack-l/r, --hub-l/r)가 화면 모드별로 지정
      const [x, y] = c;
      const top = [[x, y - z - h], [x + w, y - z], [x, y - z + h], [x - w, y - z]];
      const left = [[x - w, y - z], [x, y - z + h], [x, y + h], [x - w, y]];
      const right = [[x, y - z + h], [x + w, y - z], [x + w, y], [x, y + h]];
      const g = [svg('polygon', { class: 'left', points: pts(left) }),
        svg('polygon', { class: 'right', points: pts(right) })];
      for (let i = 1; i <= slots; i++) { // 랙 칸 선 + 표시등
        const t = i / (slots + 1);
        const ly = y - z + h + (z) * t, ry = y - z + (z) * t;
        g.push(svg('line', { class: 'slot', x1: x - w + 4, y1: ly - h + 2 - (h - 2) * 0, x2: x - 3, y2: ly + 0 - 1 }));
        g.push(svg('line', { class: 'slot', x1: x + 3, y1: ly - 1, x2: x + w - 4, y2: ry + 2 }));
      }
      g.push(svg('polygon', { class: 'top', points: pts(top), fill: topFill, filter: topFill.startsWith('url') ? null : 'url(#isoGlow)' }));
      return g;
    }

    // 대시보드(허브) 위치와 연결선
    const hub = P(-1.45, -1.45);
    const cells = items.map((r, i) => ({ r, c: P((i % cols) * SP, Math.floor(i / cols) * SP) }));
    const labels = []; // 이름표는 상자에 가리지 않도록 맨 위 층에 따로 그림
    cells.forEach(({ r, c }) => {
      if (!r.source) return;
      const ag = agentsByName.get(r.source);
      els.push(svg('path', { class: 'iso-link' + (ag && ag.state !== 'offline' && ag.state !== 'never' ? ' live' : ''),
        d: `M${hub[0]},${hub[1] - 20} Q${(hub[0] + c[0]) / 2},${Math.min(hub[1], c[1]) - 50} ${c[0]},${c[1] - 40}` }));
    });
    const hubG = svg('g', { class: 'iso-box iso-hub', 'aria-hidden': 'true' }, cube(hub, W * 0.42, H * 0.42, 34, 'url(#hubTop)', 2));
    els.push(hubG);
    labels.push(svg('text', { class: 'iso-label', x: hub[0], y: hub[1] - 34 - H * 0.42 - 12 }, '점검 대시보드'));

    // 서버 상자: 뒤 → 앞 순서로 그려야 겹침이 자연스러움 (이미 행·열 순)
    cells.forEach(({ r, c }) => {
      const tone = TONE[r.status] || TONE.none;
      const g = svg('g', { class: 'iso-box', tabindex: '0', role: 'button', 'aria-label': `${r.host} ${STATUS[r.status].label}, 상세 보기`,
        onclick: () => openDetail(r.id), onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetail(r.id); } } });
      if (r.status === 'compromise') g.append(svg('ellipse', { class: 'iso-ring', cx: c[0], cy: c[1], rx: W * 0.42, ry: H * 0.42 }));
      cube(c, W * 0.3, H * 0.3, 52, tone, 3).forEach(x => g.append(x));
      // 앞면 표시등 (상태색)
      g.append(svg('circle', { class: 'led', cx: c[0] + W * 0.21, cy: c[1] - 12, r: 2.6, fill: tone }));
      g.append(svg('circle', { class: 'led', cx: c[0] + W * 0.21, cy: c[1] - 30, r: 2.6, fill: tone }));
      labels.push(svg('text', { class: 'iso-label', x: c[0], y: c[1] + H * 0.3 + 18 }, r.host.length > 16 ? r.host.slice(0, 15) + '…' : r.host));
      // 이름표 3줄: 호스트 / 서버 IP / WildFly 버전 (SP=2.0 이면 셋째 줄까지 대각선 앞 상자와 겹치지 않음)
      labels.push(svg('text', { class: 'iso-sub', x: c[0], y: c[1] + H * 0.3 + 31 }, r.ip ? r.ip + (r.ipFromAgent ? ' (접속 IP)' : '') : 'IP 미확인'));
      labels.push(svg('text', { class: 'iso-sub', x: c[0], y: c[1] + H * 0.3 + 44 }, r.version ? 'WildFly ' + r.version.replace(/\.Final$/, '') : '버전 미확인'));
      tip(g, () => [hostLabel(r), { level: r.status === 'compromise' ? 'compromise' : r.status, text: `WildFly ${r.version || '?'}${r.belowLatest ? ' (최신 미만)' : ''}` },
        `점검 ${r.checkedAt || '-'} · ${r.source ? '에이전트 ' + r.source : '수동 업로드'}`,
        `위험 ${r.counts.risk} · 주의 ${r.counts.warn} · 해당 CVE ${cveTotal(r)}`,
        ...r.intrusionFindings.slice(0, 2).map(f => ({ level: f.level, text: f.text }))]);
      els.push(g);
    });
    els.push(svg('g', { class: 'iso-labels', 'pointer-events': 'none' }, labels));
    if (!n) {
      const mid = P((cols - 1) * SP / 2, (rows - 1) * SP / 2);
      els.push(svg('text', { class: 'iso-empty', x: mid[0], y: mid[1] }, state.reports.length ? '조건에 맞는 서버가 없습니다' : '점검 결과가 아직 없습니다'));
    }
    if (list.length > MAX) {
      const p = P(gx1, gy1);
      els.push(svg('text', { class: 'iso-sub', x: p[0], y: p[1] + T + 18 }, `위험도 높은 순 ${MAX}대만 표시 (전체 ${list.length}대)`));
    }

    // 보이는 범위에 맞춰 viewBox 계산
    const xs = [floor[0][0], floor[1][0], floor[2][0], floor[3][0]];
    const ys = [Math.min(floor[0][1] - 40, hub[1] - 34 - H * 0.42 - 30), floor[2][1] + T + 30];
    const minX = Math.min(...xs) - 20, maxX = Math.max(...xs) + 20;
    box.replaceChildren(svg('svg', { viewBox: `${minX} ${ys[0]} ${maxX - minX} ${ys[1] - ys[0]}`, role: 'img',
      'aria-label': `서버 배치도: 서버 ${n}대` }, els));
  }

  // ---------------------------------------------------------------- 일자별 점검 건수 (막대)
  function renderTrend() {
    const days = dayKeys(14);
    const rs = reportsInScope();
    const cnt = days.map(d => rs.filter(r => (r.checkedAt || '').startsWith(d)).length);
    const comp = days.map(d => rs.filter(r => (r.checkedAt || '').startsWith(d) && r.intrusion === 'compromise').length);
    const Wd = 360, Ht = 170, L = 24, B = 22, Tp = 14;
    const max = Math.max(1, ...cnt);
    const slot = (Wd - L) / days.length, bw = Math.max(4, slot * 0.5);
    const y = v => Tp + (Ht - Tp - B) * (1 - v / max);
    const els = [svg('defs', null,
      svg('linearGradient', { id: 'barGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
        svg('stop', { offset: '0', 'stop-color': '#22d3ee' }), svg('stop', { offset: '1', 'stop-color': '#2563eb', 'stop-opacity': '0.55' })),
      svg('linearGradient', { id: 'barGradHi', x1: '0', y1: '0', x2: '0', y2: '1' },
        svg('stop', { offset: '0', 'stop-color': '#a5f3fc' }), svg('stop', { offset: '1', 'stop-color': '#38bdf8' })))];
    [0, 0.5, 1].forEach(t => {
      const v = Math.round(max * t);
      els.push(svg('line', { class: 'gridline', x1: L, x2: Wd, y1: y(v), y2: y(v) }));
      els.push(svg('text', { class: 'axis-label', x: L - 6, y: y(v) + 3, 'text-anchor': 'end' }, String(v)));
    });
    const maxIdx = cnt.indexOf(Math.max(...cnt));
    days.forEach((d, i) => {
      const x = L + slot * i + (slot - bw) / 2;
      const top = y(cnt[i]), base = Ht - B;
      const r = Math.min(4, bw / 2, base - top);
      const hit = svg('rect', { class: 'bar-hit', x: L + slot * i, y: Tp, width: slot, height: Ht - Tp - B });
      const bar = cnt[i] ? svg('path', { class: 'bar', d: `M${x},${base} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${base} Z` })
        : svg('rect', { class: 'bar', x, y: base - 1, width: bw, height: 1, opacity: '0.4' });
      els.push(hit, bar);
      tip(hit, () => [`${d.slice(5).replace('-', '/')} 점검 ${cnt[i]}건`, ...(comp[i] ? [{ level: 'compromise', label: '침해 의심', text: `${comp[i]}건` }] : [])]);
      if (i % 3 === 1 || i === days.length - 1) els.push(svg('text', { class: 'axis-label', x: L + slot * i + slot / 2, y: Ht - 6, 'text-anchor': 'middle' }, d.slice(5).replace('-', '/')));
      if (i === maxIdx && cnt[i]) els.push(svg('text', { class: 'axis-label axis-strong', x: x + bw / 2, y: top - 4, 'text-anchor': 'middle' }, String(cnt[i])));
    });
    $('#trend-bars').replaceChildren(svg('svg', { viewBox: `0 0 ${Wd} ${Ht}`, role: 'img', 'aria-label': `최근 14일 점검 ${cnt.reduce((a, b) => a + b, 0)}건` }, els));
  }

  // ---------------------------------------------------------------- 도넛
  /** segs: [{value, color, label, key}] / center: [큰 글자, 작은 글자] */
  function donut(segs, center, gradientId) {
    const R = 48, C = 2 * Math.PI * R, total = segs.reduce((a, s) => a + s.value, 0);
    const els = [svg('circle', { class: 'donut-track', cx: 60, cy: 60, r: R, 'stroke-width': 12, fill: 'none' })];
    if (gradientId) {
      els.push(svg('defs', null, svg('linearGradient', { id: gradientId, x1: '0', y1: '0', x2: '1', y2: '1' },
        svg('stop', { offset: '0', 'stop-color': '#22d3ee' }), svg('stop', { offset: '1', 'stop-color': '#3b82f6' }))));
    }
    let off = 0;
    const gap = segs.filter(s => s.value > 0).length > 1 ? 2 : 0;
    segs.forEach(s => {
      if (!s.value || !total) return;
      const len = C * s.value / total;
      els.push(svg('circle', { cx: 60, cy: 60, r: R, fill: 'none', stroke: s.color, 'stroke-width': 12,
        'stroke-dasharray': `${Math.max(0, len - gap)} ${C}`, 'stroke-dashoffset': -off, transform: 'rotate(-90 60 60)' }));
      off += len;
    });
    els.push(svg('text', { class: 'donut-num', x: 60, y: 62 }, center[0]));
    els.push(svg('text', { class: 'donut-cap', x: 60, y: 80 }, center[1]));
    return svg('svg', { viewBox: '0 0 120 120', role: 'img', 'aria-label': `${center[1]} ${center[0]}` }, els);
  }

  function renderLatestDonut(list) {
    const known = list.filter(r => r.version);
    const up = known.filter(r => !r.belowLatest && !r.eol).length;
    const eol = known.filter(r => r.eol).length;
    const below = known.length - up - eol;
    const pct = known.length ? Math.round(up / known.length * 100) : 0;
    const seg = [{ value: up, color: 'url(#latestGrad)' }, { value: below, color: 'transparent' }, { value: eol, color: 'transparent' }];
    $('#latest-donut').replaceChildren(
      donut(seg, [`${pct}%`, '최신 적용'], 'latestGrad'),
      h('ul', { class: 'donut-legend' },
        h('li', null, h('i', { class: 'dot c-accent' }), `최신(${latestVer()}) 이상`, h('b', null, `${up}대`)),
        h('li', null, h('i', { class: 'dot c-warning' }), '최신 미만', h('b', null, `${below}대`)),
        h('li', null, h('i', { class: 'dot c-critical' }), 'javax 계열 (26 이하)', h('b', null, `${eol}대`)),
        list.length - known.length ? h('li', null, h('i', { class: 'dot c-info' }), '버전 미확인', h('b', null, `${list.length - known.length}대`)) : null));
  }

  function renderStatusDonut(list) {
    const keys = ['compromise', 'risk', 'warn', 'ok'];
    const cls = { compromise: 'c-critical', risk: 'c-serious', warn: 'c-warning', ok: 'c-good' };
    const segs = keys.map(k => ({ key: k, value: list.filter(r => r.status === k).length, color: TONE[k], label: STATUS[k].label }));
    $('#status-donut').replaceChildren(
      donut(segs, [String(list.length), '점검 서버']),
      h('ul', { class: 'donut-legend' }, ...segs.map(sg => h('li', null,
        h('button', { type: 'button', onclick: () => setStatusFilter(sg.key), title: `${sg.label} 서버만 서버 목록에서 보기` },
          h('i', { class: 'dot ' + cls[sg.key] }), sg.label, h('b', null, `${sg.value}대`))))));
  }

  // ---------------------------------------------------------------- 침해 의심 추이 (영역)
  function renderIntrusionArea() {
    const days = dayKeys(14);
    const rs = reportsInScope();
    const v = days.map(d => rs.filter(r => (r.checkedAt || '').startsWith(d) && r.intrusion === 'compromise').length);
    const Wd = 360, Ht = 110, L = 20, B = 20, Tp = 10;
    const max = Math.max(1, ...v);
    const x = i => L + (Wd - L - 6) * i / (days.length - 1);
    const y = t => Tp + (Ht - Tp - B) * (1 - t / max);
    const line = v.map((t, i) => `${i ? 'L' : 'M'}${x(i)},${y(t)}`).join(' ');
    const els = [svg('defs', null, svg('linearGradient', { id: 'areaGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
      svg('stop', { offset: '0', 'stop-color': '#ec835a', 'stop-opacity': '0.55' }), svg('stop', { offset: '1', 'stop-color': '#ec835a', 'stop-opacity': '0' })))];
    els.push(svg('line', { class: 'gridline', x1: L, x2: Wd, y1: y(0), y2: y(0) }));
    els.push(svg('path', { class: 'area-fill', d: `${line} L${x(days.length - 1)},${y(0)} L${x(0)},${y(0)} Z` }));
    els.push(svg('path', { class: 'area-line', d: line }));
    v.forEach((t, i) => {
      if (t) els.push(svg('circle', { class: 'area-dot', cx: x(i), cy: y(t), r: 3 }));
      const hit = svg('rect', { x: x(i) - 10, y: Tp, width: 20, height: Ht - Tp - B, fill: 'transparent' });
      tip(hit, () => [`${days[i].slice(5).replace('-', '/')} 침해 의심 리포트 ${t}건`]);
      els.push(hit);
      if (i % 4 === 1 || i === days.length - 1) els.push(svg('text', { class: 'axis-label', x: x(i), y: Ht - 5, 'text-anchor': 'middle' }, days[i].slice(5).replace('-', '/')));
    });
    els.push(svg('text', { class: 'axis-label', x: L - 4, y: y(max) + 3, 'text-anchor': 'end' }, String(max)));
    $('#intrusion-area').replaceChildren(svg('svg', { viewBox: `0 0 ${Wd} ${Ht}`, role: 'img', 'aria-label': '최근 14일 침해 의심 리포트 추이' }, els));
  }

  // ---------------------------------------------------------------- 에이전트 상태 타일
  function renderAgentTiles() {
    const el = $('#agent-tiles');
    const list = (state.agents && state.agents.agents) || [];
    if (!list.length) { el.replaceChildren(h('p', { class: 'muted none-msg' }, '등록된 에이전트가 없습니다.')); return; }
    const now = state.agents.now;
    const n = list.length;
    const online = list.filter(a => ['online', 'running', 'requested'].includes(a.state)).length;
    const known = list.filter(a => a.scriptMatches !== null && a.scriptMatches !== undefined);
    const same = known.filter(a => a.scriptMatches).length;
    const recent = list.filter(a => a.lastReportAt && now - a.lastReportAt < 24 * 3600 * 1000).length;
    const tile = (ico, num, label, ratio, bad, title) => {
      const fill = h('i');
      fill.style.width = Math.round(ratio * 100) + '%';
      return h('div', { class: 'tile' + (bad ? ' bad' : ''), title },
        h('div', { class: 't-ico' }, icon(ico)), h('div', { class: 't-num' }, num), h('div', { class: 't-label' }, label), h('div', { class: 't-bar' }, fill));
    };
    el.replaceChildren(
      tile('agent', `${online}/${n}`, '온라인', online / n, online < n, '최근 3분 안에 접속한 에이전트'),
      tile('code', known.length ? `${same}/${known.length}` : '-', '스크립트 최신', known.length ? same / known.length : 0, same < known.length, '대시보드에 들어 있는 wildfly_precheck.sh 와 같은 에이전트 (다르면 install.sh 재실행)'),
      tile('clock', `${recent}/${n}`, '24시간 내 점검', recent / n, false, '최근 24시간 안에 리포트를 보낸 에이전트'));
  }

  // ---------------------------------------------------------------- 시작
  let refreshing = false;
  async function refreshAll() {
    if (refreshing) return;
    refreshing = true;
    try {
      await loadLatest();
      await Promise.all([load(), loadAgents()]);
      renderSideAgents();
      $('#last-refresh').textContent = `마지막 갱신: ${new Date().toLocaleTimeString('ko-KR')}`;
    } finally { refreshing = false; }
  }

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
    $('#btn-refresh').addEventListener('click', refreshAll);
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

    $('#btn-agents').addEventListener('click', () => { showView('agents'); loadAgents(); });
    $$('[data-view]').forEach(b => { if (b.tagName === 'BUTTON') b.addEventListener('click', () => showView(b.dataset.view)); });
    $$('[data-goto]').forEach(b => b.addEventListener('click', () => showView(b.dataset.goto)));
    $$('[data-click]').forEach(b => b.addEventListener('click', () => $('#' + b.dataset.click).click()));
    $('#btn-bell').addEventListener('click', () => {
      showView('overview');
      $('#intrusion-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
    window.addEventListener('hashchange', () => showView(location.hash.slice(1), true));
    showView(location.hash.slice(1) || 'overview', true);
    tickClock();
    setInterval(tickClock, 15000);
    $('#btn-latest-refresh').addEventListener('click', () => latestAction({ action: 'refresh' }));
    $('#btn-latest-auto').addEventListener('click', () => latestAction({ action: 'auto' }));
    $('#btn-latest-manual').addEventListener('click', () => {
      const v = prompt('최신 버전으로 쓸 WildFly 버전을 입력하세요 (예: 41.0.1.Final)', state.latest ? state.latest.version : '');
      if (v) latestAction({ action: 'manual', version: v.trim() });
    });
    $('#latest-skip').addEventListener('change', e => latestAction({ action: 'skip', value: String(e.target.checked) }));
    $('#btn-add-agent').addEventListener('click', () => {
      $('#ag-title').textContent = '에이전트 추가';
      $('#agent-form').hidden = false;
      $('#agent-form').reset();
      $('#agent-install').hidden = true;
      $('#agent-dlg').showModal();
    });
    $('#agent-form').addEventListener('submit', async e => {
      e.preventDefault();
      try {
        const r = await api('agents', { method: 'POST', body: new URLSearchParams(new FormData(e.target)) });
        e.target.hidden = true;
        showInstall(r.name, r.token, false);
        await loadAgents();
      } catch (err) { alert(err.message); }
    });
    $('#agent-dlg').addEventListener('close', () => { $('#agent-install').replaceChildren(); });
    $('#btn-run-all').addEventListener('click', async () => {
      if (!confirm('등록된 모든 에이전트에 지금 점검을 요청할까요?')) return;
      try { const r = await api('agents-run', { method: 'POST' }); await loadAgents(); showAlert(''); alert(`${r.requested}대에 점검을 요청했습니다. 1분 안에 시작됩니다.`); }
      catch (err) { alert(err.message); }
    });

    await refreshAll();
    // 30초마다 자동 갱신 (열린 창이 있거나 탭이 숨겨져 있으면 건너뜀)
    setInterval(() => {
      if (document.hidden || $$('dialog').some(d => d.open)) return;
      refreshAll();
    }, 30000);
  }

  init();
})();
