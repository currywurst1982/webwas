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
    renderSuspects();
    const chip = $('#f-source');
    chip.hidden = !state.sourceFilter;
    if (state.sourceFilter) {
      chip.replaceChildren(`에이전트: ${state.sourceFilter} `,
        h('button', { class: 'btn-link', type: 'button', 'aria-label': '에이전트 필터 해제', onclick: () => { state.sourceFilter = null; render(); renderSideAgents(); } }, '✕'));
    }
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
    const below = list.filter(r => r.belowLatest).length;
    const eol = list.filter(r => r.eol).length;
    const unpatched = list.filter(r => cveTotal(r) > 0).length;
    const dq = list.filter(r => r.dataQuality.length).length;
    $('#kpis').replaceChildren(
      kpi('점검 인스턴스', n, '개', '필터 조건 기준'),
      kpi('', count('compromise'), '대', '[4] 침해 흔적에 [위험] 있음 → 사고 대응 우선', 'compromise', () => setStatusFilter('compromise')),
      kpi('', count('risk'), '대', '침해 흔적 외 [위험] 항목 보유', 'risk', () => setStatusFilter('risk')),
      kpi(`최신(${latestVer()}) 미만`, below, '대', eol ? `이 중 EOL(2.2 이하) ${eol}대` : '업그레이드 대상'),
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
        h('td', null, h('div', null, r.host), h('div', { class: 'sub mono' }, (r.binary || '') + (r.pid ? ` · PID ${r.pid}` : '')),
          h('div', { class: 'sub' }, r.source ? `에이전트 ${r.source} 수집` : '수동 업로드')),
        h('td', null, h('div', null, r.version || '확인 불가'),
          r.eol ? h('div', { class: 'sub' }, 'EOL') : r.belowLatest ? h('div', { class: 'sub', title: `최신 ${latestVer()} 미만` }, '최신 미만') : r.version ? h('div', { class: 'sub' }, '최신 버전') : null),
        h('td', null, r.installType || '-'),
        h('td', { class: 'nowrap' }, r.checkedAt || '-'),
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
  /** extraLines: 툴팁에 덧붙일 줄 (문자열, 또는 {text, level, head}) */
  function hbar(name, segs, max, tipTitle, onclick, extraLines) {
    const total = segs.reduce((a, s) => a + s.value, 0);
    const track = h('div', { class: 'track' });
    segs.filter(s => s.value > 0).forEach(s => {
      const seg = h('div', { class: 'seg ' + s.cls });
      seg.style.width = (s.value / max * 100) + '%';
      track.append(seg);
    });
    const row = h('div', { class: 'hbar', role: onclick ? 'button' : null, tabindex: onclick ? '0' : null, onclick },
      h('div', { class: 'name', title: name }, name), track, h('div', { class: 'val' }, String(total)));
    tip(row, () => [tipTitle || name, ...segs.map(s => `${s.label}: ${s.value}`), ...(extraLines ? extraLines() : [])]);
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
    const pdf = $('#btn-config-pdf');
    pdf.href = 'api/config.pdf' + (state.sourceFilter ? '?source=' + encodeURIComponent(state.sourceFilter) : '');
    const agg = new Map();
    list.forEach(r => {
      const seen = new Set();
      r.configIssues.forEach(ci => {
        const key = ci.text.split(/ → | \(/)[0].trim(); // ConfigIssues.key() 와 같은 규칙
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
    const max = Math.max(1, ...rows.map(a => a.risk + a.warn));
    const LIMIT = 12;
    el.replaceChildren(...rows.map(a => hbar(a.key, [
      { cls: 'c-critical', value: a.risk, label: '위험 서버' },
      { cls: 'c-warning', value: a.warn, label: '주의 서버' }
    ], max, a.full, () => openConfigItem(a), () => [
      { head: true, text: '대상 서버' },
      ...a.servers.slice(0, LIMIT).map(s => ({ level: s.level, text: serverLabel(s.r) })),
      ...(a.servers.length > LIMIT ? [`외 ${a.servers.length - LIMIT}대 — 눌러서 전체 보기`] : [])
    ])));
  }

  function serverLabel(r) {
    return `${r.host}${r.pid ? ` (PID ${r.pid})` : ''} · Apache ${r.version || '?'}`;
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
          h('td', null, h('div', null, s.r.host + (s.r.pid ? ` (PID ${s.r.pid})` : '')), h('div', { class: 'sub' }, `Apache ${s.r.version || '?'}`)),
          h('td', { class: 'nowrap' }, s.r.checkedAt || '-'),
          h('td', null, s.r.source ? `에이전트 ${s.r.source}` : '수동 업로드'))))),
      h('p', { class: 'muted' }, '서버를 누르면 그 서버의 상세 결과(설정 파일 위치 포함)가 열립니다.'));
    $('#cfg-dlg').showModal();
  }

  // ---------------------------------------------------------------- 툴팁
  function tip(el, lines) {
    const t = $('#tooltip');
    const show = e => {
      const [title, ...rest] = lines();
      t.replaceChildren(h('b', null, title), ...rest.map(l => typeof l === 'string' ? h('div', null, l)
        : l.head ? h('div', { class: 'tip-head' }, l.text)
          : h('div', { class: 'tip-item' }, h('span', { class: 'tip-lv tip-' + l.level }, STATUS[l.level] ? STATUS[l.level].label : l.level), l.text)));
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
    $('#d-title').replaceChildren(badge(r.status), r.host, h('span', { class: 'muted' }, `Apache ${r.version || '?'}`));
    $('#d-sub').textContent = [r.checkedAt, r.binary, r.pid ? 'PID ' + r.pid : null, r.installType ? r.installType + ' 설치' : null,
      r.runUser ? '실행계정 ' + r.runUser : null, r.moduleCount !== null ? `모듈 ${r.moduleCount}개` : null, r.id].filter(Boolean).join(' · ');
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

  // ---------------------------------------------------------------- 최신 버전 / 사이드바 / 침해 의심
  function latestVer() {
    return state.latest ? state.latest.version : '?';
  }

  function apacheCell(a) {
    if (!a.apacheVersion) return h('span', { class: 'zero' }, '미확인');
    return h('span', null, a.apacheVersion, ' ',
      a.upToDate ? h('span', { class: 'badge b-ok' }, '최신') : h('span', { class: 'badge b-warn' }, '최신 미만'));
  }

  async function loadLatest() {
    try { state.latest = await api('latest-version'); } catch (e) { return; }
    const l = state.latest;
    $('#latest-ver').textContent = l.version;
    $('#brand-sub').textContent = `Apache 최신 ${l.version} 미만 서버 · apache_precheck.sh 결과`;
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
    $('#side-agents-count').textContent = list.length ? `${list.length}대` : '';
    if (!list.length) {
      ul.replaceChildren(h('li', { class: 'muted side-empty' }, state.me.admin ? '등록된 에이전트가 없습니다. [에이전트 관리]에서 추가하세요.' : '등록된 에이전트가 없습니다.'));
      return;
    }
    const order = { offline: 0, running: 1, requested: 2, online: 3, never: 4 };
    const sorted = list.slice().sort((a, b) => {
      const ra = latestReportOf(a.name), rb = latestReportOf(b.name);
      const ca = ra && ra.intrusion === 'compromise' ? 0 : 1, cb = rb && rb.intrusion === 'compromise' ? 0 : 1;
      return ca - cb || (order[a.state] ?? 9) - (order[b.state] ?? 9) || a.name.localeCompare(b.name);
    });
    ul.replaceChildren(...sorted.map(a => {
      const st = AGENT_STATE[a.state] || AGENT_STATE.never;
      const rep = latestReportOf(a.name);
      const selected = state.sourceFilter === a.name;
      const item = h('li', null, h('button', {
        class: 'side-item' + (selected ? ' selected' : ''), type: 'button', 'aria-pressed': String(selected),
        title: '누르면 이 에이전트의 점검 결과만 표시',
        onclick: () => { state.sourceFilter = selected ? null : a.name; render(); renderSideAgents(); }
      },
        h('span', { class: 'side-row' },
          h('span', { class: 'badge ' + st.cls }, h('span', { class: 'ic', 'aria-hidden': 'true' }, st.icon), st.label),
          rep && rep.intrusion === 'compromise' ? badge('compromise') : null),
        h('span', { class: 'side-name' }, a.name),
        h('span', { class: 'side-meta mono' }, a.hostname || '아직 접속 안 함'),
        h('span', { class: 'side-meta' }, a.apacheVersion ? `Apache ${a.apacheVersion} · ${a.upToDate ? '최신' : '최신 미만'}` : 'Apache 버전 미확인',
          rep ? ` · 점검 ${rel(rep.fileModified)}` : '')));
      return item;
    }));
  }

  /** 인스턴스별 최신 리포트 중 [4] 침해 흔적에 위험/주의가 있는 것 */
  function renderSuspects() {
    const seen = new Set();
    const latest = state.reports.filter(r => { if (seen.has(r.instanceKey)) return false; seen.add(r.instanceKey); return true; });
    const comp = latest.filter(r => r.intrusion === 'compromise');
    const check = latest.filter(r => r.intrusion === 'check');
    $('#btn-suspects-pdf').hidden = comp.length === 0;
    const row = r => h('div', { class: 'suspect' },
      h('div', { class: 'suspect-main' },
        h('div', { class: 'suspect-title' }, badge(r.intrusion === 'compromise' ? 'compromise' : 'warn', r.intrusion === 'compromise' ? '침해 의심' : '확인 필요'),
          h('b', null, r.host), r.pid ? h('span', { class: 'muted' }, `PID ${r.pid}`) : null,
          h('span', { class: 'muted' }, `Apache ${r.version || '?'}`), h('span', { class: 'muted' }, r.checkedAt || ''),
          h('span', { class: 'muted' }, r.source ? `에이전트 ${r.source}` : '수동 업로드')),
        h('ul', { class: 'suspect-findings' }, ...r.intrusionFindings.slice(0, 3).map(f => h('li', null, badge(f.level), ' ', f.text)),
          r.intrusionFindings.length > 3 ? h('li', { class: 'muted' }, `외 ${r.intrusionFindings.length - 3}건`) : null)),
      h('div', { class: 'suspect-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: () => openDetail(r.id) }, '상세'),
        h('a', { class: 'btn small' + (r.intrusion === 'compromise' ? ' btn-danger' : ''), href: 'api/reports/' + encodeURIComponent(r.id) + '/intrusion.pdf', download: '' }, 'PDF')));
    const out = [];
    if (!comp.length) out.push(h('p', { class: 'muted none-msg' }, state.reports.length ? '침해 의심 서버가 없습니다.' : '점검 결과가 아직 없습니다.'));
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
        h('td', null, apacheCell(a)),
        h('td', null, a.autoSkipped && a.intervalHours > 0 ? h('span', { class: 'muted', title: '최신 버전이라 자동 점검 제외 (지금 점검은 가능)' }, '제외(최신)') : next),
        h('td', null, (INTERVALS.find(([v]) => v === a.intervalHours) || [0, `${a.intervalHours}시간`])[1]),
        h('td', null, scriptCell),
        actions);
    });
    if (!rows.length) rows.push(h('tr', null, h('td', { colspan: '9', class: 'muted' },
      state.me.admin ? '등록된 에이전트가 없습니다. [에이전트 추가]로 웹서버에 에이전트를 설치하세요.' : '등록된 에이전트가 없습니다.')));
    $('#agents tbody').replaceChildren(...rows);
    renderSideAgents();
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
          ? h('li', null, h('p', null, '웹서버에서 아래 명령으로 설정 파일의 토큰만 바꿉니다. (또는 아래 2~3단계로 다시 설치)'),
            codeBox(`sudo sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN='${token}'|" /etc/precheck-agent.conf && sudo /opt/precheck-agent/precheck-agent.sh test`))
          : null,
        h('li', null, h('p', null, '점검할 웹서버에 root 권한이 있는 계정으로 접속해 설치 파일을 받습니다.'),
          codeBox(`curl -fsSo /tmp/precheck-install.sh ${url}/agent-api/files/install.sh`)),
        h('li', null, h('p', null, '설치를 실행합니다. 토큰을 물어보면 아래 3번의 토큰을 붙여 넣고 Enter 를 누릅니다.'),
          codeBox(`sudo bash /tmp/precheck-install.sh ${url} ${name}`)),
        h('li', null, h('p', null, '에이전트 토큰'), codeBox(token)),
        h('li', null, h('p', null, '"설치 완료"가 나오면 1~2분 안에 이 화면의 상태가 "온라인"이 되고, 첫 점검이 자동으로 시작됩니다.'))),
      h('p', { class: 'muted' }, `※ 웹서버에서 ${url} 로 접속할 수 있어야 합니다(방화벽 확인). 웹서버에서 보이는 주소가 다르면 명령의 주소를 바꿔서 실행하세요. `
        + '인터넷이 안 되는 서버는 precheck-agent.sh, apache_precheck.sh, install.sh 세 파일을 같은 폴더에 복사한 뒤 그 폴더에서 install.sh 를 실행하면 됩니다.'));
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
    if (!confirm(`${name} 토큰을 재발급할까요? 기존 토큰은 바로 사용할 수 없게 되어, 웹서버 설정을 바꾸기 전까지 에이전트가 접속하지 못합니다.`)) return;
    try {
      const r = await api('agents/' + encodeURIComponent(name) + '/token', { method: 'POST' });
      $('#ag-title').textContent = '토큰 재발급';
      $('#agent-form').hidden = true;
      showInstall(r.name, r.token, true);
      $('#agent-dlg').showModal();
    } catch (e) { alert(e.message); }
  }
  async function agentDelete(name) {
    if (!confirm(`${name} 에이전트를 삭제할까요? 이미 받은 리포트는 남습니다. 웹서버의 에이전트는 'sudo bash /tmp/precheck-install.sh --uninstall' 로 따로 삭제하세요.`)) return;
    try { await api('agents/' + encodeURIComponent(name), { method: 'DELETE' }); await loadAgents(); }
    catch (e) { alert(e.message); }
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

    $('#btn-agents').addEventListener('click', () => { $('#agents-dlg').showModal(); loadAgents(); });
    $('#btn-latest-refresh').addEventListener('click', () => latestAction({ action: 'refresh' }));
    $('#btn-latest-auto').addEventListener('click', () => latestAction({ action: 'auto' }));
    $('#btn-latest-manual').addEventListener('click', () => {
      const v = prompt('최신 버전으로 쓸 Apache 버전을 입력하세요 (예: 2.4.69)', state.latest ? state.latest.version : '');
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
      // 에이전트 관리 창은 열려 있어도 갱신, 다른 창이 열려 있으면 건너뜀
      if (document.hidden || $$('dialog').some(d => d.open && d.id !== 'agents-dlg')) return;
      refreshAll();
    }, 30000);
  }

  init();
})();
