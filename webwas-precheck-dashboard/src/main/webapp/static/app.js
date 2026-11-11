/* Web·WAS(Apache·WildFly·Tomcat) 사전점검 대시보드 화면 스크립트 (외부 라이브러리 없음, 모든 값은 textContent 로만 넣음) */
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
    high: { label: 'high', color: 'c-serious', rank: 1 },  // Apache 의 important 도 high 로 들어옴
    moderate: { label: 'moderate', color: 'c-warning', rank: 2 },
    low: { label: 'low', color: 'c-info', rank: 3 }
  };
  /** 제품별 "교체 필요" 표시 설명 (Report.eol) */
  const EOL_HINT = {
    apache: 'Apache 2.2 이하 — 공식 지원 종료(EOL), 보안 패치 없음. 교체가 근본 대책',
    wildfly: 'Java EE 8(javax) 계열(WildFly 26 이하) — 최신으로 올릴 때 앱의 javax → jakarta 변경 필요',
    tomcat: '지원 종료(EOL) 브랜치 — 보안 패치 없음. 지원 브랜치(11.0 / 10.1 / 9.0)로 교체 필요',
    nginx: '지원 종료(EOL) 브랜치 — nginx.org 보안 수정 없음. stable 브랜치로 교체 필요 (배포판 패키지는 배포판 백포트 확인)'
  };
  const CVE_NOTE = {
    apache: '판정은 업스트림 버전 기준(Apache 보안팀 공지의 영향 버전 + 필요 모듈이 켜져 있는지)입니다. 패키지 설치본의 "백포트 추정"은 changelog 에 CVE 번호가 있다는 뜻일 뿐이므로 배포판 보안 공지로 최종 확인하세요.',
    wildfly: '판정은 이 서버 설치 폴더(modules)의 실제 구성요소(jar) 버전을 OSV 취약점 DB 의 영향 구간과 비교한 결과입니다. 설명은 OSV 원문(영문)입니다. 해당 기능(AJP·OIDC·HTTP/2 등)을 쓰지 않으면 실제 악용 가능성은 낮을 수 있습니다.',
    tomcat: '판정은 Tomcat 버전을 OSV 취약점 DB 의 영향 구간과 비교한 결과입니다(선택 구성요소는 lib 에 jar 가 있을 때만). 설명은 OSV 원문(영문)입니다. 해당 기능(AJP·HTTP/2·WebDAV·CGI 등)을 쓰지 않으면 실제 악용 가능성은 낮을 수 있습니다.',
    nginx: '판정은 nginx.org 보안 공지의 영향 버전·수정 버전과, 설정에서 그 기능(HTTP/3·mp4·mail·resolver 등)을 쓰는지를 함께 본 결과입니다. 필요 기능은 공지 제목으로 정한 추정이며, 설명은 공지 원문(영문)입니다. 패키지 설치본의 "백포트 추정"은 changelog 에 CVE 번호가 있다는 뜻이므로 배포판 보안 공지로 최종 확인하세요.'
  };
  const SECTION_TITLE = {
    '1': '[1] 버전 및 설치 방식',
    '2': '[2] CVE 판정',
    '3': '[3] 위험 설정',
    '4': '[4] 침해 흔적'
  };

  const PRODUCTS = { apache: 'Apache', wildfly: 'WildFly', tomcat: 'Tomcat', nginx: 'Nginx' };
  /** CVE 를 "버전 + 필요 모듈(기능)"으로 판정하고 changelog 로 백포트를 추정하는 제품 (Product.moduleStyle 과 같음) */
  const MODSTYLE = p => p === 'apache' || p === 'nginx';
  const COND_LABEL = p => p === 'nginx' ? '필요 기능' : '필요 모듈';
  const state = { me: null, reports: [], sort: { key: 'status', asc: true }, product: loadProduct() };
  function loadProduct() { try { const v = localStorage.getItem('precheck.product') || ''; return PRODUCTS[v] ? v : ''; } catch (e) { return ''; } }
  /** "Tomcat 9.0.80" */
  function prodVer(r) { return `${r.productLabel || PRODUCTS[r.product] || ''} ${r.version || '?'}`; }
  function prodBadge(p) { return h('span', { class: 'pbadge p-' + p }, PRODUCTS[p] || p); }
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
    // 제품 + 인스턴스 구분(Apache -f 설정 파일 / WildFly·Tomcat 서버 폴더), 없으면 WAS 는 설치 폴더 이름 (IntrusionPdf.hostLabel 과 같은 규칙)
    let inst = null;
    if (r.confArg) inst = r.confArg.length <= 40 ? r.confArg : '…' + r.confArg.slice(-39);
    else if (!MODSTYLE(r.product) && r.binary) inst = r.binary.slice(r.binary.lastIndexOf('/') + 1);
    return `${s} [${PRODUCTS[r.product] || r.product}${inst ? ' ' + inst : ''}]`;
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

  /**
   * 큰 목록용 요청: 지난번 응답의 ETag 를 보내 바뀐 것이 없으면(304) 지난 데이터를 그대로 씀.
   * 반환: { data, changed, total }
   */
  const etagCache = new Map();
  async function apiCached(path) {
    const prev = etagCache.get(path);
    const res = await fetch('api/' + path, { credentials: 'same-origin', cache: 'no-store',
      headers: prev ? { 'If-None-Match': prev.etag } : {} });
    if (res.status === 401) { location.href = 'login'; throw new Error('로그인이 필요합니다.'); }
    if (res.status === 304 && prev) return { data: prev.data, changed: false, total: prev.total };
    const body = await res.json();
    if (!res.ok) throw new Error((body && body.error) || ('요청 실패 (' + res.status + ')'));
    const total = +(res.headers.get('X-Total-Reports') || 0);
    if (res.headers.get('ETag')) etagCache.set(path, { etag: res.headers.get('ETag'), data: body, total });
    return { data: body, changed: true, total };
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
    const grp = $('#f-group') ? $('#f-group').value : '';
    const latestOnly = $('#f-latest').checked;
    const dqOnly = $('#f-dq').checked;
    const src = state.sourceFilter;
    // state.reports 는 인스턴스별 최신만(서버에서 걸러 옴). 끄면 전체 이력(state.allReports, 필요할 때만 받음)
    let list = (latestOnly || !state.allReports ? state.reports : state.allReports).filter(r => !state.product || r.product === state.product);
    return list.filter(r => {
      if (st && r.status !== st) return false;
      if (grp && (r.group || '') !== grp) return false;
      if (dqOnly && !r.dataQuality.length) return false;
      if (src && r.source !== src) return false;
      if (state.gapFilter && !(r.gaps || []).includes(state.gapFilter)) return false;
      if (!q) return true;
      const hay = [r.host, ...(r.ips || []), r.group, r.productLabel, r.version, r.versionLine, r.binary, r.id, r.cveList.map(c => c.id).join(' '), (r.cveExemptIds || []).join(' ')].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  function sortList(list) {
    const { key, asc } = state.sort;
    const val = r => {
      switch (key) {
        case 'status': return STATUS[r.status].rank * 1000 - r.counts.risk;
        case 'host': return r.host;
        case 'product': return r.product + '|' + r.host;
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

  // ---------------------------------------------------------------- CSV 내보내기
  /** 지금 걸러진 서버 목록을 CSV 로 저장. 엑셀이 한글을 바로 읽도록 UTF-8 BOM, 수식 주입 방지(=,+,-,@ 로 시작하면 ' 붙임) */
  function exportCsv() {
    const list = sortList(filtered());
    if (!list.length) { alert('내보낼 결과가 없습니다. 검색·판정 조건을 확인하세요.'); return; }
    const cell = v => {
      let s = v == null ? '' : String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const head = ['판정', '그룹', '제품', '호스트', 'IP', '바이너리', '설정', '버전', '버전 상태', '설치 방식', '점검 시각',
      '위험', '주의', '양호', '예외(위험)', '예외(주의)', 'CVE critical', 'CVE high', 'CVE moderate', 'CVE low',
      '점검 사각지대', '데이터 경고', '수집', '리포트'];
    const rows = list.map(r => {
      const cu = r.cveUnpatched || {};
      const ex = r.exempt || {};
      return [
        (STATUS[r.status] || {}).label || r.status, r.group || '', r.productLabel || r.product, r.host, (r.ips || []).join(' ') || r.ip || '',
        r.binary || '', r.confArg || '', r.version || '확인 불가',
        r.eol ? r.eolLabel : r.belowLatest ? (r.latestForVersion ? `최신 ${r.latestForVersion} 미만` : '지원 종료 브랜치') : r.version ? '최신' : '',
        r.installType || '', r.checkedAt || '', r.counts.risk, r.counts.warn, r.counts.ok, ex.risk || 0, ex.warn || 0,
        cu.critical || 0, cu.high || 0, cu.moderate || 0, cu.low || 0,
        (r.gaps || []).map(g => (GAPS[g] || [g])[0]).join(' / '), (r.dataQuality || []).join(' / '),
        r.source ? `에이전트 ${r.source}` : '수동 업로드', r.id].map(cell).join(',');
    });
    const csv = '﻿' + [head.map(cell).join(','), ...rows].join('\r\n') + '\r\n';
    const d = new Date(), p = n => String(n).padStart(2, '0');
    const name = `webwas-precheck_servers_${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}.csv`;
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const a = h('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------------------------------------------------------------- 렌더링
  /** 개요 화면용: 인스턴스별 최신 리포트 (에이전트·제품을 고르면 그것만) */
  function overviewList() {
    const seen = new Set();
    return state.reports.filter(r => {
      if (seen.has(r.instanceKey)) return false;
      seen.add(r.instanceKey);
      return (!state.sourceFilter || r.source === state.sourceFilter) && (!state.product || r.product === state.product);
    });
  }

  /** 제품 탭 (전체 / Apache / WildFly / Tomcat) + 제품별 인스턴스 수 */
  function renderProductTabs() {
    const seen = new Set();
    const latest = state.reports.filter(r => { if (seen.has(r.instanceKey)) return false; seen.add(r.instanceKey); return true; });
    const cnt = p => latest.filter(r => !p || r.product === p).length;
    const bad = p => latest.filter(r => (!p || r.product === p) && r.status === 'compromise').length;
    $('#prod-tabs').replaceChildren(...[['', '전체'], ...Object.entries(PRODUCTS)].map(([p, label]) => {
      const sel = state.product === p;
      return h('button', { type: 'button', role: 'tab', 'aria-selected': String(sel), class: 'ptab' + (p ? ' p-' + p : ''),
        onclick: () => { state.product = p; try { localStorage.setItem('precheck.product', p); } catch (e) { /* 저장 불가 환경 */ } render(); } },
        label, h('span', { class: 'ptab-n' }, String(cnt(p))), bad(p) ? h('span', { class: 'ptab-bad', title: '침해 의심' }, String(bad(p))) : null);
    }));
  }

  /** 그룹 필터 드롭다운 옵션을 현재 리포트들의 그룹으로 채움 (선택값은 유지) */
  function fillGroupFilter() {
    const sel = $('#f-group');
    if (!sel) return;
    const groups = [...new Set((state.allReports || state.reports || []).map(r => r.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'ko'));
    const cur = sel.value;
    sel.replaceChildren(h('option', { value: '' }, '그룹 전체'),
      ...groups.map(g => h('option', { value: g, selected: g === cur || null }, g)));
    if (cur && !groups.includes(cur)) sel.value = ''; // 그룹이 사라지면 전체로
  }

  function render() {
    fillGroupFilter();
    const list = sortList(filtered());
    const ov = overviewList();
    $('#empty').hidden = state.reports.length > 0;
    $('#f-count').textContent = state.reports.length ? `${list.length}건 표시 / 인스턴스 ${state.reports.length}개 · 보관 리포트 ${state.totalReports || state.reports.length}건` : '';
    const chip = $('#f-source');
    chip.hidden = !state.sourceFilter;
    if (state.sourceFilter) {
      chip.replaceChildren(`에이전트: ${state.sourceFilter} `,
        h('button', { class: 'btn-link', type: 'button', 'aria-label': '에이전트 필터 해제', onclick: () => { state.sourceFilter = null; render(); renderSideAgents(); } }, '✕'));
    }
    const gchip = $('#f-gap');
    gchip.hidden = !state.gapFilter;
    if (state.gapFilter) {
      gchip.replaceChildren(`사각지대: ${(GAPS[state.gapFilter] || [state.gapFilter])[0]} `,
        h('button', { class: 'btn-link', type: 'button', 'aria-label': '사각지대 필터 해제', onclick: () => { state.gapFilter = null; render(); } }, '✕'));
    }
    renderProductTabs();
    // 개요
    renderKpis(ov);
    renderHero(ov);
    renderTrend();
    renderLatestDonut(ov);
    renderStatusDonut(ov);
    renderSuspects();
    renderCveChart(ov);
    renderConfigChart(ov);
    renderGaps(ov);
    // 서버 목록
    renderTable(list);
    renderFindingsChart(list);
  }

  /** 점검 사각지대 (Report.gaps() 코드) → 이름, 설명(무엇이 빠졌고 어떻게 메우는지) */
  const GAPS = {
    accessLog: ['접근 로그 없음', '경로 탐색·웹쉘 요청·성공(200) 응답 등 요청 단위 흔적을 못 봄. server.log·catalina.out 의 JNDI·역직렬화 흔적은 따로 점검하지만, 요청 스트림은 접근 로그에만 남습니다(요청 URL·응답 코드). → WildFly 접근 로그 켜기, 또는 앞단 Apache·Nginx 접근 로그를 에이전트 설정 *_LOG_PATHS(-l)로 지정'],
    serverLog: ['서버 로그 못 찾음', 'server.log·catalina.out 의 역직렬화·JNDI 흔적을 못 봄 → 에이전트 설정 WILDFLY_/TOMCAT_SERVER_LOG_PATHS(-s)로 위치 지정'],
    webFiles: ['웹 파일 위치 못 찾음', 'DocumentRoot·배포 폴더를 못 찾아 웹쉘 파일 점검을 못 함'],
    authLog: ['OS 로그인 기록 못 읽음', '/var/log/secure·auth.log·journal 을 읽지 못해 로그인 공격 점검을 못 함 (root 권한·로그 위치 확인)'],
    oldScript: ['이전 스크립트 결과', 'OS 로그인 기록 점검이 없는 옛 점검 스크립트로 만든 리포트 → 에이전트 재설치 후 다시 점검'],
    noRoot: ['root 권한 없이 실행', '권한이 없어 로그·설정·프로세스 점검이 불완전'],
    incomplete: ['점검 중단', '점검이 끝까지 실행되지 않아 결과가 불완전'],
  };

  function renderGaps(ov) {
    const total = ov.length;
    $('#gaps-meta').textContent = total ? `인스턴스 ${total}개 기준` : '';
    const has = code => ov.filter(r => (r.gaps || []).includes(code));
    const anyGap = ov.filter(r => (r.gaps || []).length).length;
    const tiles = Object.entries(GAPS).map(([code, [label, desc]]) => {
      const n = has(code).length;
      const go = () => { state.gapFilter = code; showView('servers'); render(); };
      return h('div', {
        class: 'gap-tile' + (n ? ' on' : ''), title: desc + (n ? '\n누르면 해당 서버만 서버 목록에 표시' : ''),
        role: n ? 'button' : null, tabindex: n ? '0' : null, onclick: n ? go : null,
        onkeydown: n ? e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } } : null
      },
        h('div', { class: 'g-num' }, String(n), h('small', null, total ? ` / ${total}` : '')),
        h('div', { class: 'g-label' }, label),
        h('div', { class: 'g-desc' }, desc));
    });
    $('#gap-tiles').replaceChildren(
      h('div', { class: 'gap-sum' + (anyGap ? ' bad' : '') }, total
        ? (anyGap ? `점검이 일부 빠진 인스턴스 ${anyGap}개 / ${total}개` : `모든 인스턴스가 빠짐없이 점검됨 (${total}개)`)
        : '아직 점검 결과가 없습니다.'),
      ...tiles);
  }

  function kpi(label, value, unit, hint, kind, onclick) {
    return h('div', { class: 'kpi' + (onclick ? ' clickable' : ''), onclick, role: onclick ? 'button' : null, tabindex: onclick ? '0' : null,
      onkeydown: onclick ? e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onclick(); } } : null },
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
      statCard({ ico: 'server', label: '점검 인스턴스', value: n, unit: '개',
        hint: `서버 ${new Set(list.map(r => r.host + '|' + (r.ip || ''))).size}대` + (state.sourceFilter ? ` · 에이전트 ${state.sourceFilter} 수집분` : ' · 인스턴스별 최신 점검'),
        onclick: () => { $('#f-status').value = ''; render(); showView('servers'); } }),
      statCard({ ico: 'shield', tone: 'critical', label: '침해 의심', value: comp, unit: '대',
        hint: comp ? '사고 대응 우선 — [4] 침해 흔적 [위험]' : '침해 흔적 [위험] 없음', hintTone: comp ? 'up' : 'good', onclick: () => setStatusFilter('compromise') }),
      statCard({ ico: 'alert', tone: 'serious', label: '위험', value: count('risk'), unit: '대', hint: '침해 흔적 외 [위험] 항목 보유', onclick: () => setStatusFilter('risk') }),
      statCard({ ico: 'up', tone: 'warning', label: state.product ? `최신(${latestVer(state.product)}) 미만` : '최신 버전 미만', value: below, unit: '대',
        hint: eol ? `이 중 교체 필요(EOL·지원 종료·javax) ${eol}대` : (n ? `${n - below}대 최신 버전` : '업그레이드 대상') }),
      statCard({ ico: 'bug', tone: 'serious', label: '미조치 CVE 보유', value: unpatched, unit: '대', hint: '해당 CVE 중 백포트 기록 없음 (Apache·Nginx 는 모듈·기능 조건 포함)' }),
      statCard({ ico: 'data', tone: 'warning', label: '데이터 경고', value: dq, unit: '대', hint: dq ? '점검 불완전 — 수동 확인 필요' : '이상 없음', hintTone: dq ? '' : 'good',
        onclick: dq ? () => { $('#f-dq').checked = true; render(); showView('servers'); } : null })
    );
    // 머리글 알림 종: 침해 의심 수 (에이전트 필터와 관계없이 전체)
    const allComp = (() => { const seen = new Set(); return state.reports.filter(r => { if (seen.has(r.instanceKey)) return false; seen.add(r.instanceKey); return r.intrusion === 'compromise'; }).length; })();
    const bell = $('#bell-count');
    bell.hidden = !allComp;
    bell.textContent = String(allComp);
  }

  /** 서버 목록 표에 한 번에 그리는 행 수 (전체 이력 9,000줄을 한꺼번에 그리면 10초 이상 걸림) */
  const TABLE_PAGE = 500;
  state.tableLimit = TABLE_PAGE;

  function renderTable(list) {
    $$('#servers th[data-sort]').forEach(th => {
      th.classList.toggle('sorted', th.dataset.sort === state.sort.key);
      th.classList.toggle('asc', th.dataset.sort === state.sort.key && state.sort.asc);
    });
    const shown = list.slice(0, state.tableLimit);
    const rows = shown.map(r => {
      const num = v => h('td', { class: 'num' + (v ? '' : ' zero') }, String(v));
      const chips = Object.entries(r.cveUnpatched).filter(([, v]) => v > 0)
        .map(([sev, v]) => h('span', { class: 'badge b-' + sev, title: sev }, `${sev[0].toUpperCase()} ${v}`));
      const tr = h('tr', { class: 'row', tabindex: '0', onclick: () => openDetail(r.id),
        onkeydown: e => { if (e.key === 'Enter') openDetail(r.id); } },
        h('td', null, badge(r.status)),
        h('td', null, prodBadge(r.product)),
        h('td', null, h('div', null, r.host, r.group ? h('span', { class: 'badge b-group', title: `그룹: ${r.group}` }, r.group) : null),
          h('div', { class: 'sub mono' }, [r.ip ? (r.ipFromAgent ? `${r.ip}(접속 IP)` : r.ips.join(', ')) : null, r.binary, r.confArg ? (r.product === 'apache' ? '-f ' + r.confArg : r.confArg) : null].filter(Boolean).join(' · ')),
          h('div', { class: 'sub' }, r.source ? `에이전트 ${r.source} 수집` : '수동 업로드')),
        h('td', null, h('div', null, r.version || '확인 불가'),
          r.eol ? h('div', { class: 'sub nowrap', title: EOL_HINT[r.product] }, r.eolLabel) : r.belowLatest ? h('div', { class: 'sub nowrap', title: r.latestForVersion ? `최신 ${r.latestForVersion} 미만` : '지원 종료 브랜치' }, r.latestForVersion ? '최신 미만' : '지원 종료') : r.version ? h('div', { class: 'sub' }, '최신 버전') : null),
        h('td', null, r.installType || '-'),
        h('td', { class: 'nowrap' }, r.checkedAt || '-'),
        num(r.counts.risk), num(r.counts.warn), num(r.counts.ok),
        h('td', { class: 'num' }, chips.length ? h('div', { class: 'cve-chips' }, chips)
          : r.product === 'apache' && r.version && !r.version.startsWith('2.4.') ? h('span', { class: 'badge b-warn', title: '2.4.x 가 아니라 스크립트가 CVE 판정을 하지 않았습니다. EOL 버전은 교체가 근본 대책입니다.' }, '판정 제외')
          : h('span', { class: 'zero' }, '0')),
        h('td', null, r.dataQuality.length ? h('span', { class: 'badge b-warn', title: r.dataQuality.join('\n') }, h('span', { class: 'ic' }, '!'), `${r.dataQuality.length}건`) : h('span', { class: 'zero' }, '-'))
      );
      return tr;
    });
    if (!rows.length) rows.push(h('tr', null, h('td', { colspan: '11', class: 'muted' }, state.reports.length ? '조건에 맞는 결과가 없습니다.' : '등록된 리포트가 없습니다.')));
    if (list.length > shown.length) {
      const left = list.length - shown.length;
      rows.push(h('tr', { class: 'more-row' }, h('td', { colspan: '11' },
        `${shown.length}건 표시 중 · 남은 ${left}건 `,
        h('button', { class: 'btn small', type: 'button', onclick: () => { state.tableLimit += TABLE_PAGE; renderTable(sortList(filtered())); } },
          `다음 ${Math.min(TABLE_PAGE, left)}건 더 보기`),
        ' ', h('span', { class: 'muted' }, '(검색·판정으로 좁히면 더 빠릅니다)'))));
    }
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
    ], max, `${r.host} · ${prodVer(r)}`, () => openDetail(r.id))));
    if (list.length > rows.length) el.append(h('div', { class: 'none' }, `상위 ${rows.length}개만 표시 (위험 많은 순)`));
  }

  function renderCveChart(list) {
    legend('#legend-cve', [['c-critical', 'critical'], ['c-serious', 'high'], ['c-warning', 'moderate'], ['c-backport', '백포트 추정']]);
    $('#btn-cve-pdf').href = 'api/cve.pdf' + pdfQuery();
    $('#chart-cve').dataset.total = list.length;
    const agg = new Map();
    list.forEach(r => r.cveList.forEach(c => {
      const a = agg.get(c.id) || { id: c.id, open: 0, bp: 0, sev: SEVERITY[c.severity] ? c.severity : 'low', desc: c.description,
        affected: c.affected, advisory: c.advisory, product: r.product, servers: [] };
      if (c.backported) a.bp++; else a.open++;
      a.servers.push({ r, condition: c.condition, affected: c.affected, backported: c.backported });
      agg.set(c.id, a);
    }));
    // CveIssues.group() 과 같은 순서: 미조치 서버 수 → 등급 → 백포트 서버 수, 서버는 미조치 먼저 → 호스트 이름 순
    agg.forEach(a => a.servers.sort((x, y) => (x.backported - y.backported) || x.r.host.localeCompare(y.r.host)));
    const rows = Array.from(agg.values())
      .sort((a, b) => (b.open - a.open) || SEVERITY[a.sev].rank - SEVERITY[b.sev].rank || (b.bp - a.bp) || a.id.localeCompare(b.id)).slice(0, 15);
    const el = $('#chart-cve');
    if (!rows.length) { el.replaceChildren(h('div', { class: 'none' }, '해당 CVE 없음')); return; }
    const max = Math.max(1, list.length);
    const LIMIT = 12;
    el.replaceChildren(...rows.map(a => hbar(state.product ? `${a.id} · ${a.sev}` : `${a.id} · ${PRODUCTS[a.product] || ''}`, [
      { cls: SEVERITY[a.sev].color, value: a.open, label: '미조치 추정 서버' },
      { cls: 'c-backport', value: a.bp, label: '백포트 추정 서버' }
    ], max, `${PRODUCTS[a.product] || ''} ${a.id} [${a.sev}] ${a.desc || ''}`, () => openCveItem(a), () => [
      { head: true, text: MODSTYLE(a.product) ? `대상 서버 (${COND_LABEL(a.product)} 조건 충족)` : '대상 서버 (설치된 구성요소)' },
      ...a.servers.slice(0, LIMIT).map(s => s.backported ? { level: 'bp', label: '백포트', text: serverLabel(s.r) }
        : { level: a.sev === 'critical' || a.sev === 'high' ? 'risk' : 'warn', text: serverLabel(s.r) + (MODSTYLE(a.product) ? '' : ` · ${(s.condition || '').replace(/ 설치됨$/, '')}`) }),
      ...(a.servers.length > LIMIT ? [`외 ${a.servers.length - LIMIT}대 — 눌러서 전체 보기`] : [])
    ], `${a.open + a.bp}/${list.length}대`)));
  }

  /** CVE 1건의 대상 서버 목록 창 */
  function openCveItem(a) {
    $('#cfg-title').textContent = `${PRODUCTS[a.product] || ''} ${a.id} [${a.sev}]`;
    $('#cfg-sub').textContent = `대상 서버 ${a.servers.length}대` + (a.bp ? ` (미조치 추정 ${a.open} · 백포트 추정 ${a.bp})` : '');
    $('#cfg-body').replaceChildren(
      h('p', null, a.desc || ''),
      h('p', { class: 'muted' }, `영향 구간(첫 대상 서버 기준): ${a.affected || '-'}` + (MODSTYLE(a.product) ? ` · ${COND_LABEL(a.product)} 조건: ${a.servers[0].condition || '-'}` : '') + ' · ',
        h('a', { href: 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(a.id), target: '_blank', rel: 'noopener noreferrer' }, 'cve.org 상세'),
        a.advisory ? ' · ' : null,
        a.advisory ? h('a', { href: 'https://osv.dev/vulnerability/' + encodeURIComponent(a.advisory), target: '_blank', rel: 'noopener noreferrer' }, 'OSV 권고') : null),
      h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['판정', '서버', MODSTYLE(a.product) ? '설치' : '설치된 구성요소', '점검 일시', '수집'].map(t => h('th', null, t)))),
        h('tbody', null, ...a.servers.map(s => h('tr', { class: 'row', tabindex: '0', onclick: () => { $('#cfg-dlg').close(); openDetail(s.r.id); } },
          h('td', null, s.backported ? h('span', { class: 'badge b-backport' }, '백포트 추정') : h('span', { class: 'badge b-' + a.sev }, a.sev)),
          h('td', null, h('div', null, hostLabel(s.r)), h('div', { class: 'sub' }, prodVer(s.r))),
          h('td', { class: 'mono' }, MODSTYLE(a.product) ? (s.r.installType || '-') : (s.condition || '-').replace(/ 설치됨$/, '')),
          h('td', { class: 'nowrap' }, s.r.checkedAt || '-'),
          h('td', null, s.r.source ? `에이전트 ${s.r.source}` : '수동 업로드'))))),
      h('p', { class: 'dialog-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: () => { $('#cfg-dlg').close(); $('#f-q').value = a.id; render(); showView('servers'); } }, '이 CVE로 서버 목록 거르기'),
        h('span', { class: 'muted' }, '서버를 누르면 그 서버의 상세 결과가 열립니다. Apache 는 Apache 보안 공지의 영향 버전 + 필요 모듈 기준("백포트 추정"은 패키지 changelog 에 CVE 번호가 있다는 뜻), '
          + 'WildFly·Tomcat 은 설치 폴더의 실제 버전과 OSV 영향 구간 기준입니다.')));
    $('#cfg-dlg').showModal();
  }

  function renderConfigChart(list) {
    legend('#legend-config', [['c-critical', '위험'], ['c-warning', '주의']]);
    const pdf = $('#btn-config-pdf');
    pdf.href = 'api/config.pdf' + pdfQuery();
    const agg = new Map();
    list.forEach(r => {
      const seen = new Set();
      r.configIssues.forEach(ci => {
        // ConfigIssues.key() 와 같은 규칙: Apache 는 " → " / " (" 앞, WildFly·Tomcat 은 ": " 앞까지. 제품이 다르면 다른 항목
        const name = ci.text.split(MODSTYLE(r.product) ? / → | \(/ : / → | \(|: /)[0].trim();
        const key = r.product + '|' + name;
        if (seen.has(key)) return;
        seen.add(key);
        const a = agg.get(key) || { key: `[${PRODUCTS[r.product]}] ${name}`, risk: 0, warn: 0, full: ci.text, servers: [] };
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
    return `${hostLabel(r)} · ${prodVer(r)}`;
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
          h('td', null, h('div', null, hostLabel(s.r)), h('div', { class: 'sub' }, prodVer(s.r))),
          h('td', { class: 'nowrap' }, s.r.checkedAt || '-'),
          h('td', null, s.r.source ? `에이전트 ${s.r.source}` : '수동 업로드'))))),
      h('p', { class: 'muted' }, '서버를 누르면 그 서버의 상세 결과(근거가 된 설정 파일·줄·옵션 포함)가 열립니다.'));
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
    $('#d-title').replaceChildren(badge(r.status), prodBadge(r.product), r.host, h('span', { class: 'muted' }, prodVer(r)));
    $('#d-sub').textContent = [r.checkedAt, r.ips.length ? 'IP ' + r.ips.join(', ') + (r.ipFromAgent ? '(접속 IP)' : '') : null, r.binary,
      r.confArg ? (r.product === 'apache' ? '-f ' + r.confArg : r.product === 'nginx' ? '-c ' + r.confArg : r.confArg) : null,
      r.installType ? r.installType + ' 설치' : null, r.runMode, r.runUser ? '실행계정 ' + r.runUser : null,
      r.javaVersion ? 'Java ' + r.javaVersion.replace(/^openjdk version |"/g, '') : null,
      r.moduleCount !== null ? (r.product === 'apache' ? `모듈 ${r.moduleCount}개` : r.product === 'nginx' ? `빌드 옵션 ${r.moduleCount}개` : `구성요소 ${r.moduleCount}개`) : null,
      MODSTYLE(r.product) ? `설정 파일 ${r.confFileCount}개(${r.confMethodShort})` : `설정 ${r.confMethodShort}`,
      r.cveDbInfo ? 'CVE 목록: ' + r.cveDbInfo : 'CVE 목록: 스크립트 내장본(이전 스크립트)', r.id].filter(Boolean).join(' · ');
    $('#d-raw').href = 'api/reports/' + encodeURIComponent(r.id) + '/raw';
    $('#d-pdf').href = 'api/reports/' + encodeURIComponent(r.id) + '/intrusion.pdf';

    $('#d-dq').replaceChildren(...(r.dataQuality.length ? [h('div', { class: 'alert warn dq' },
      h('b', null, '데이터 품질 경고 — 아래 결과를 그대로 믿기 전에 확인하세요'), ...r.dataQuality.map(d => h('div', null, '· ' + d)))] : []),
      ...(r.compromise ? [h('div', { class: 'alert' }, h('b', null, '침해 의심: '), '[4] 침해 흔적 점검에 [위험] 항목이 있습니다. 설정 보완·패치보다 침해사고 대응(격리·증거 보존·분석)이 우선입니다.')] : []));

    dFilter = { tab: null, value: null };
    renderDetailKpis(r);
    renderFindings(r);
    renderCves(r);
    renderHistory(r);
    renderDiff(r);
    $('#d-rawtext').textContent = r.raw;
    selectTab('findings');
    if (!dlg.open) dlg.showModal();
    // 창이 열린 뒤에 맨 위로 (닫힌 창에서는 스크롤 위치가 바뀌지 않음)
    $('#detail .dialog-body').scrollTop = 0;
    $('#d-top').hidden = true;
  }

  /** 상세 창 걸러 보기: tab = findings | cves, value = risk/warn/ok 또는 '1'(해당 CVE)/'0'(미해당 CVE) */
  let dFilter = { tab: null, value: null };
  const FILTER_LABEL = { risk: '위험', warn: '주의', ok: '양호', '1': '해당 CVE', '0': '미해당 CVE' };

  /** 위쪽 건수 카드. 누르면 아래 목록을 그 등급만 걸러 보기 (다시 누르면 전체, 0건이면 누를 수 없음) */
  function renderDetailKpis(r) {
    const un = Object.values(r.cveUnpatched).reduce((a, b) => a + b, 0);
    const ap = r.cves.filter(c => c.applicable).length;
    const card = (n, tab, value, el) => {
      const on = dFilter.tab === tab && dFilter.value === value;
      if (n > 0) {
        el.classList.add('clickable');
        el.classList.toggle('selected', on);
        el.setAttribute('role', 'button'); el.setAttribute('tabindex', '0');
        el.setAttribute('aria-pressed', String(on));
        el.title = on ? '다시 누르면 전체 보기' : `누르면 아래 목록을 ${FILTER_LABEL[value]} 항목만 걸러 보기`;
        const act = () => setFilter(r, tab, value);
        el.addEventListener('click', act);
        el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); act(); } });
      }
      return el;
    };
    $('#d-kpis').replaceChildren(
      card(r.counts.risk, 'findings', 'risk', kpi('', r.counts.risk, '건', r.exempt && r.exempt.risk ? `예외 ${r.exempt.risk}건 제외` : null, 'risk')),
      card(r.counts.warn, 'findings', 'warn', kpi('', r.counts.warn, '건', r.exempt && r.exempt.warn ? `예외 ${r.exempt.warn}건 제외` : null, 'warn')),
      card(r.counts.ok, 'findings', 'ok', kpi('', r.counts.ok, '건', null, 'ok')),
      card(ap, 'cves', '1', kpi('해당 CVE', ap, '건', MODSTYLE(r.product) ? `미조치 추정 ${un} / 백포트 추정 ${ap - un}` : `critical ${r.cveApplicable.critical || 0} · high ${r.cveApplicable.high || 0}`)),
      card(r.cves.length - ap, 'cves', '0', kpi('미해당 CVE', r.cves.length - ap, '건', MODSTYLE(r.product) ? `${COND_LABEL(r.product)} 미사용` : '구성요소 없음/다른 프로젝트'))
    );
  }

  function setFilter(r, tab, value) {
    const off = dFilter.tab === tab && dFilter.value === value;
    dFilter = off ? { tab: null, value: null } : { tab, value };
    renderDetailKpis(r);
    renderFindings(r);
    renderCves(r);
    selectTab(tab);
    // 걸러 본 목록이 바로 보이도록 탭 줄을 창 위쪽으로
    const tabs = $('#detail .tabs'), body = $('#detail .dialog-body');
    if (!off && tabs.offsetTop > body.scrollTop + 80) {
      const smooth = !(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
      tabs.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
    }
    const k = $('#d-kpis .kpi.selected'); if (k) k.focus({ preventScroll: true });
  }

  /** 걸러 보는 중일 때 목록 맨 위 안내 줄 */
  function filterBar(r, n) {
    return h('div', { class: 'filter-bar', role: 'status' },
      h('span', null, h('b', null, FILTER_LABEL[dFilter.value]), ` 항목만 보는 중 (${n}건)`),
      h('button', { class: 'btn small', type: 'button', onclick: () => setFilter(r, dFilter.tab, dFilter.value) }, '전체 보기'));
  }

  function renderFindings(r) {
    const panel = $('[data-panel="findings"]');
    const out = [];
    const lv = dFilter.tab === 'findings' ? dFilter.value : null;
    let shown = 0;
    ['4', '3', '1', '2'].forEach(sec => { // 침해 흔적을 가장 먼저
      const items = r.findings.filter(f => f.section === sec && (!lv || (f.level === lv && !f.exempt)))
        .sort((a, b) => STATUS[a.level].rank - STATUS[b.level].rank);
      shown += items.length;
      if (!items.length) return;
      out.push(h('div', { class: 'sec' }, h('h3', null, SECTION_TITLE[sec] || sec),
        ...items.map(f => h('div', { class: 'finding' + (f.exempt ? ' exempt' : '') },
          h('div', null, badge(f.level), f.exempt ? h('span', { class: 'badge b-exempt', title: '예외(위험 수용) — 판정·건수에서 제외' }, '예외') : null),
          h('div', null, f.text,
            f.exempt ? h('div', { class: 'exc-note' },
              `예외: ${f.exempt.reason} · ${f.exempt.scope === 'product' ? (PRODUCTS[f.exempt.product] || f.exempt.product) + ' 전체' : '이 서버'} · ${abs(f.exempt.expiresAt)}까지 · ${f.exempt.by || '?'}`,
              state.me && state.me.admin ? h('button', { class: 'btn-link', type: 'button', onclick: () => removeExc(f.exempt.id) }, '예외 해제') : null)
              : (state.me && state.me.admin && (f.level === 'risk' || f.level === 'warn')
                ? (f.exemptRefuse ? null : h('div', null, h('button', { class: 'btn-link exc-btn', type: 'button', onclick: () => openExc(r, f) }, '예외 처리')))
                : null),
            f.details.length ? h('details', { open: (f.level === 'risk' && !f.exempt) || null },
              h('summary', null, `상세 ${f.details.length}줄`), h('pre', { class: 'details' }, f.details.join('\n'))) : null)))));
    });
    if (lv) out.unshift(filterBar(r, shown));
    panel.replaceChildren(...(shown ? out : [...out, h('p', { class: 'muted' }, lv ? `점검 결과 목록에 ${FILTER_LABEL[lv]} 항목이 없습니다.` : '점검 항목이 없습니다.')]));
  }

  function renderCves(r) {
    const panel = $('[data-panel="cves"]');
    const want = dFilter.tab === 'cves' ? dFilter.value : null;
    const rows = r.cves.filter(c => !want || (c.applicable ? '1' : '0') === want).sort((a, b) =>
      (b.applicable - a.applicable) || (a.backported - b.backported) || SEVERITY[a.severity].rank - SEVERITY[b.severity].rank);
    if (!rows.length) {
      panel.replaceChildren(h('p', { class: 'muted' }, r.product === 'apache' && r.version && !r.version.startsWith('2.4.')
        ? 'CVE 판정 결과가 없습니다. (2.4.x 가 아니라 판정 제외 — EOL 버전은 교체가 근본 대책)' : 'CVE 판정 결과가 없습니다. (CVE 목록 기준으로 해당 없음)'));
      return;
    }
    panel.replaceChildren(
      ...(want ? [filterBar(r, rows.length)] : []),
      h('p', { class: 'muted' }, CVE_NOTE[r.product] + (r.cveDbInfo ? ` (CVE 목록: ${r.cveDbInfo})` : '')),
      h('div', { class: 'table-scroll' }, h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['판정', 'CVE', '등급', '설명', '영향 구간', MODSTYLE(r.product) ? COND_LABEL(r.product) : '설치된 구성요소'].map(t => h('th', null, t)))),
        h('tbody', null, ...rows.map(c => h('tr', null,
          h('td', null, !c.applicable ? h('span', { class: 'badge b-skip' }, '미해당')
            : c.exempt ? h('span', { class: 'badge b-exempt', title: `예외: ${c.exempt.reason} (${abs(c.exempt.expiresAt)}까지)` }, '예외')
            : c.backported ? h('span', { class: 'badge b-backport' }, '백포트 추정') : badge(c.severity === 'critical' || c.severity === 'high' ? 'risk' : 'warn', '해당')),
          h('td', { class: 'mono nowrap' }, h('a', { href: 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(c.id), target: '_blank', rel: 'noopener noreferrer' }, c.id),
            c.advisory ? h('div', { class: 'sub' }, h('a', { href: 'https://osv.dev/vulnerability/' + encodeURIComponent(c.advisory), target: '_blank', rel: 'noopener noreferrer' }, c.advisory)) : null),
          h('td', null, sevBadge(c.severity)),
          h('td', null, c.description || h('span', { class: 'muted' }, '(미해당 항목은 리포트에 설명 없음 — 필요한 모듈·구성요소가 없음)')),
          h('td', { class: 'mono' }, c.affected || '-'),
          h('td', { class: 'mono' }, c.applicable ? (c.condition || '-').replace(/ 설치됨$/, '') : '없음: ' + (c.condition || '-')))))))
    );
  }

  async function renderHistory(r) {
    const panel = $('[data-panel="history"]');
    panel.replaceChildren(h('p', { class: 'muted' }, '점검 이력을 불러오는 중…'));
    let same;
    try { same = (await apiCached('reports?instance=' + encodeURIComponent(r.instanceKey))).data; }
    catch (e) { panel.replaceChildren(h('p', { class: 'muted' }, '점검 이력을 불러오지 못했습니다: ' + e.message)); return; }
    if (!current || current.id !== r.id) return; // 그 사이 다른 리포트를 열었음
    panel.replaceChildren(
      h('p', { class: 'muted' }, '같은 호스트·제품·설치 폴더(실행 파일)·인스턴스 구분의 점검 기록입니다. 재시작해도 같은 인스턴스로 묶입니다. 패치 전/후 비교에 사용하세요.'),
      h('table', { class: 'servers' },
        h('thead', null, h('tr', null, ...['점검 일시', '판정', '버전', '위험', '주의', '양호', '해당 CVE', '파일'].map(t => h('th', null, t)))),
        h('tbody', null, ...same.map(x => h('tr', { class: 'row', onclick: () => openDetail(x.id) },
          h('td', null, x.checkedAt + (x.id === r.id ? ' (현재)' : '')),
          h('td', null, badge(x.status)), h('td', null, x.version || '-'),
          h('td', { class: 'num' }, String(x.counts.risk)), h('td', { class: 'num' }, String(x.counts.warn)),
          h('td', { class: 'num' }, String(x.counts.ok)), h('td', { class: 'num' }, String(cveTotal(x))),
          h('td', { class: 'mono' }, x.id))))));
  }

  /** 지난 점검 대비: 같은 서버의 바로 전 점검과 비교 (ReportDiff) */
  function renderDiff(r) {
    const panel = $('[data-panel="diff"]'), tab = $('#d-diff-tab');
    const d = r.diff;
    if (!d || !d.hasPrevious) {
      tab.textContent = '지난 점검 대비';
      panel.replaceChildren(h('p', { class: 'muted' }, '같은 서버(인스턴스)의 이전 점검 기록이 없어 비교할 수 없습니다. 다음 점검부터 변화가 표시됩니다.'));
      return;
    }
    const plus = d.added.length + d.cveNew.length, minus = d.resolved.length + d.cveResolved.length;
    tab.textContent = `지난 점검 대비 (+${plus} / −${minus})`;
    const row = x => h('div', { class: 'finding' }, h('div', null, badge(x.level)),
      h('div', null, h('span', { class: 'sub' }, (SECTION_TITLE[x.section] || x.section) + ' · '), x.text,
        x.from ? h('span', { class: 'sub' }, ` (이전: ${STATUS[x.from] ? STATUS[x.from].label : x.from})`) : null));
    const block = (title, items, empty, cls) => h('div', { class: 'sec diff-sec ' + (cls || '') },
      h('h3', null, `${title} (${items.length})`),
      ...(items.length ? items.map(row) : [h('p', { class: 'muted' }, empty)]));
    const cves = (title, ids, cls) => h('div', { class: 'sec diff-sec ' + cls }, h('h3', null, `${title} (${ids.length})`),
      ids.length ? h('p', { class: 'mono diff-cves' }, ids.join(', ')) : h('p', { class: 'muted' }, '없음'));
    const pc = d.prevCounts || {};
    panel.replaceChildren(
      h('div', { class: 'diff-head' },
        h('span', null, '비교 대상: ', h('b', null, d.prevCheckedAt || '?'), ' 점검',
          d.prevVersion ? ` · 버전 ${d.prevVersion}${d.versionChanged ? ' → ' + r.version : ''}` : '',
          ` · 위험 ${pc.risk ?? '?'}→${r.counts.risk} · 주의 ${pc.warn ?? '?'}→${r.counts.warn}`),
        h('button', { class: 'btn small', type: 'button', onclick: () => openDetail(d.prevId) }, '이전 점검 열기')),
      block('새로 생긴 위험·주의', d.added, '없음 — 이전 점검에 없던 위험·주의 항목이 없습니다.', 'diff-add'),
      block('해결된 위험·주의', d.resolved, '없음', 'diff-gone'),
      ...(d.levelChanged.length ? [block('등급이 바뀐 항목', d.levelChanged, '', 'diff-chg')] : []),
      cves('새로 해당하는 미조치 CVE', d.cveNew, 'diff-add'),
      cves('해결(또는 백포트)된 CVE', d.cveResolved, 'diff-gone'),
      h('p', { class: 'muted small-note' }, '같은 항목인지 판단할 때 문구 안의 숫자(건수 등)는 무시합니다. 예: "경로 탐색 시도 3건" → "5건" 은 같은 항목으로 봅니다. 미조치 CVE = 해당하면서 패키지 백포트 기록이 없는 것.'));
  }

  // ---------------------------------------------------------------- 예외(위험 수용)
  let excTarget = null;
  function openExc(r, f) {
    excTarget = { report: r.id, section: f.section, text: f.text };
    $('#exc-item').replaceChildren(badge(f.level), ' ', h('span', { class: 'sub' }, (SECTION_TITLE[f.section] || f.section) + ' · '), f.text);
    $('#exc-host').textContent = `(${r.host}${r.binary ? ' · ' + r.binary : ''})`;
    $('#exc-prod').textContent = `(모든 ${PRODUCTS[r.product] || r.product} 서버의 같은 항목)`;
    $('#exc-reason').value = '';
    $('#exc-form').querySelector('input[value="instance"]').checked = true;
    $('#exc-dlg').showModal();
    $('#exc-reason').focus();
  }

  async function submitExc(ev) {
    ev.preventDefault();
    if (!excTarget) return;
    const scope = $('#exc-form').querySelector('input[name="exc-scope"]:checked').value;
    try {
      await api('exceptions', { method: 'POST', body: new URLSearchParams(Object.assign({}, excTarget,
        { scope, days: $('#exc-days').value, reason: $('#exc-reason').value })) });
      $('#exc-dlg').close();
      await afterExcChange();
    } catch (e) { alert(e.message); }
  }

  async function removeExc(id) {
    if (!confirm('이 예외를 해제할까요? 해제하면 다음 화면부터 다시 위험·주의로 집계됩니다.')) return;
    try { await api('exceptions/' + encodeURIComponent(id), { method: 'DELETE' }); await afterExcChange(); }
    catch (e) { alert(e.message); }
  }

  async function afterExcChange() {
    if ($('#detail').open && current) await openDetail(current.id);
    await load();
    await loadExceptions();
  }

  async function loadExceptions() {
    let data;
    try { data = await api('exceptions'); } catch (e) { return; }
    const items = data.items || [];
    const active = items.filter(x => x.active).length;
    $('#exc-count').textContent = items.length ? `유효 ${active}건 / 만료 ${items.length - active}건` : '';
    $('#exc-rows').replaceChildren(...(items.length ? items.map(x => h('tr', { class: x.active ? null : 'muted' },
      h('td', null, x.active ? h('span', { class: 'badge b-exempt' }, '유효') : h('span', { class: 'badge b-skip' }, '만료')),
      h('td', null, badge(x.level), ' ', prodBadge(x.product), ' ', h('span', null, x.text)),
      h('td', null, x.scope === 'product' ? `${PRODUCTS[x.product] || x.product} 전체` : `서버 ${x.host || '?'}`),
      h('td', null, x.reason),
      h('td', { class: 'nowrap' }, h('div', null, x.by || '?'), h('div', { class: 'sub' }, abs(x.createdAt))),
      h('td', { class: 'nowrap', title: abs(x.expiresAt) }, abs(x.expiresAt).split(' ').slice(0, 3).join(' ')),
      h('td', { class: 'admin-only' }, h('button', { class: 'btn small', type: 'button', onclick: () => removeExc(x.id) }, '해제'))))
      : [h('tr', null, h('td', { colspan: '7', class: 'muted' }, '등록된 예외가 없습니다.'))]));
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

  // ---------------------------------------------------------------- 최신 버전 / CVE 목록 / 사이드바 / 침해 의심
  /** 제품의 최신 버전 표시 문자열 (Tomcat 은 "11.0.27 / 10.1.61 / 9.0.123") */
  function latestVer(p) {
    const l = state.latest && state.latest.products && state.latest.products[p];
    return l ? l.display : '?';
  }

  /** PDF 주소의 거르기 조건 (에이전트·제품 필터 반영) */
  function pdfQuery() {
    const q = new URLSearchParams();
    if (state.sourceFilter) q.set('source', state.sourceFilter);
    if (state.product) q.set('product', state.product);
    const s = q.toString();
    return s ? '?' + s : '';
  }

  /** 인스턴스 구분 이름 (hostLabel 과 같은 규칙: Apache -f 설정 파일 / WAS 는 서버 폴더 또는 설치 폴더 이름) */
  function instName(r) {
    if (r.confArg) return r.confArg.length <= 40 ? r.confArg : '…' + r.confArg.slice(-39);
    if (!MODSTYLE(r.product) && r.binary) return r.binary.slice(r.binary.lastIndexOf('/') + 1);
    return null;
  }

  /** 에이전트의 [제품, 버전] 목록 (같은 제품·버전은 한 번만). 사이드바 요약용 */
  function agentVersions(a) {
    if (a.instances && a.instances.length) {
      const seen = new Set();
      return a.instances.map(i => [i.product, i.version || '버전 미확인']).filter(([p, v]) => !seen.has(p + v) && seen.add(p + v));
    }
    return Object.entries(a.versions || {});
  }

  /** 에이전트가 마지막 점검에서 읽은 제품·버전 (인스턴스마다 한 줄) */
  function versionCell(a) {
    const insts = a.instances || [];
    if (insts.length) {
      return h('div', { class: 'ver-list' }, ...insts.map(i => {
        const name = instName(i);
        return h('div', { title: [i.binary, i.confArg].filter(Boolean).join(' · ') || null },
          prodBadge(i.product), ' ', i.version ? i.version : h('span', { class: 'zero' }, '버전 미확인'), ' ',
          !i.version ? null : i.upToDate ? h('span', { class: 'badge b-ok' }, '최신') : h('span', { class: 'badge b-warn' }, '최신 미만'),
          name ? h('span', { class: 'sub mono' }, ' ' + name) : null);
      }));
    }
    const vs = Object.entries(a.versions || {});
    if (!vs.length) return h('span', { class: 'zero' }, '미확인');
    return h('div', { class: 'ver-list' }, ...vs.map(([p, v]) => h('div', null, prodBadge(p), ' ', v, ' ',
      (a.versionUpToDate || {})[p] ? h('span', { class: 'badge b-ok' }, '최신') : h('span', { class: 'badge b-warn' }, '최신 미만'))));
  }

  async function loadLatest() {
    try { state.latest = await api('latest-version'); } catch (e) { return; }
    const L = state.latest;
    const short = Object.values(L.products).map(l => `${l.label} ${l.display.split(' / ')[0].replace(/\.Final$/, '')}${l.display.includes(' / ') ? '…' : ''}`).join(' · ');
    $('#latest-ver-pill').textContent = short;
    $('#latest-ver-pill').title = L.summary;
    $('#brand-sub').textContent = `최신 버전 기준 ${L.summary} · 점검 스크립트 결과`;
    $('#latest-skip').checked = !!L.skipUpToDate;
    const isAdmin = state.me && state.me.admin;
    $('#latest-list').replaceChildren(...Object.values(L.products).map(l => {
      const host = (() => { try { return new URL(l.source).host; } catch (e) { return l.source; } })();
      let origin;
      if (l.origin === 'manual') origin = '관리자가 직접 지정한 값';
      else if (l.origin === 'auto') origin = `자동 확인 · ${host} · ${rel(l.autoSuccessAt)}`;
      else origin = '자동 확인 전/실패 → 점검 스크립트 기준값 사용';
      const warns = [];
      if (l.autoError && l.origin !== 'manual') {
        warns.push(h('div', { class: 'side-warn' }, `자동 확인 실패: ${l.autoError}`,
          h('div', { class: 'muted' }, '내부망이라 인터넷이 막혀 있으면 [직접 지정]으로 버전을 넣으세요.')));
      }
      return h('div', { class: 'latest-row' },
        h('div', { class: 'latest-head' }, prodBadge(l.product), h('span', { class: 'latest-ver' }, l.display)),
        h('div', { class: 'muted side-sub', title: l.autoCheckedAt ? `마지막 확인 시도: ${abs(l.autoCheckedAt)}` : '' }, origin),
        ...warns,
        isAdmin ? h('div', { class: 'side-actions' },
          h('button', { class: 'btn small', type: 'button', onclick: () => latestAction({ action: 'refresh', product: l.product }) }, icon('refresh'), '지금 확인'),
          h('button', { class: 'btn small', type: 'button', onclick: () => {
            const v = prompt(`최신 버전으로 쓸 ${l.label} 버전을 입력하세요 (예: ${l.example})`, l.display.replace(/ \/ /g, ', '));
            if (v) latestAction({ action: 'manual', product: l.product, version: v.trim() });
          } }, '직접 지정'),
          l.mode === 'manual' ? h('button', { class: 'btn small', type: 'button', onclick: () => latestAction({ action: 'auto', product: l.product }) }, '자동으로 되돌리기') : null) : null);
    }));
  }

  async function latestAction(params) {
    try { state.latest = await api('latest-version', { method: 'POST', body: new URLSearchParams(params) }); }
    catch (e) { alert(e.message); }
    await refreshAll();
  }

  /** CVE 목록 자동 업데이트 상태 (설정 화면) */
  async function loadCveFeed() {
    let f;
    try { f = await api('cve-feed'); } catch (e) { return; }
    $('#cve-feed-state').textContent = !f.auto ? '자동 업데이트 꺼짐 (-Dwebwas.precheck.cve.auto=false) — 스크립트 내장 목록만 사용'
      : f.running ? '지금 받는 중…' : '12시간마다 자동 갱신 · 에이전트는 점검할 때마다 최신 목록을 받아 씁니다';
    $('#btn-cve-refresh').disabled = !!f.running || !f.auto;
    $('#cve-feed-rows').replaceChildren(...Object.entries(f.products).map(([p, x]) => {
      const host = (() => { try { return new URL(x.source).host || x.source; } catch (e) { return x.source; } })();
      return h('tr', null,
        h('td', null, prodBadge(p)),
        h('td', null, x.using === 'generated'
          ? h('span', null, h('span', { class: 'badge b-ok' }, '자동 업데이트본'), h('div', { class: 'sub', title: abs(x.generatedAt) }, `${rel(x.generatedAt)} · ${host}`))
          : h('span', null, h('span', { class: 'badge b-info' }, '스크립트 내장본'), h('div', { class: 'sub' }, x.embeddedNote ? x.embeddedNote + ' 기준' : ''))),
        h('td', { class: 'num nowrap' }, `${x.cveCount}건`, x.addedCves ? h('div', { class: 'sub' }, `내장 대비 +${x.addedCves}`) : null),
        h('td', null, x.error ? h('span', { class: 'badge b-warn', title: x.error }, h('span', { class: 'ic' }, '!'), '최근 갱신 실패') : x.checkedAt ? h('span', { class: 'muted', title: abs(x.checkedAt) }, rel(x.checkedAt)) : h('span', { class: 'zero' }, '-'),
          x.error ? h('div', { class: 'sub msg' }, x.error) : null),
        h('td', null, h('a', { class: 'btn small', href: `agent-api/cve/${p}`, download: `${p}_cve.txt`, title: `직접 실행할 때: sudo bash ${p}_precheck.sh -C ${p}_cve.txt` }, icon('file'), '받기')));
    }));
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
    const SIDE_MAX = 15;
    const more = sorted.length - SIDE_MAX;
    ul.replaceChildren(...sorted.slice(0, SIDE_MAX).map(a => {
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
          (() => { const t = meta + agentVersions(a).map(([p, v]) => ` · ${PRODUCTS[p]} ${v.replace(/\.Final$/, '')}`).join('') + (rep ? ` · 점검 ${rel(rep.fileModified, now)}` : '');
            return h('span', { class: 'sched-meta', title: t }, t); })()),
        rep && rep.intrusion === 'compromise' ? badge('compromise')
          : h('span', { class: 'badge ' + st.cls }, h('span', { class: 'ic', 'aria-hidden': 'true' }, st.icon), st.label)));
    }), ...(more > 0 ? [h('li', { class: 'side-more' }, h('button', { class: 'btn-link', type: 'button', onclick: () => { showView('agents'); loadAgents(); } },
      `외 ${more}대 — 에이전트 화면에서 전체 보기`))] : [])); // (replaceChildren 에 null 을 넘기면 글자 "null" 이 됨)
  }

  /** 인스턴스별 최신 리포트 중 [4] 침해 흔적에 위험/주의가 있는 것 */
  function renderSuspects() {
    const seen = new Set();
    const latest = state.reports.filter(r => { if (seen.has(r.instanceKey)) return false; seen.add(r.instanceKey); return !state.product || r.product === state.product; });
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
          prodBadge(r.product), h('span', { class: 'muted' }, prodVer(r)), h('span', { class: 'muted' }, r.checkedAt || ''),
          h('span', { class: 'muted' }, r.source ? `에이전트 ${r.source}` : '수동 업로드')),
        h('ul', { class: 'suspect-findings' }, ...r.intrusionFindings.slice(0, 3).map(f => h('li', null, badge(f.level), ' ', f.text)),
          r.intrusionFindings.length > 3 ? h('li', { class: 'muted' }, `외 ${r.intrusionFindings.length - 3}건`) : null)),
      h('div', { class: 'suspect-actions' },
        h('button', { class: 'btn small', type: 'button', onclick: () => openDetail(r.id) }, '상세'),
        h('a', { class: 'btn small' + (r.intrusion === 'compromise' ? ' btn-danger' : ''), href: 'api/reports/' + encodeURIComponent(r.id) + '/intrusion.pdf', download: '' }, 'PDF')));
    const out = [];
    if (!comp.length) out.push(h('p', { class: 'muted none-msg' }, state.reports.length ? '침해 의심 서버가 없습니다. (서버별 최신 점검 기준)' : '점검 결과가 아직 없습니다.'));
    const LIST_MAX = 4; // 서버가 많으면 목록이 화면을 다 차지하지 않도록 (나머지는 서버 목록에서)
    out.push(...comp.slice(0, LIST_MAX).map(row));
    if (comp.length > LIST_MAX) out.push(h('p', null, h('button', { class: 'btn small', type: 'button', onclick: () => setStatusFilter('compromise') },
      `외 ${comp.length - LIST_MAX}대 — 서버 목록에서 침해 의심만 보기`)));
    if (check.length) {
      out.push(h('details', { class: 'check-group' }, h('summary', null, `확인 필요 ${check.length}대 — [4]에 [주의] 항목(스캔 시도, 최근 변경 파일 등)`),
        ...check.slice(0, 20).map(row), check.length > 20 ? h('p', { class: 'muted' }, `외 ${check.length - 20}대는 서버 목록에서 확인하세요.`) : null));
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
    renderAgentUrl();
    const now = data.now;
    const count = {};
    data.agents.forEach(a => { count[a.state] = (count[a.state] || 0) + 1; });
    $('#agents-summary').textContent = data.agents.length
      ? Object.entries(AGENT_STATE).filter(([k]) => count[k]).map(([k, v]) => `${v.label} ${count[k]}`).join(' · ')
      : '';
    const rows = data.agents.map(a => {
      const st = AGENT_STATE[a.state] || AGENT_STATE.never;
      const next = a.intervalHours === 0 ? '수동만' : a.lastReportAt ? rel(a.nextRunAt, now) : '설치 후 바로';
      const scriptBadge = a.scriptMatches === null || a.scriptMatches === undefined ? h('span', { class: 'zero' }, '-')
        : a.scriptMatches ? h('span', { class: 'badge b-ok' }, '대시보드와 같음')
          : h('span', { class: 'badge b-warn', title: `에이전트: ${a.scriptSha256}\n대시보드: ${data.expectedScriptSha256}` }, h('span', { class: 'ic' }, '!'), '다름');
      // 점검 스크립트가 같아도 에이전트 본체가 옛 버전이면 새 기능(예: 서버 로그 위치 -s 전달)이 동작하지 않음
      const scriptCell = h('div', null, scriptBadge,
        a.agentVersion ? h('div', { class: 'sub' + (a.agentOutdated ? ' warn-ink' : ''),
          title: a.agentOutdated ? `대시보드의 에이전트는 ${data.expectedAgentVersion} 입니다. 에이전트를 재설치하세요.` : null },
          `에이전트 ${a.agentVersion}`, a.agentOutdated ? ` → ${data.expectedAgentVersion} 재설치 필요` : '') : null);
      const lastRun = a.lastRunAt
        ? h('div', null, h('span', { title: abs(a.lastRunAt) }, rel(a.lastRunAt, now)), ' ',
          a.lastExit === 0 || (a.lastReportCount > 0 && a.lastExit !== 124) ? null : h('span', { class: 'badge b-risk' }, `실패(exit ${a.lastExit})`),
          a.lastMessage ? h('div', { class: 'msg' }, a.lastMessage) : null)
        : h('span', { class: 'zero' }, '아직 없음');
      const actions = h('td', { class: 'admin-only' }, h('div', { class: 'row-actions' },
        h('button', { class: 'btn small', type: 'button', disabled: a.state === 'running' || a.state === 'requested' || (a.state === 'offline' && a.pendingRun) || null,
          title: a.state === 'offline' ? '에이전트가 오프라인이면 요청만 저장되고, 다시 접속할 때 시작합니다' : null,
          onclick: () => agentRun(a.name, a.state) },
          a.state === 'running' ? '점검 중' : a.state === 'requested' || a.pendingRun ? '요청됨' : '지금 점검'),
        h('select', { 'aria-label': `${a.name} 점검 주기`, onchange: e => agentInterval(a.name, e.target.value) },
          ...INTERVALS.map(([v, l]) => h('option', { value: String(v), selected: v === a.intervalHours || null }, l))),
        h('button', { class: 'btn small', type: 'button', onclick: () => agentGroup(a.name, a.group) }, '그룹'),
        h('button', { class: 'btn small', type: 'button', onclick: () => agentToken(a.name) }, '토큰 재발급'),
        h('button', { class: 'btn small btn-danger', type: 'button', title: '이 에이전트가 보낸 점검 기록과 상태를 초기화 (등록·토큰은 유지)',
          onclick: () => resetRecords('agent', a.name, `${a.name} 에이전트 기록 초기화`, { agentState: 'true' }) }, '기록 초기화'),
        h('button', { class: 'btn small btn-danger', type: 'button', onclick: () => agentDelete(a.name) }, '삭제')));
      return h('tr', null,
        h('td', null, h('span', { class: 'badge ' + st.cls }, h('span', { class: 'ic', 'aria-hidden': 'true' }, st.icon), st.label),
          a.state === 'offline' && a.pendingRun ? h('div', { class: 'sub', title: '에이전트가 다시 접속하면 바로 점검을 시작합니다' }, '점검 요청됨 · 접속 대기') : null,
          a.authFailAt ? h('div', { class: 'sub warn-ink', title: `${abs(a.authFailAt)} · 접속 IP ${a.authFailIp || '?'}` },
            a.authLocked ? '토큰 인증 실패 반복 → 잠시 차단됨' : '토큰 인증 실패 중', ` (${rel(a.authFailAt, now)}, ${a.authFailIp || '?'}) → 토큰 재발급 필요`) : null),
        h('td', null, h('div', null, a.name,
          a.group ? h('span', { class: 'badge b-group', title: `그룹: ${a.group}` }, a.group) : null),
          h('div', { class: 'sub mono' }, [a.hostname, a.ip].filter(Boolean).join(' · ') || '아직 접속 안 함')),
        h('td', { title: abs(a.lastSeen) }, rel(a.lastSeen, now)),
        h('td', null, lastRun),
        h('td', null, versionCell(a)),
        h('td', null, a.autoSkipped && a.intervalHours > 0 ? h('span', { class: 'muted', title: '최신 버전이라 자동 점검 제외 (지금 점검은 가능)' }, '제외(최신)') : next),
        h('td', null, (INTERVALS.find(([v]) => v === a.intervalHours) || [0, `${a.intervalHours}시간`])[1]),
        h('td', null, scriptCell),
        actions);
    });
    if (!rows.length) rows.push(h('tr', null, h('td', { colspan: '9', class: 'muted' },
      state.me.admin ? '등록된 에이전트가 없습니다. [에이전트 추가]로 점검할 서버(Apache·WildFly·Tomcat)에 에이전트를 설치하세요.' : '등록된 에이전트가 없습니다.')));
    $('#agents tbody').replaceChildren(...rows);
    renderReinstall(data);
    const rsel = $('#r-agent');
    if (rsel) {
      const keep = rsel.value;
      rsel.replaceChildren(h('option', { value: '' }, '— 고르세요 —'), ...data.agents.map(a => h('option', { value: a.name, selected: a.name === keep || null }, a.name)));
    }
    renderAgentAlert();
    renderSideAgents();
    renderAgentTiles();
  }

  /** 화면 위 알림: 3분 넘게 접속하지 않은 에이전트 (점검 결과가 끊길 수 있으므로 개요·서버 목록에서도 바로 보이게) */
  function renderAgentAlert() {
    const box = $('#agent-alert');
    const list = ((state.agents && state.agents.agents) || []).filter(a => a.state === 'offline');
    if (!list.length) { box.hidden = true; return; }
    const now = state.agents.now;
    list.sort((a, b) => a.lastSeen - b.lastSeen); // 오래 끊긴 것부터
    const SHOW = 5;
    box.replaceChildren(
      h('b', null, `오프라인 에이전트 ${list.length}대`),
      ` — 3분 넘게 대시보드에 접속하지 않았습니다. 점검 결과가 더 이상 갱신되지 않을 수 있습니다. `,
      h('span', { class: 'mono' }, list.slice(0, SHOW).map(a => `${a.name}(${rel(a.lastSeen, now)}${a.authFailAt ? ', 토큰 인증 실패 중' : ''})`).join(', ')),
      list.length > SHOW ? ` 외 ${list.length - SHOW}대` : '', ' ',
      h('button', { class: 'btn small', type: 'button', onclick: () => { showView('agents'); loadAgents(); } }, '에이전트 화면에서 보기'),
      h('div', { class: 'muted small-note' }, '확인 방법: 그 서버에서 sudo systemctl status webwas-precheck-agent.timer / sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh test'));
    box.hidden = false;
  }

  /** HTTP 로 접속 중이면 관리자에게 경고 (비밀번호·점검 결과가 암호화되지 않음) */
  function renderHttpAlert() {
    const box = $('#http-alert');
    const insecure = state.me && !state.me.secure && location.protocol === 'http:' && !/^(localhost|127\.)/.test(location.hostname);
    let dismissed = false;
    try { dismissed = sessionStorage.getItem('precheck.httpAlert') === 'off'; } catch (e) { /* 저장 불가 */ }
    if (!insecure || !state.me.admin || dismissed) { box.hidden = true; return; }
    box.replaceChildren(h('b', null, 'HTTP 로 접속 중'),
      ' — 로그인 비밀번호, 에이전트 토큰, 점검 결과가 암호화되지 않은 채 네트워크로 오갑니다. README 의 "HTTPS 적용" 순서대로 HTTPS 를 켜 주세요. ',
      h('button', { class: 'btn small', type: 'button', onclick: () => { try { sessionStorage.setItem('precheck.httpAlert', 'off'); } catch (e) { /* 무시 */ } box.hidden = true; } }, '이번 접속 동안 숨기기'));
    box.hidden = false;
  }

  /** 브라우저 주소창 기준 대시보드 주소 */
  function browserUrl() {
    return new URL('.', location.href).href.replace(/\/$/, '');
  }
  /** 설치 명령에 넣을 주소: 설정의 "에이전트 접속 주소" 가 있으면 그것, 없으면 브라우저 주소 */
  function dashboardUrl() {
    return (state.agents && state.agents.agentUrl) || browserUrl();
  }

  function renderAgentUrl() {
    const saved = (state.agents && state.agents.agentUrl) || '';
    const input = $('#agurl-input');
    if (document.activeElement !== input) input.value = saved;
    const url = dashboardUrl();
    $('#agurl-meta').textContent = saved ? '직접 지정한 주소 사용' : '브라우저 주소 사용';
    $('#agurl-check').replaceChildren(
      h('p', { class: 'muted small-note' }, '설치 명령에 들어가는 주소: ', h('b', { class: 'mono' }, url)),
      h('p', { class: 'muted small-note' }, '점검할 서버에서 먼저 연결을 확인하세요. 200 이 나오면 정상입니다 (000 = 연결 안 됨 → 방화벽·포트 확인, 404 = 주소 뒤 경로 확인).'),
      codeBox(`curl -s -o /dev/null -w "%{http_code}\\n" ${url}/agent-api/files/install.sh`),
      url.startsWith('http://') ? h('p', { class: 'muted small-note warn-ink' },
        'http 주소라 에이전트 토큰·점검 결과가 암호화되지 않고 오갑니다. 내부망에서만 쓰고, 가능하면 https 주소를 쓰세요.') : null);
  }

  async function saveAgentUrl(v) {
    try {
      const r = await api('agent-url', { method: 'POST', body: new URLSearchParams({ url: v }) });
      if (state.agents) state.agents.agentUrl = r.agentUrl;
      $('#agurl-input').value = r.agentUrl;
      renderAgentUrl();
    } catch (e) { alert(e.message); }
  }

  /** 서버에서 붙여 넣을 재설치 명령 (기존 설정 파일에서 주소·이름·토큰을 읽고, 빈 폴더에 install.sh 를 받아 실행) */
  const REINSTALL_CMD = [
    'F=/etc/webwas-precheck-agent.conf',
    'U=$(sed -n "s/^DASHBOARD_URL=\'\\(.*\\)\'$/\\1/p" $F)',
    'N=$(sed -n "s/^AGENT_NAME=\'\\(.*\\)\'$/\\1/p" $F)',
    'T=$(sed -n "s/^AGENT_TOKEN=\'\\(.*\\)\'$/\\1/p" $F)',
    'C=$(sed -n "s/^CA_CERT=\'\\(.*\\)\'$/\\1/p" $F)',
    'D=$(mktemp -d)',
    'echo "대시보드: $U / 에이전트: $N / 받는 폴더: $D"',
    'curl -fsSo "$D/install.sh" ${C:+--cacert "$C"} "$U/agent-api/files/install.sh" && PRECHECK_AGENT_TOKEN="$T" bash "$D/install.sh" "$U" "$N" ${C:+--ca-cert "$C"}'
  ].join('\n');

  function renderReinstall(data) {
    const card = $('#reinstall-card');
    if (!card) return;
    const need = data.agents.filter(a => a.scriptMatches === false || a.agentOutdated);
    card.hidden = !need.length;
    if (!need.length) return;
    $('#reinstall-count').textContent = `${need.length}대 / 전체 ${data.agents.length}대`;
    $('#reinstall-list').replaceChildren(...need.map(a => h('li', null, h('b', null, a.name), ' ',
      h('span', { class: 'sub mono' }, [a.hostname, a.ip].filter(Boolean).join(' · ')), ' — ',
      [a.scriptMatches === false ? '점검 스크립트가 대시보드와 다름' : null,
        a.agentOutdated ? `에이전트 ${a.agentVersion} → ${data.expectedAgentVersion}` : null].filter(Boolean).join(', '),
      a.state === 'offline' || a.state === 'never' ? h('span', { class: 'sub warn-ink' }, ' (지금 오프라인 — 서버 상태부터 확인)') : null)));
    $('#reinstall-cmd').replaceChildren(codeBox(REINSTALL_CMD),
      h('p', { class: 'muted small-note' }, '확인: 설치 출력에 "대시보드에서 받음" 과 "설치 완료" 가 보여야 합니다. 대시보드 주소가 예전 주소로 나오면 실행을 멈추고 /etc/webwas-precheck-agent.conf 의 DASHBOARD_URL 부터 고치세요.'));
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
          ? h('li', null, h('p', null, '그 서버에서 아래 명령으로 설정 파일의 토큰만 바꿉니다. (또는 아래 2~3단계로 다시 설치)'),
            codeBox(`sudo sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN='${token}'|" /etc/webwas-precheck-agent.conf && sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh test`))
          : null,
        h('li', null, h('p', null, '점검할 서버(Apache·WildFly·Tomcat·Nginx 중 하나 이상이 도는 서버)에 root 권한이 있는 계정으로 접속해 아래 한 줄을 실행합니다. '
          + '한 서버에 여러 제품이 있어도 에이전트는 하나만 설치하면 됩니다(실행 중인 제품을 자동으로 찾아 각각 점검). '
          + '설치 파일은 매번 새로 만든 빈 폴더에 받습니다 — /tmp 에 예전 점검 스크립트가 남아 있으면 install.sh 가 그 파일을 먼저 써서 옛 버전이 설치되기 때문입니다.'),
          codeBox(`D=$(mktemp -d) && curl -fsSo "$D/install.sh" ${url}/agent-api/files/install.sh && sudo bash "$D/install.sh" ${url} ${name}`)),
        h('li', null, h('p', null, '토큰을 물어보면 아래 토큰을 붙여 넣고 Enter 를 누릅니다. 출력에 "대시보드에서 받음" 과 "설치 완료" 가 보여야 합니다.'), codeBox(token)),
        h('li', null, h('p', null, '"설치 완료"가 나오면 1~2분 안에 이 화면의 상태가 "온라인"이 되고, 첫 점검이 자동으로 시작됩니다.'))),
      h('p', { class: 'muted' }, `※ 명령의 주소(${url})는 ${state.agents && state.agents.agentUrl ? '에이전트 화면의 [에이전트 접속 주소]에 지정한 값' : '지금 브라우저 주소'}입니다. 점검할 서버에서 이 주소로 접속할 수 있어야 합니다(방화벽 확인). 다르면 에이전트 화면 위쪽 [에이전트 접속 주소]에서 바꾸세요. `
        + 'HTTP 주소면 토큰과 설치 파일이 암호화되지 않은 채 오가므로, 대시보드에 HTTPS 를 켰다면 https 주소와 --ca-cert 옵션을 쓰는 것이 안전합니다. '
        + '대시보드에 연결할 수 없는 서버는 install.sh, webwas-precheck-agent.sh, apache_precheck.sh, wildfly_precheck.sh, tomcat_precheck.sh, nginx_precheck.sh 여섯 파일을 빈 폴더에 함께 복사한 뒤 그 폴더에서 install.sh 를 실행하면 됩니다.'));
    box.hidden = false;
  }

  async function agentRun(name, st) {
    try {
      await api('agents/' + encodeURIComponent(name) + '/run', { method: 'POST' });
      await loadAgents();
      if (st === 'offline' || st === 'never') {
        alert(`${name} 점검을 요청했습니다.\n\n다만 이 에이전트는 지금 ${st === 'never' ? '한 번도 접속하지 않은' : '오프라인'} 상태라 바로 시작되지 않습니다. `
          + '에이전트가 다시 접속하면(1분 간격) 그때 시작합니다.\n\n그 서버에서 확인: sudo systemctl status webwas-precheck-agent.timer / sudo /opt/webwas-precheck-agent/webwas-precheck-agent.sh test');
      }
    } catch (e) { alert(e.message); }
  }
  async function agentInterval(name, hours) {
    try { await api('agents/' + encodeURIComponent(name) + '/interval', { method: 'POST', body: new URLSearchParams({ hours }) }); await loadAgents(); }
    catch (e) { alert(e.message); }
  }
  async function agentGroup(name, current) {
    const v = prompt(`${name} 서버의 그룹 이름을 입력하세요. (같은 이름끼리 묶여서 보입니다. 예: HAPPY)\n비워 두면 그룹에서 빼냅니다.`, current || '');
    if (v === null) return; // 취소
    try {
      await api('agents/' + encodeURIComponent(name) + '/group', { method: 'POST', body: new URLSearchParams({ group: v }) });
      await loadAgents();
      await load(); // 서버 목록·필터에도 반영
    } catch (e) { alert(e.message); }
  }

  async function agentToken(name) {
    if (!confirm(`${name} 토큰을 재발급할까요? 기존 토큰은 바로 사용할 수 없게 되어, 그 서버의 설정을 바꾸기 전까지 에이전트가 접속하지 못합니다.`)) return;
    try {
      const r = await api('agents/' + encodeURIComponent(name) + '/token', { method: 'POST' });
      $('#ag-title').textContent = '토큰 재발급';
      $('#agent-form').hidden = true;
      showInstall(r.name, r.token, true);
      $('#agent-dlg').showModal();
    } catch (e) { alert(e.message); }
  }
  /**
   * 점검 기록 초기화: 먼저 미리보기로 건수를 보여 주고, '초기화' 를 직접 입력해야 실행.
   * scope = instance | agent | product | old | all (ReportReset 과 같음)
   */
  async function resetRecords(scope, value, title, extra) {
    const body = new URLSearchParams(Object.assign({ scope, value: value == null ? '' : String(value) }, extra || {}));
    let pv;
    try { pv = await api('reset', { method: 'POST', body: new URLSearchParams([...body, ['dryRun', 'true']]) }); }
    catch (e) { alert(e.message); return false; }
    if (!pv.count && !(extra && extra.agentState === 'true')) { alert(`${title}: 지울 점검 기록이 없습니다.`); return false; }
    const sample = (pv.sample || []).map(s => ' · ' + s).join('\n');
    const word = prompt(`${title}\n\n점검 기록 ${pv.count}건 (서버 ${pv.instances}대)을 지웁니다.`
      + (sample ? `\n${sample}${pv.count > 5 ? '\n · …' : ''}` : '')
      + (extra && extra.agentState === 'true' ? '\n\n에이전트 상태(마지막 점검·버전·메시지)도 초기화합니다. 자동 점검 주기가 있으면 1분 안에 다시 점검합니다.' : '')
      + `\n\n지운 기록은 휴지통(reports-trash)에 ${pv.trashDays}일 동안 보관됩니다.\n계속하려면 초기화 라고 입력하세요.`);
    if (word === null) return false;
    if (word.trim() !== '초기화') { alert("입력한 문구가 '초기화' 가 아니라 취소했습니다."); return false; }
    try {
      const r = await api('reset', { method: 'POST', body: new URLSearchParams([...body, ['confirm', '초기화']]) });
      alert(`${title}: ${r.count}건을 휴지통으로 옮겼습니다.` + (r.agentReset ? '\n에이전트 상태도 초기화했습니다.' : '') + (r.trash ? `\n(휴지통 폴더: reports-trash/${r.trash})` : ''));
      await load();
      if (state.me && state.me.admin) await loadAgents();
      return true;
    } catch (e) { alert(e.message); return false; }
  }

  async function agentDelete(name) {
    if (!confirm(`${name} 에이전트를 삭제할까요? 이미 받은 리포트는 남습니다. 서버의 에이전트는 'sudo bash /tmp/webwas-precheck-install.sh --uninstall' 로 따로 삭제하세요.`)) return;
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
    if (name === 'settings') loadExceptions();
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
  /** 일자별 [점검 건수, 침해 의심 건수] (서버 집계 /api/daily 를 제품·에이전트 필터로 거름) */
  function dailyCounts(days) {
    const rows = (state.daily && state.daily.rows) || [];
    const idx = new Map(days.map((d, i) => [d, i]));
    const cnt = days.map(() => 0), comp = days.map(() => 0);
    rows.forEach(([d, prod, src, n, c]) => {
      if (!idx.has(d)) return;
      if (state.product && prod !== state.product) return;
      if (state.sourceFilter && src !== state.sourceFilter) return;
      cnt[idx.get(d)] += n; comp[idx.get(d)] += c;
    });
    return { cnt, comp };
  }

  // ---------------------------------------------------------------- 서버 현황판 (타일) — 서버 수백 대용
  /** 점검이 이 일수보다 오래되면 빗금으로 표시 */
  const STALE_DAYS = 3;
  const HERO_STATUS = ['compromise', 'risk', 'warn', 'ok'];
  const heroState = { view: loadPref('precheck.heroView', ''), group: loadPref('precheck.heroGroup', 'status'), q: '', hidden: new Set(), open: new Map() };
  /** 이 대수를 넘는 "양호" 묶음은 처음에 접어 둠 (할 일이 있는 서버가 먼저 보이도록) */
  const COLLAPSE_OK = 60;
  function loadPref(k, d) { try { return localStorage.getItem(k) || d; } catch (e) { return d; } }
  function savePref(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* 저장 불가 환경 */ } }

  /** 같은 서버(호스트 + IP)의 인스턴스를 하나로 묶음. 가장 나쁜 판정 = 서버 판정 */
  function groupServers(list) {
    const byServer = new Map();
    list.forEach(r => {
      const key = r.host + '|' + (r.ip || '');
      if (!byServer.has(key)) byServer.set(key, { key, host: r.host, ip: r.ip, ipFromAgent: r.ipFromAgent, inst: [] });
      byServer.get(key).inst.push(r);
    });
    const rankOf = r => STATUS[r.status].rank;
    const servers = Array.from(byServer.values());
    servers.forEach(g => {
      // 아래층 → 위층 순서 (입체 배치도용). 가장 나쁜 판정이 맨 뒤
      g.inst.sort((a, b) => rankOf(b) - rankOf(a) || a.product.localeCompare(b.product) || (a.binary || '').localeCompare(b.binary || '') || (a.confArg || '').localeCompare(b.confArg || ''));
      g.worst = g.inst[g.inst.length - 1];
      g.status = g.worst.status;
      g.products = Array.from(new Set(g.inst.map(r => r.product))).sort((a, b) => Object.keys(PRODUCTS).indexOf(a) - Object.keys(PRODUCTS).indexOf(b));
      g.checked = g.inst.map(r => r.checkedAt || '').sort()[0] || '';   // 가장 오래된 점검
      g.sources = Array.from(new Set(g.inst.map(r => r.source || '')));
    });
    return servers.sort((a, b) => rankOf(a.worst) - rankOf(b.worst) || a.host.localeCompare(b.host, 'ko', { numeric: true }));
  }

  function isStale(checkedAt) {
    if (!checkedAt) return true;
    const t = Date.parse(checkedAt.replace(' ', 'T'));
    return !isNaN(t) && Date.now() - t > STALE_DAYS * 86400000;
  }

  function renderHero(list) {
    const servers = groupServers(list);
    let view = heroState.view;
    if (view !== 'board' && view !== 'iso') view = servers.length > 24 ? 'board' : 'iso'; // 처음엔 서버 수로 자동 선택
    $$('[data-hview]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.hview === view)));
    $('#hero-tools').hidden = view !== 'board';
    $('.dash').classList.toggle('board-mode', view === 'board');
    if (view === 'iso') {
      $('#hero-hint').textContent = `서버 ${servers.length}대 전체 · 서버(호스트·IP)마다 상자 하나, 층 하나가 인스턴스 하나입니다. 위험한 서버일수록 위쪽에 놓입니다. `
        + '층을 누르면 상세 결과가 열립니다.' + (servers.length > 24 ? ' 서버가 많아 처음엔 작게 보이니 확대해서 보세요. 이름으로 찾기·묶기는 [타일] 보기가 편합니다.' : '');
      $('#hero-map').className = 'hero-map';
      legend('#legend-hero', [['c-critical', '침해 의심'], ['c-serious', '위험'], ['c-warning', '주의'], ['c-good', '양호']]);
      renderHeroMap(list);
    } else {
      $('#hero-map').className = 'board';
      renderBoard(servers, list.length);
    }
  }

  /** 묶음 이름과 순서 */
  function boardGroups(servers) {
    const mode = heroState.group;
    const groups = new Map();
    const add = (key, label, order, s) => {
      if (!groups.has(key)) groups.set(key, { key, label, order, items: [] });
      groups.get(key).items.push(s);
    };
    servers.forEach(s => {
      if (mode === 'status') add(s.status, STATUS[s.status].label, STATUS[s.status].rank, s);
      else if (mode === 'product') {
        const k = s.products.join('+');
        add(k, s.products.map(p => PRODUCTS[p]).join(' + '), s.products.length > 1 ? 10 : Object.keys(PRODUCTS).indexOf(s.products[0]), s);
      } else if (mode === 'agent') {
        const src = s.sources.filter(Boolean)[0];
        add(src || '', src ? `에이전트 ${src}` : '수동 업로드', src ? 0 : 1, s);
      } else if (mode === 'subnet') {
        const m = (s.ip || '').match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
        const k = m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : 'IP 미확인';
        add(k, k, m ? 0 : 1, s);
      } else add('all', '전체', 0, s);
    });
    const ipNum = k => k.split(/[./]/).slice(0, 3).reduce((a, n) => a * 256 + (+n || 0), 0);
    return Array.from(groups.values()).sort((a, b) => a.order - b.order
      || (mode === 'subnet' ? ipNum(a.key) - ipNum(b.key) : a.label.localeCompare(b.label, 'ko', { numeric: true })));
  }

  function renderBoard(servers, nInst) {
    const box = $('#hero-map');
    const q = heroState.q.trim().toLowerCase();
    const cnt = k => servers.filter(s => s.status === k).length;
    // 판정 칩: 눌러서 숨기기/보이기 (색 + 기호 + 이름 + 대수)
    $('#legend-hero').replaceChildren(...HERO_STATUS.map(k => h('button', {
      type: 'button', class: 'bchip s-' + k, 'aria-pressed': String(!heroState.hidden.has(k)),
      title: heroState.hidden.has(k) ? `${STATUS[k].label} 서버 보이기` : `${STATUS[k].label} 서버 숨기기`,
      onclick: () => { heroState.hidden.has(k) ? heroState.hidden.delete(k) : heroState.hidden.add(k); render(); }
    }, h('span', { class: 'bchip-ic', 'aria-hidden': 'true' }, STATUS[k].icon), STATUS[k].label, h('b', null, String(cnt(k))))));

    const visible = servers.filter(s => !heroState.hidden.has(s.status));
    const match = s => !q || [s.host, s.ip, ...s.inst.map(r => r.version)].some(v => (v || '').toLowerCase().includes(q));
    const nMatch = q ? visible.filter(match).length : visible.length;
    const stale = servers.filter(s => isStale(s.checked)).length;
    $('#hero-hint').replaceChildren(
      `서버 ${servers.length}대 · 인스턴스 ${nInst}개`,
      heroState.hidden.size ? ` · 표시 ${visible.length}대` : '',
      q ? ` · 검색 일치 ${nMatch}대` : '',
      stale ? h('span', { class: 'hint-stale' }, ` · 빗금 = ${STALE_DAYS}일 넘게 점검 안 됨 ${stale}대`) : '',
      ' · 칸 하나가 서버 1대(색과 기호 = 그 서버에서 가장 나쁜 판정, 아래 띠 = 인스턴스별 판정). 누르면 상세가 열립니다.');

    if (!servers.length) {
      box.replaceChildren(h('p', { class: 'muted none-msg' }, state.reports.length ? '조건에 맞는 서버가 없습니다.' : '점검 결과가 아직 없습니다.'));
      return;
    }
    let first = true;
    const groups = boardGroups(visible).map(g => {
      const byStatus = HERO_STATUS.map(k => [k, g.items.filter(s => s.status === k).length]).filter(([, n]) => n);
      const tiles = g.items.map(s => {
        const hit = match(s);
        const t = h('button', {
          type: 'button', class: 'btile s-' + s.status + (isStale(s.checked) ? ' stale' : '') + (hit ? '' : ' dim') + (q && hit ? ' hit' : ''),
          tabindex: first ? '0' : '-1',
          'aria-label': `${s.host}${s.ip ? ' ' + s.ip : ''}, ${STATUS[s.status].label}, ${s.inst.map(prodVer).join(', ')}`,
          onclick: () => openServer(s)
        }, h('span', { class: 'btile-ic', 'aria-hidden': 'true' }, STATUS[s.status].icon),
          s.inst.length > 1 ? h('span', { class: 'btile-strip', 'aria-hidden': 'true' },
            ...s.inst.slice(-4).reverse().map(r => h('i', { class: 's-' + r.status }))) : null);
        first = false;
        tip(t, () => [
          `${s.host}${s.ip ? ' (' + s.ip + (s.ipFromAgent ? ', 접속 IP' : '') + ')' : ''}`,
          ...s.inst.slice().reverse().slice(0, 6).map(r => ({ level: r.status, text: `${prodVer(r)}${r.eol ? ' (' + r.eolLabel + ')' : r.belowLatest ? ' (최신 미만)' : ''} · 위험 ${r.counts.risk} · CVE ${cveTotal(r)}` })),
          ...(s.inst.length > 6 ? [`외 ${s.inst.length - 6}개 인스턴스`] : []),
          `점검 ${s.checked || '-'}${isStale(s.checked) ? ` (${STALE_DAYS}일 넘음)` : ''}`,
          ...s.worst.intrusionFindings.slice(0, 1).map(f => ({ level: f.level, text: f.text }))]);
        return t;
      });
      // 접힘 상태: 사용자가 바꾼 값 → 검색 중이면 펼침 → 큰 "양호" 묶음은 접음
      const gk = heroState.group + '|' + g.key;
      const allOk = g.items.every(x => x.status === 'ok');
      const open = heroState.open.has(gk) ? heroState.open.get(gk) : (q ? true : !(allOk && g.items.length > COLLAPSE_OK));
      const d = h('details', { class: 'bgroup', open: open || null },
        h('summary', { class: 'bgroup-head' }, h('b', null, g.label), h('span', { class: 'muted' }, `${g.items.length}대`),
          !open ? h('span', { class: 'muted' }, '— 접힘 (눌러서 펼치기)') : null,
          heroState.group !== 'status' ? h('span', { class: 'bgroup-mix' }, ...byStatus.map(([k, n]) => h('span', { class: 's-' + k, title: STATUS[k].label }, `${STATUS[k].icon} ${n}`))) : null),
        h('div', { class: 'btiles', role: 'group', 'aria-label': `${g.label} ${g.items.length}대` }, tiles));
      d.addEventListener('toggle', () => { if (d.open !== open) { heroState.open.set(gk, d.open); render(); } });
      return d;
    });
    box.replaceChildren(...(groups.length ? groups : [h('p', { class: 'muted none-msg' }, '숨기지 않은 판정의 서버가 없습니다.')]));
  }

  /** 타일 누름: 인스턴스 1개면 바로 상세, 여러 개면 목록 창 */
  function openServer(s) {
    if (s.inst.length === 1) { openDetail(s.inst[0].id); return; }
    $('#cfg-title').textContent = `${s.host}${s.ip ? ' (' + s.ip + ')' : ''}`;
    $('#cfg-sub').textContent = `인스턴스 ${s.inst.length}개 · 가장 나쁜 판정 ${STATUS[s.status].label}`;
    $('#cfg-body').replaceChildren(h('table', { class: 'servers' },
      h('thead', null, h('tr', null, ...['판정', '제품 · 버전', '인스턴스', '위험', '미조치 CVE', '점검 일시'].map(t => h('th', null, t)))),
      h('tbody', null, ...s.inst.slice().reverse().map(r => h('tr', { class: 'row', tabindex: '0',
        onclick: () => { $('#cfg-dlg').close(); openDetail(r.id); }, onkeydown: e => { if (e.key === 'Enter') { $('#cfg-dlg').close(); openDetail(r.id); } } },
        h('td', null, badge(r.status)), h('td', null, prodBadge(r.product), ' ', r.version || '?'),
        h('td', { class: 'mono' }, r.confArg || (r.binary ? r.binary.slice(r.binary.lastIndexOf('/') + 1) : '-')),
        h('td', { class: 'num' }, String(r.counts.risk)), h('td', { class: 'num' }, String(cveTotal(r))),
        h('td', { class: 'nowrap' }, r.checkedAt || '-'))))));
    $('#cfg-dlg').showModal();
  }

  /** 타일 사이 화살표 키 이동 (탭 키는 현황판 전체에서 한 번만 멈춤) */
  function boardKeys(e) {
    const tiles = $$('#hero-map .btile').filter(t => t.offsetParent !== null); // 접힌 묶음 제외
    const i = tiles.indexOf(document.activeElement);
    if (i < 0) return;
    let j = -1;
    if (e.key === 'ArrowRight') j = Math.min(tiles.length - 1, i + 1);
    else if (e.key === 'ArrowLeft') j = Math.max(0, i - 1);
    else if (e.key === 'Home') j = 0;
    else if (e.key === 'End') j = tiles.length - 1;
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const cur = tiles[i].getBoundingClientRect();
      const down = e.key === 'ArrowDown';
      let best = null, bestD = Infinity;
      tiles.forEach((t, k) => {
        const r = t.getBoundingClientRect();
        if (down ? r.top <= cur.top + 2 : r.top >= cur.top - 2) return;
        const d = Math.abs(r.top - cur.top) * 1000 + Math.abs(r.left - cur.left);
        if (d < bestD) { bestD = d; best = k; }
      });
      if (best !== null) j = best;
    } else return;
    e.preventDefault();
    if (j >= 0 && j !== i) {
      tiles[i].tabIndex = -1;
      tiles[j].tabIndex = 0;
      tiles[j].focus();
    }
  }

  // ---------------------------------------------------------------- 서버 배치도 (등각 투영)
  function renderHeroMap(list) {
    const box = $('#hero-map');
    const MAX = Infinity; // 서버 수 제한 없음 (많으면 확대/축소·이동으로 봄)
    const STACK = 6;   // 서버 상자 하나에 쌓는 인스턴스 최대 수
    // 같은 서버(호스트 + IP)의 인스턴스(Apache·WildFly·Tomcat)를 상자 하나로 묶음
    const byServer = new Map();
    list.forEach(r => {
      const key = r.host + '|' + (r.ip || '');
      if (!byServer.has(key)) byServer.set(key, { host: r.host, ip: r.ip, ipFromAgent: r.ipFromAgent, inst: [] });
      byServer.get(key).inst.push(r);
    });
    const rankOf = r => STATUS[r.status].rank;
    const allServers = Array.from(byServer.values());
    allServers.forEach(g => {
      // 아래층 → 위층 순서. 가장 나쁜 판정을 맨 위층에 두어 윗면 색 = 서버의 최악 판정
      g.inst.sort((a, b) => rankOf(b) - rankOf(a) || a.product.localeCompare(b.product) || (a.binary || '').localeCompare(b.binary || '') || (a.confArg || '').localeCompare(b.confArg || ''));
      g.worst = g.inst[g.inst.length - 1];
    });
    const servers = allServers.sort((a, b) => rankOf(a.worst) - rankOf(b.worst) || a.host.localeCompare(b.host)).slice(0, MAX);
    const n = servers.length;
    const cols = Math.max(2, Math.ceil(Math.sqrt(n || 1)));
    const rows = Math.max(2, Math.ceil((n || 1) / cols));
    const W = 132, H = 66;                       // 바닥 칸 하나의 폭·높이 (2:1 등각)
    const SP = 2.3;                              // 서버 사이 간격 (칸 단위). 뒤 서버 이름표(3줄)가 대각선 앞 상자 윗면과 겹치지 않는 값
    const P = (gx, gy) => [(gx - gy) * W / 2, (gx + gy) * H / 2];
    const pts = a => a.map(p => p.join(',')).join(' ');
    const agentsByName = new Map(((state.agents && state.agents.agents) || []).map(a => [a.name, a]));

    // 바닥판: 서버 칸 + 뒤쪽에 대시보드 자리
    const g0 = -3.1, gx1 = (cols - 1) * SP + 0.9, gy1 = (rows - 1) * SP + 0.9;
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
    function cube(c, w, h, z, topFill, slots, withTop = true) { // 옆면 색은 CSS(--rack-l/r, --hub-l/r)가 화면 모드별로 지정
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
      if (withTop) g.push(svg('polygon', { class: 'top', points: pts(top), fill: topFill, filter: topFill.startsWith('url') ? null : 'url(#isoGlow)' }));
      return g;
    }

    // 대시보드(허브) 위치와 연결선
    const hub = P(-2.2, -2.2); // 인스턴스가 쌓인 앞 서버 상자(최대 높이 84)에 가리지 않을 만큼 뒤로
    const cells = servers.map((g, i) => ({ g, c: P((i % cols) * SP, Math.floor(i / cols) * SP) }));
    const labels = []; // 이름표는 상자에 가리지 않도록 맨 위 층에 따로 그림
    cells.forEach(({ g, c }) => {
      if (n > 40) return; // 서버가 많으면 연결선 생략
      const srcs = g.inst.filter(r => r.source).map(r => agentsByName.get(r.source));
      if (!srcs.length) return;
      const live = srcs.some(ag => ag && ag.state !== 'offline' && ag.state !== 'never');
      els.push(svg('path', { class: 'iso-link' + (live ? ' live' : ''),
        d: `M${hub[0]},${hub[1] - 20} Q${(hub[0] + c[0]) / 2},${Math.min(hub[1], c[1]) - 50} ${c[0]},${c[1] - 40}` }));
    });
    const hubG = svg('g', { class: 'iso-box iso-hub', 'aria-hidden': 'true' }, cube(hub, W * 0.42, H * 0.42, 34, 'url(#hubTop)', 2));
    els.push(hubG);
    labels.push(svg('text', { class: 'iso-label', x: hub[0], y: hub[1] - 34 - H * 0.42 - 12 }, '점검 대시보드'));

    // 서버 상자: 뒤 → 앞 순서로 그려야 겹침이 자연스러움 (이미 행·열 순)
    // 인스턴스마다 한 층. 전체 높이는 84 이하로 맞춰 뒤 서버 이름표를 가리지 않게 함
    const w = W * 0.3, h = H * 0.3;
    cells.forEach(({ g: srv, c }) => {
      const total = srv.inst.length;
      const stack = srv.inst.slice(-STACK); // 넘치면 위쪽(판정이 나쁜) 인스턴스를 우선 표시
      const k = stack.length;
      const bh = k === 1 ? 52 : Math.min(26, 84 / k);
      if (srv.inst.some(r => r.status === 'compromise')) els.push(svg('ellipse', { class: 'iso-ring', cx: c[0], cy: c[1], rx: W * 0.42, ry: H * 0.42 }));
      stack.forEach((r, i) => {
        const tone = TONE[r.status] || TONE.none;
        const cb = [c[0], c[1] - i * bh];
        const top = i === k - 1;
        const g = svg('g', { class: 'iso-box' + (k > 1 ? ' iso-blade' : ''), tabindex: '0', role: 'button',
          'aria-label': `${srv.host} ${k > 1 ? `인스턴스 ${i + 1}/${total} ` : ''}${prodVer(r)} ${STATUS[r.status].label}, 상세 보기`,
          onclick: () => openDetail(r.id), onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetail(r.id); } } });
        cube(cb, w, h, bh, tone, k === 1 ? 3 : 0, top).forEach(x => g.append(x));
        if (k > 1) { // 층 구분: 오른쪽 면을 그 인스턴스 판정색으로 옅게 칠함
          const [x, y] = cb;
          g.append(svg('polygon', { class: 'tint', fill: tone, points: pts([[x, y - bh + h], [x + w, y - bh], [x + w, y], [x, y + h]]) }));
          g.append(svg('circle', { class: 'led', cx: x + W * 0.21, cy: y + h * 0.3 - bh / 2, r: 2.6, fill: tone }));
        } else {
          g.append(svg('circle', { class: 'led', cx: c[0] + W * 0.21, cy: c[1] - 12, r: 2.6, fill: tone }));
          g.append(svg('circle', { class: 'led', cx: c[0] + W * 0.21, cy: c[1] - 30, r: 2.6, fill: tone }));
        }
        tip(g, () => [
          k > 1 ? `서버 ${srv.host}${srv.ip ? ' (' + srv.ip + ')' : ''} · 인스턴스 ${total}개 중` : hostLabel(r),
          ...(k > 1 ? [`${PRODUCTS[r.product]} · ${r.binary || '?'}${r.confArg ? ' · ' + r.confArg : ''}`] : []),
          { level: r.status === 'compromise' ? 'compromise' : r.status, text: `${prodVer(r)}${r.eol ? ' (' + r.eolLabel + ')' : r.belowLatest ? ' (최신 미만)' : ''}` },
          `점검 ${r.checkedAt || '-'} · ${r.source ? '에이전트 ' + r.source : '수동 업로드'}`,
          `위험 ${r.counts.risk} · 주의 ${r.counts.warn} · 해당 CVE ${cveTotal(r)}`,
          ...r.intrusionFindings.slice(0, 2).map(f => ({ level: f.level, text: f.text }))]);
        els.push(g);
      });
      // 이름표 3줄: 호스트 / 서버 IP / 제품·버전(인스턴스가 여러 개면 제품별 개수)
      labels.push(svg('text', { class: 'iso-label', x: c[0], y: c[1] + h + 18 }, srv.host.length > 16 ? srv.host.slice(0, 15) + '…' : srv.host));
      labels.push(svg('text', { class: 'iso-sub', x: c[0], y: c[1] + h + 31 }, srv.ip ? srv.ip + (srv.ipFromAgent ? ' (접속 IP)' : '') : 'IP 미확인'));
      const prods = Array.from(new Set(srv.inst.map(r => r.product)));
      const vers = Array.from(new Set(srv.inst.map(r => (r.version || '?').replace(/\.Final$/, ''))));
      let sub3;
      if (total === 1) sub3 = `${PRODUCTS[srv.inst[0].product]} ${vers[0]}`;
      else if (prods.length === 1) sub3 = `${PRODUCTS[prods[0]]} 인스턴스 ${total}개` + (vers.length === 1 ? ` · ${vers[0]}` : '');
      else sub3 = prods.map(p => `${PRODUCTS[p]} ${srv.inst.filter(r => r.product === p).length}`).join(' · ');
      labels.push(svg('text', { class: 'iso-sub', x: c[0], y: c[1] + h + 44 }, sub3 + (total > k ? ` (위 ${k}개 표시)` : '')));
    });
    els.push(svg('g', { class: 'iso-labels', 'pointer-events': 'none' }, labels));
    if (!n) {
      const mid = P((cols - 1) * SP / 2, (rows - 1) * SP / 2);
      els.push(svg('text', { class: 'iso-empty', x: mid[0], y: mid[1] }, state.reports.length ? '조건에 맞는 서버가 없습니다' : '점검 결과가 아직 없습니다'));
    }

    // 보이는 범위에 맞춰 viewBox 계산
    const xs = [floor[0][0], floor[1][0], floor[2][0], floor[3][0]];
    const ys = [Math.min(floor[0][1] - 40, hub[1] - 34 - H * 0.42 - 30), floor[2][1] + T + 30];
    const minX = Math.min(...xs) - 20, maxX = Math.max(...xs) + 20;
    const full = [minX, ys[0], maxX - minX, ys[1] - ys[0]];
    const svgEl = svg('svg', { viewBox: full.join(' '), role: 'img', class: 'iso-svg',
      'aria-label': `서버 배치도: 서버 ${n}대, 인스턴스 ${list.length}개` }, els);
    const wrap = document.createElement('div'); // (이 함수 안에서는 h 가 상자 높이 숫자라 h() 를 쓸 수 없음)
    wrap.className = 'iso-wrap' + (n > 24 ? ' big' : '');
    wrap.append(svgEl);
    box.replaceChildren(wrap);
    isoZoom(wrap, svgEl, full, `${n}|${cols}`, W);
  }

  /**
   * 입체 배치도 확대/축소·이동. 마우스 휠(커서 위치 기준), 끌어서 이동, 두 손가락 확대, +/−/맞춤 버튼.
   * 30초 자동 갱신 때도 같은 배치(서버 수·열 수)면 보던 위치를 유지.
   * 확대가 충분할 때만 이름표를 보여 줌 (멀리서는 글자가 1~2px 이라 읽을 수 없음).
   */
  function isoZoom(wrap, el, full, layoutKey, cellW) {
    const st = heroState.zoom && heroState.zoom.key === layoutKey ? heroState.zoom : { key: layoutKey, vb: full.slice() };
    heroState.zoom = st;
    const minW = Math.min(full[2], cellW * 3);  // 최대 확대: 서버 약 3칸 폭
    const apply = () => {
      const [x, y, w, hh] = st.vb;
      el.setAttribute('viewBox', `${x} ${y} ${w} ${hh}`);
      const ppu = Math.min(el.clientWidth / w, el.clientHeight / hh); // 화면 px / 도면 단위 (가로·세로 중 작은 쪽에 맞춰짐)
      el.classList.toggle('lod-far', ppu * cellW < 75); // 칸 폭이 75px 보다 작으면 이름표 숨김
      zl.textContent = `${Math.round(full[2] / w * 100)}%`;
    };
    const zoomAt = (f, cx, cy) => { // f > 1 이면 확대. (cx, cy) = 화면상 기준점 비율(0~1)
      let [x, y, w, hh] = st.vb;
      const nw = Math.max(minW, Math.min(full[2], w / f)), k = nw / w, nh = hh * k;
      x += (w - nw) * cx; y += (hh - nh) * cy;
      st.vb = clamp([x, y, nw, nh]);
      apply();
    };
    const clamp = ([x, y, w, hh]) => [
      Math.min(Math.max(x, full[0] - w * 0.25), full[0] + full[2] - w * 0.75),
      Math.min(Math.max(y, full[1] - hh * 0.25), full[1] + full[3] - hh * 0.75), w, hh];
    const zl = h('span', { class: 'iso-zl', 'aria-live': 'polite' });
    const btn = (label, title, fn) => h('button', { type: 'button', class: 'iso-zbtn', title, 'aria-label': title, onclick: fn }, label);
    wrap.append(h('div', { class: 'iso-zoom' },
      btn('+', '확대', () => zoomAt(1.6, 0.5, 0.5)),
      btn('−', '축소', () => zoomAt(1 / 1.6, 0.5, 0.5)),
      btn('맞춤', '전체가 보이게', () => { st.vb = full.slice(); apply(); }), zl),
      h('div', { class: 'iso-help' }, '휠: 확대/축소 · 끌기: 이동 · 확대하면 서버 이름이 보입니다'));
    el.addEventListener('wheel', e => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.25 : 0.8, (e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height);
    }, { passive: false });
    // 끌어서 이동 / 두 손가락 확대 (포인터 이벤트)
    const pts = new Map();
    let moved = false, last = null, pinch = null;
    el.addEventListener('pointerdown', e => {
      pts.set(e.pointerId, [e.clientX, e.clientY]);
      moved = false; last = [e.clientX, e.clientY];
      if (pts.size === 2) { const [a, b] = Array.from(pts.values()); pinch = Math.hypot(a[0] - b[0], a[1] - b[1]); }
    });
    el.addEventListener('pointermove', e => {
      if (!pts.has(e.pointerId)) return;
      pts.set(e.pointerId, [e.clientX, e.clientY]);
      const r = el.getBoundingClientRect();
      if (pts.size === 2 && pinch) {
        const [a, b] = Array.from(pts.values());
        const d = Math.hypot(a[0] - b[0], a[1] - b[1]);
        zoomAt(d / pinch, ((a[0] + b[0]) / 2 - r.left) / r.width, ((a[1] + b[1]) / 2 - r.top) / r.height);
        pinch = d; moved = true;
        return;
      }
      const dx = e.clientX - last[0], dy = e.clientY - last[1];
      if (!moved && Math.hypot(dx, dy) < 5) return;   // 5px 미만은 클릭으로 봄
      if (!moved) el.setPointerCapture(e.pointerId);
      moved = true; last = [e.clientX, e.clientY];
      const [x, y, w, hh] = st.vb;
      st.vb = clamp([x - dx * w / r.width, y - dy * hh / r.height, w, hh]);
      el.classList.add('dragging');
      apply();
    });
    const end = e => { pts.delete(e.pointerId); if (pts.size < 2) pinch = null; el.classList.remove('dragging'); };
    el.addEventListener('pointerup', end);
    el.addEventListener('pointercancel', end);
    el.addEventListener('click', e => { if (moved) { e.stopPropagation(); e.preventDefault(); moved = false; } }, true); // 끌기 뒤 클릭 무시
    requestAnimationFrame(apply);
    new ResizeObserver(apply).observe(el);
  }

  // ---------------------------------------------------------------- 일자별 점검 건수 (막대)
  function renderTrend() {
    const days = dayKeys(14);
    const { cnt, comp } = dailyCounts(days);
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
        h('li', null, h('i', { class: 'dot c-accent' }), state.product ? `최신(${latestVer(state.product)}) 이상` : '최신 이상', h('b', null, `${up}대`)),
        h('li', null, h('i', { class: 'dot c-warning' }), '최신 미만', h('b', null, `${below}대`)),
        h('li', { title: Object.values(EOL_HINT).join('\n') }, h('i', { class: 'dot c-critical' }),
          state.product === 'apache' ? 'EOL (2.2 이하)' : state.product === 'wildfly' ? 'javax 계열 (26 이하)' : state.product === 'tomcat' || state.product === 'nginx' ? '지원 종료 브랜치' : '교체 필요 (EOL 등)', h('b', null, `${eol}대`)),
        list.length - known.length ? h('li', null, h('i', { class: 'dot c-info' }), '버전 미확인', h('b', null, `${list.length - known.length}대`)) : null));
  }

  function renderStatusDonut(list) {
    const keys = ['compromise', 'risk', 'warn', 'ok'];
    const cls = { compromise: 'c-critical', risk: 'c-serious', warn: 'c-warning', ok: 'c-good' };
    const segs = keys.map(k => ({ key: k, value: list.filter(r => r.status === k).length, color: TONE[k], label: STATUS[k].label }));
    $('#status-donut').replaceChildren(
      donut(segs, [String(list.length), '인스턴스']),
      h('ul', { class: 'donut-legend' }, ...segs.map(sg => h('li', null,
        h('button', { type: 'button', onclick: () => setStatusFilter(sg.key), title: `${sg.label} 서버만 서버 목록에서 보기` },
          h('i', { class: 'dot ' + cls[sg.key] }), sg.label, h('b', null, `${sg.value}대`))))));
  }

  // ---------------------------------------------------------------- 침해 의심 추이 (영역)
  function renderIntrusionArea() {
    const days = dayKeys(14);
    const v = dailyCounts(days).comp;
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
    // 스크립트 해시나 에이전트 버전 중 하나라도 아는 에이전트 기준. 스크립트가 다르거나 에이전트가 옛 버전이면 "최신" 아님
    const known = list.filter(a => (a.scriptMatches !== null && a.scriptMatches !== undefined) || a.agentVersion);
    const same = known.filter(a => a.scriptMatches !== false && !a.agentOutdated).length;
    const recent = list.filter(a => a.lastReportAt && now - a.lastReportAt < 24 * 3600 * 1000).length;
    const tile = (ico, num, label, ratio, bad, title) => {
      const fill = h('i');
      fill.style.width = Math.round(ratio * 100) + '%';
      return h('div', { class: 'tile' + (bad ? ' bad' : ''), title },
        h('div', { class: 't-ico' }, icon(ico)), h('div', { class: 't-num' }, num), h('div', { class: 't-label' }, label), h('div', { class: 't-bar' }, fill));
    };
    el.replaceChildren(
      tile('agent', `${online}/${n}`, '온라인', online / n, online < n, '최근 3분 안에 접속한 에이전트'),
      tile('code', known.length ? `${same}/${known.length}` : '-', '스크립트 최신', known.length ? same / known.length : 0, same < known.length, `점검 스크립트 4개(apache/wildfly/tomcat/nginx)가 대시보드와 같고 에이전트 본체도 ${state.agents.expectedAgentVersion || '최신'} 이상인 에이전트 (아니면 재설치)`),
      tile('clock', `${recent}/${n}`, '24시간 내 점검', recent / n, false, '최근 24시간 안에 리포트를 보낸 에이전트'));
  }

  // ---------------------------------------------------------------- 시작
  let refreshing = false;
  async function refreshAll() {
    if (refreshing) return;
    refreshing = true;
    try {
      await loadLatest();
      await Promise.all([load(), loadAgents(), loadCveFeed()]);
      renderSideAgents();
      $('#last-refresh').textContent = `마지막 갱신: ${new Date().toLocaleTimeString('ko-KR')}`;
    } finally { refreshing = false; }
  }

  async function load() {
    let changed = !state.loadedOnce;
    try {
      const [rep, daily] = await Promise.all([apiCached('reports'), apiCached('daily?days=14')]);
      state.reports = rep.data;
      state.totalReports = rep.total;
      state.daily = daily.data;
      changed = changed || rep.changed || daily.changed;
      if (!$('#f-latest').checked) {
        const all = await apiCached('reports?scope=all');
        state.allReports = all.data;
        changed = changed || all.changed;
      } else {
        state.allReports = null; // 메모리 절약: 전체 이력은 필요할 때만
        etagCache.delete('reports?scope=all');
      }
      showAlert('');
    } catch (e) {
      showAlert('리포트를 불러오지 못했습니다: ' + e.message);
      if (!state.reports) state.reports = [];
      changed = true;
    }
    state.loadedOnce = true;
    if (changed) render(); // 바뀐 것이 없으면 다시 그리지 않음 (보고 있던 툴팁·확대 위치 유지)
  }

  async function init() {
    try {
      state.me = await api('me');
    } catch (e) {
      showAlert(e.message);
      return;
    }
    document.body.classList.toggle('is-admin', !!state.me.admin);
    renderHttpAlert();
    $('#who').textContent = `${state.me.user} (${state.me.admin ? '관리자' : '조회 전용'})`;
    $('#logout-csrf').value = state.me.csrf;
    if (state.me.reportDir) $('#report-dir').textContent = `(리포트 폴더: ${state.me.reportDir})`;

    ['#f-q', '#f-status', '#f-dq', '#f-group'].forEach(s => $(s).addEventListener('input', () => { state.tableLimit = TABLE_PAGE; render(); }));
    $('#f-latest').addEventListener('change', async () => { // 끄면 전체 이력을 받아 옴
      if (!$('#f-latest').checked) $('#f-count').textContent = '전체 이력을 불러오는 중…';
      state.tableLimit = TABLE_PAGE;
      state.loadedOnce = false;
      await load();
    });
    $('#btn-refresh').addEventListener('click', refreshAll);
    $('#btn-csv').addEventListener('click', exportCsv);
    $$('#servers th[data-sort]').forEach(th => th.addEventListener('click', () => {
      const k = th.dataset.sort;
      state.sort = { key: k, asc: state.sort.key === k ? !state.sort.asc : k === 'status' || k === 'host' };
      render();
    }));
    $$('dialog [data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
    // 상세 창: 아래로 내려가면 "건수 요약으로" 버튼 표시
    const dBody = $('#detail .dialog-body');
    dBody.addEventListener('scroll', () => { $('#d-top').hidden = dBody.scrollTop < 240; }, { passive: true });
    $('#d-top').addEventListener('click', () => {
      const smooth = !(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
      dBody.scrollTo({ top: 0, behavior: smooth ? 'smooth' : 'auto' });
      const first = $('#d-kpis .kpi.clickable'); if (first) first.focus({ preventScroll: true });
    });
    $$('#detail .tab').forEach(t => t.addEventListener('click', () => selectTab(t.dataset.tab)));
    $('#d-delete').addEventListener('click', async () => {
      if (!current || !confirm(`${current.id} 점검 1건을 삭제할까요? (휴지통 reports-trash 로 옮겨지며 일정 기간 뒤 완전히 지워집니다)`)) return;
      try { await api('reports/' + encodeURIComponent(current.id), { method: 'DELETE' }); $('#detail').close(); await load(); }
      catch (e) { alert(e.message); }
    });

    $('#exc-form').addEventListener('submit', submitExc);
    $('#agurl-form').addEventListener('submit', ev => { ev.preventDefault(); saveAgentUrl($('#agurl-input').value); });
    $('#agurl-clear').addEventListener('click', () => saveAgentUrl(''));
    $('#d-reset-instance').addEventListener('click', async () => {
      if (!current) return;
      const label = `${PRODUCTS[current.product] || current.product} ${current.host}` + (current.binary ? ` (${current.binary})` : '');
      if (await resetRecords('instance', current.instanceKey, `${label} 서버의 점검 이력 삭제`)) $('#detail').close();
    });
    // 설정 → 점검 기록 초기화
    const rScope = () => $('#r-scope').value;
    const rShow = () => {
      const s = rScope();
      $('#r-keep-wrap').hidden = s !== 'old';
      $('#r-agent-wrap').hidden = s !== 'agent';
      $('#r-agent-state-wrap').hidden = s !== 'agent';
      $('#r-product-wrap').hidden = s !== 'product';
    };
    $('#r-product').replaceChildren(...Object.entries(PRODUCTS).map(([k, v]) => h('option', { value: k }, v)));
    $('#r-scope').addEventListener('change', rShow);
    rShow();
    $('#btn-reset').addEventListener('click', () => {
      const s = rScope();
      if (s === 'old') resetRecords('old', $('#r-keep').value, `오래된 이력 정리 (서버마다 최근 ${$('#r-keep').value}개만 남김)`);
      else if (s === 'agent') {
        const n = $('#r-agent').value;
        if (!n) { alert('에이전트를 고르세요.'); return; }
        resetRecords('agent', n, `${n} 에이전트 기록 초기화`, $('#r-agent-state').checked ? { agentState: 'true' } : null);
      } else if (s === 'product') resetRecords('product', $('#r-product').value, `${PRODUCTS[$('#r-product').value]} 점검 기록 전체 삭제`);
      else resetRecords('all', '', '전체 점검 기록 삭제');
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
    // 서버 현황판 조작
    $$('[data-hview]').forEach(b => b.addEventListener('click', () => { heroState.view = b.dataset.hview; savePref('precheck.heroView', heroState.view); render(); }));
    $('#b-group').value = heroState.group;
    $('#b-group').addEventListener('change', e => { heroState.group = e.target.value; savePref('precheck.heroGroup', heroState.group); render(); });
    $('#b-q').addEventListener('input', e => { heroState.q = e.target.value; render(); });
    $('#b-q').addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const hits = $$('#hero-map .btile.hit');
      if (hits.length === 1) hits[0].click(); else if (hits.length) hits[0].focus();
    });
    $('#hero-map').addEventListener('keydown', boardKeys);
    $('#btn-cve-refresh').addEventListener('click', async () => {
      try { await api('cve-feed', { method: 'POST', body: new URLSearchParams({ action: 'refresh' }) }); } catch (e) { alert(e.message); return; }
      await loadCveFeed();
      setTimeout(loadCveFeed, 20000); // OSV 전체 자료(약 10MB)를 받는 데 수십 초 걸릴 수 있음
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
      try { const r = await api('agents-run', { method: 'POST' }); await loadAgents(); showAlert(''); alert(`${r.requested}대에 점검을 요청했습니다.\n온라인 ${r.requested - (r.offline || 0)}대는 1분 안에 시작됩니다.`
        + (r.offline ? `\n오프라인(또는 설치 대기) ${r.offline}대는 에이전트가 다시 접속해야 시작됩니다. 화면 위 알림과 에이전트 목록의 상태 칸을 확인하세요.` : '')); }
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
