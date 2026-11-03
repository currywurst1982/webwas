// 화면 모드(어둡게/밝게/시스템 설정) 선택. CSS 가 깜빡이지 않도록 <head> 에서 defer 없이 먼저 읽음.
// 선택값은 이 브라우저에만 저장됨(localStorage). 저장이 막힌 환경에서도 기본값(어둡게)으로 동작.
(function () {
  'use strict';
  const KEY = 'precheck.theme';
  const MODES = ['dark', 'light', 'system'];
  const mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

  function load() {
    try { const v = localStorage.getItem(KEY); return MODES.includes(v) ? v : 'dark'; } catch (e) { return 'dark'; }
  }
  function save(v) {
    try { localStorage.setItem(KEY, v); } catch (e) { /* 저장 불가: 이번 화면에만 적용 */ }
  }

  let mode = load();
  const resolved = () => (mode === 'system' ? (mq && mq.matches ? 'light' : 'dark') : mode);

  function sync() {
    const t = resolved();
    document.documentElement.dataset.theme = t;
    document.querySelectorAll('.theme-btn').forEach(b => {
      const label = t === 'light' ? '어두운 화면으로 전환' : '밝은 화면으로 전환';
      b.title = label;
      b.setAttribute('aria-label', label);
    });
    document.querySelectorAll('.theme-seg [data-theme-mode]').forEach(b =>
      b.setAttribute('aria-pressed', String(b.dataset.themeMode === mode)));
    document.dispatchEvent(new CustomEvent('precheck-theme', { detail: { mode, theme: t } }));
  }

  function set(v) {
    if (!MODES.includes(v)) return;
    mode = v;
    save(v);
    sync();
  }

  document.documentElement.dataset.theme = resolved();
  if (mq) {
    const onChange = () => { if (mode === 'system') sync(); };
    if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
  }

  document.addEventListener('DOMContentLoaded', () => {
    // 머리글 버튼: 지금 보이는 모드의 반대로 고정 전환
    document.querySelectorAll('.theme-btn').forEach(b =>
      b.addEventListener('click', () => set(resolved() === 'light' ? 'dark' : 'light')));
    document.querySelectorAll('.theme-seg [data-theme-mode]').forEach(b =>
      b.addEventListener('click', () => set(b.dataset.themeMode)));
    sync();
  });

  window.precheckTheme = { get: () => mode, resolved, set };
})();
