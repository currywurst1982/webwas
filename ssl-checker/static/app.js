'use strict';

const hostsInput   = document.getElementById('hosts-input');
const btnCheck     = document.getElementById('btn-check');
const btnClear     = document.getElementById('btn-clear');
const btnLoadApache = document.getElementById('btn-load-apache');
const loading      = document.getElementById('loading');
const errorMsg     = document.getElementById('error-msg');
const summarySection = document.getElementById('summary-section');
const resultsSection = document.getElementById('results-section');
const resultsBody  = document.getElementById('results-body');
const checkedAt    = document.getElementById('checked-at');

// 상태 레이블 및 배지 매핑
const STATUS_MAP = {
  ok:       { label: '정상',   badgeClass: 'badge-ok',       daysClass: 'days-ok' },
  warning:  { label: '경고',   badgeClass: 'badge-warning',  daysClass: 'days-warning' },
  critical: { label: '위험',   badgeClass: 'badge-critical', daysClass: 'days-critical' },
  expired:  { label: '만료됨', badgeClass: 'badge-expired',  daysClass: 'days-expired' },
  error:    { label: '오류',   badgeClass: 'badge-error',    daysClass: 'days-error' },
  unknown:  { label: '알 수 없음', badgeClass: 'badge-unknown', daysClass: 'days-error' },
};

// 남은 일수에 따른 프로그레스 바 색상
function progressColor(days) {
  if (days === null || days < 0) return '#ef4444';
  if (days <= 14) return '#f97316';
  if (days <= 30) return '#f59e0b';
  return '#22c55e';
}

// 프로그레스 바 너비 계산 (최대 365일 기준)
function progressWidth(days) {
  if (days === null || days < 0) return 0;
  return Math.min(100, Math.round((days / 365) * 100));
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorMsg.classList.remove('hidden');
}

function hideError() {
  errorMsg.classList.add('hidden');
}

function setLoading(on) {
  loading.classList.toggle('hidden', !on);
  btnCheck.disabled = on;
  btnLoadApache.disabled = on;
}

function escHtml(str) {
  if (!str) return '-';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderDays(item) {
  const info = STATUS_MAP[item.status] || STATUS_MAP.unknown;
  if (item.status === 'error') {
    return `<span class="days-pill days-error">-</span>`;
  }
  if (item.days_remaining === null) {
    return `<span class="days-pill days-error">-</span>`;
  }
  const days = item.days_remaining;
  const label = days < 0 ? '만료됨' : `${days}일 남음`;
  const color = progressColor(days);
  const width = progressWidth(days);
  return `
    <div class="progress-wrap">
      <span class="days-pill ${info.daysClass}">${escHtml(label)}</span>
      <div class="progress-bar">
        <div class="progress-fill" style="width:${width}%;background:${color};"></div>
      </div>
    </div>`;
}

function renderRow(item) {
  const info = STATUS_MAP[item.status] || STATUS_MAP.unknown;
  const hostDisplay = item.port !== 443
    ? `${escHtml(item.hostname)}:<strong>${item.port}</strong>`
    : escHtml(item.hostname);

  const subjectCell = item.error
    ? `<span class="error-detail">${escHtml(item.error)}</span>`
    : escHtml(item.subject);

  return `
    <tr>
      <td><span class="badge ${info.badgeClass}">${info.label}</span></td>
      <td>${hostDisplay}</td>
      <td>${subjectCell}</td>
      <td>${escHtml(item.issuer)}</td>
      <td>${escHtml(item.not_after)}</td>
      <td>${renderDays(item)}</td>
    </tr>`;
}

function renderSummary(results) {
  const counts = { ok: 0, warning: 0, critical: 0, expired: 0, error: 0 };
  results.forEach(r => {
    if (counts[r.status] !== undefined) counts[r.status]++;
    else counts.error++;
  });
  document.getElementById('num-total').textContent   = results.length;
  document.getElementById('num-ok').textContent      = counts.ok;
  document.getElementById('num-warning').textContent = counts.warning;
  document.getElementById('num-critical').textContent = counts.critical;
  document.getElementById('num-expired').textContent = counts.expired;
  document.getElementById('num-error').textContent   = counts.error;
  summarySection.classList.remove('hidden');
}

async function checkCerts() {
  const rawInput = hostsInput.value.trim();
  if (!rawInput) {
    showError('호스트를 한 개 이상 입력하세요.');
    return;
  }
  hideError();
  const hosts = rawInput
    .split('\n')
    .map(h => h.trim())
    .filter(h => h.length > 0 && !h.startsWith('#'));

  if (hosts.length === 0) {
    showError('유효한 호스트가 없습니다.');
    return;
  }

  setLoading(true);
  resultsSection.classList.add('hidden');
  summarySection.classList.add('hidden');
  checkedAt.classList.add('hidden');

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hosts }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `서버 오류: ${res.status}`);
    }

    const data = await res.json();
    const results = data.results || [];

    resultsBody.innerHTML = results.map(renderRow).join('');
    renderSummary(results);

    if (data.checked_at) {
      checkedAt.textContent = `확인 시각: ${data.checked_at}`;
      checkedAt.classList.remove('hidden');
    }

    resultsSection.classList.remove('hidden');
  } catch (err) {
    showError(err.message || '알 수 없는 오류가 발생했습니다.');
  } finally {
    setLoading(false);
  }
}

async function loadApacheVhosts() {
  setLoading(true);
  hideError();
  try {
    const res = await fetch('/api/apache-vhosts');
    if (!res.ok) throw new Error(`서버 오류: ${res.status}`);
    const data = await res.json();
    const domains = data.domains || [];
    if (domains.length === 0) {
      showError('로컬 Apache에서 HTTPS VirtualHost 도메인을 찾지 못했습니다.\napache2ctl 또는 apachectl 명령이 사용 가능한지 확인하세요.');
    } else {
      const existing = hostsInput.value.trim();
      const newEntries = domains.join('\n');
      hostsInput.value = existing ? `${existing}\n${newEntries}` : newEntries;
    }
  } catch (err) {
    showError(err.message || '알 수 없는 오류가 발생했습니다.');
  } finally {
    setLoading(false);
  }
}

btnCheck.addEventListener('click', checkCerts);
btnClear.addEventListener('click', () => {
  hostsInput.value = '';
  hideError();
  summarySection.classList.add('hidden');
  resultsSection.classList.add('hidden');
  checkedAt.classList.add('hidden');
});
btnLoadApache.addEventListener('click', loadApacheVhosts);

// Enter 키로 제출 (Shift+Enter는 줄바꿈)
hostsInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    checkCerts();
  }
});
