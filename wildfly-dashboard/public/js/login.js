'use strict';

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit');
  const err = document.getElementById('error');
  err.textContent = '';
  btn.disabled = true;
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'wildfly-dashboard' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `로그인 실패 (HTTP ${res.status})`);
    location.href = '/app';
  } catch (ex) {
    err.textContent = ex.message;
    btn.disabled = false;
  }
});
