#!/usr/bin/env node
'use strict';

// Adds or resets a dashboard user:  node scripts/add-user.js <username> [admin|viewer]
// The password is read from the terminal (or DASHBOARD_USER_PASSWORD).

const readline = require('readline');
const config = require('../src/config');
const { UserStore, validatePassword, ROLES } = require('../src/auth');

async function ask(question, hidden) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); if (hidden) process.stdout.write('\n'); resolve(a); }));
}

(async () => {
  const [username, role = 'admin'] = process.argv.slice(2);
  if (!username || !ROLES.includes(role)) {
    console.error(`사용법: node scripts/add-user.js <username> [${ROLES.join('|')}]`);
    process.exit(1);
  }
  let password = process.env.DASHBOARD_USER_PASSWORD;
  if (!password) {
    password = await ask('비밀번호: ', true);
    if (password !== await ask('비밀번호 확인: ', true)) { console.error('비밀번호가 일치하지 않습니다'); process.exit(1); }
  }
  const err = validatePassword(password);
  if (err) { console.error(err); process.exit(1); }
  const store = new UserStore(config.load().dataDir);
  const existed = Boolean(store.find(username));
  store.upsert(username, password, role);
  console.log(`${existed ? '변경' : '추가'}됨: ${username} (${role})`);
})();
