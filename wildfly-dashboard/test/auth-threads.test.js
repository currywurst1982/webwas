'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { UserStore } = require('../src/auth');
const { analyze, toText, poolName } = require('../src/thread-analyzer');

test('user store: first admin, login, lockout and password change', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'users-'));
  delete process.env.DASHBOARD_ADMIN_PASSWORD;
  const store = new UserStore(dir);
  const pw = store.ensureAdmin();
  assert.ok(pw && pw.length >= 10);
  assert.strictEqual(store.ensureAdmin(), null, 'admin is only created once');

  const ok = store.authenticate('admin', pw, '1.1.1.1');
  assert.strictEqual(ok.user.mustChangePassword, true);
  assert.throws(() => store.changePassword('admin', pw, 'short'), /8자/);
  store.changePassword('admin', pw, 'NewPassw0rd');
  assert.ok(new UserStore(dir).authenticate('admin', 'NewPassw0rd', 'x').user, 'persisted to disk');
  assert.ok(!fs.readFileSync(path.join(dir, 'users.json'), 'utf8').includes('NewPassw0rd'));

  for (let i = 0; i < 5; i++) assert.ok(store.authenticate('admin', 'bad', '2.2.2.2').error);
  const locked = store.authenticate('admin', 'NewPassw0rd', '2.2.2.2');
  assert.ok(locked.locked, 'locked after 5 failures from the same IP');
});

const frame = (c, m) => ({ className: c, methodName: m, fileName: 'X.java', lineNumber: 1 });
const t = (id, name, state, stack, extra = {}) => ({
  id, name, state, stack, lockName: null, lockOwnerId: null, lockOwnerName: null, lockedMonitors: [], lockedSynchronizers: [], ...extra,
});

test('thread analysis detects deadlocks, contention and pools', () => {
  const app = [frame('com.example.A', 'run')];
  const dump = {
    timestamp: Date.now(),
    deadlockedIds: [1, 2],
    threads: [
      t(1, 'default task-1', 'BLOCKED', app, { lockName: 'L2', lockOwnerId: 2, lockOwnerName: 'default task-2' }),
      t(2, 'default task-2', 'BLOCKED', app, { lockName: 'L1', lockOwnerId: 1, lockOwnerName: 'default task-1' }),
      t(3, 'default task-3', 'BLOCKED', app, { lockName: 'L1', lockOwnerId: 1, lockOwnerName: 'default task-1' }),
      t(4, 'default task-4', 'WAITING', [frame('jdk.internal.misc.Unsafe', 'park'), frame('org.jboss.threads.EnhancedQueueExecutor', 'run')]),
    ],
  };
  const a = analyze(dump);
  assert.strictEqual(a.deadlocks.length, 1);
  assert.deepStrictEqual(a.deadlocks[0].map((c) => c.id), [1, 2]);
  assert.strictEqual(a.states.BLOCKED, 3);
  assert.strictEqual(a.pools[0].name, 'default task');
  assert.strictEqual(a.pools[0].idle, 1);
  assert.strictEqual(a.locks.find((l) => l.lock === 'L1').waiters.length, 2);
  assert.ok(a.findings.some((f) => f.level === 'critical'));
  assert.match(toText(dump), /"default task-1" #1[\s\S]*waiting to lock <L2>/);
});

test('pool names group numbered threads', () => {
  assert.strictEqual(poolName('default task-12'), 'default task');
  assert.strictEqual(poolName('ServerService Thread Pool -- 77'), 'ServerService Thread Pool --');
  assert.strictEqual(poolName('EJB default - 3'), 'EJB default -');
});
