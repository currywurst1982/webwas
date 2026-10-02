'use strict';

// Analysis of a thread dump: state distribution, thread pools, hot stacks,
// lock contention and deadlock chains, plus jstack-compatible text output.

const IDLE_FRAMES = [
  /^sun\.misc\.Unsafe\.park$/, /^jdk\.internal\.misc\.Unsafe\.park$/, /^java\.lang\.Object\.wait/,
  /^java\.lang\.Thread\.sleep/, /^sun\.nio\.ch\.\w+\.(poll|wait|epollWait|doSelect|kevent\w*)/,
  /^sun\.nio\.ch\.Net\.poll/, /^java\.net\.\w*SocketImpl\.(socketAccept|accept0|accept)/,
  /^sun\.nio\.ch\.\w+\.accept0?/,
];

function frameText(f) {
  const loc = f.nativeMethod ? 'Native Method'
    : f.fileName ? (f.lineNumber >= 0 ? `${f.fileName}:${f.lineNumber}` : f.fileName) : 'Unknown Source';
  return `${f.className}.${f.methodName}(${loc})`;
}

function poolName(name) {
  return String(name || '')
    .replace(/\s*\(.*\)$/, '')
    .replace(/[-#_ ]?\d+$/g, '')
    .replace(/(-thread|-worker)?[-#_ ]?\d+(?=[-_ ])/g, '$1')
    .replace(/\d+/g, 'N') || '(unnamed)';
}

function isIdle(t) {
  const top = t.stack[0];
  if (!top) return true;
  const sig = `${top.className}.${top.methodName}`;
  // Parked/sleeping/polling with no application code on the stack = idle pool thread.
  // A park inside application code (e.g. waiting for a DB connection) is not idle.
  return (t.state === 'WAITING' || t.state === 'TIMED_WAITING' || t.state === 'RUNNABLE') &&
    IDLE_FRAMES.some((re) => re.test(sig)) && !firstAppFrame(t) &&
    !t.stack.some((f) => /\.jca\.|\.jdbc\./.test(f.className));
}

function firstAppFrame(t) {
  return t.stack.find((f) => !/^(java|javax|jdk|sun|com\.sun|org\.jboss|io\.undertow|org\.wildfly|org\.xnio|io\.netty)\./.test(f.className));
}

function analyze(dump) {
  const threads = dump.threads;
  const byId = new Map(threads.map((t) => [t.id, t]));
  const states = {};
  for (const t of threads) states[t.state] = (states[t.state] || 0) + 1;

  // Thread pools (grouping threads by name pattern).
  const pools = new Map();
  for (const t of threads) {
    const p = poolName(t.name);
    if (!pools.has(p)) pools.set(p, { name: p, total: 0, states: {}, idle: 0 });
    const e = pools.get(p);
    e.total++;
    e.states[t.state] = (e.states[t.state] || 0) + 1;
    if (isIdle(t)) e.idle++;
  }

  // Identical stacks (hot spots): group non-idle threads by their top 8 frames.
  const stacks = new Map();
  for (const t of threads) {
    if (!t.stack.length || isIdle(t)) continue;
    const key = t.stack.slice(0, 8).map(frameText).join('\n');
    if (!stacks.has(key)) stacks.set(key, { frames: t.stack.slice(0, 8).map(frameText), threads: [], state: t.state });
    stacks.get(key).threads.push(t.name);
  }

  // Lock contention: which monitors / synchronizers have waiters.
  const locks = new Map();
  for (const t of threads) {
    if (!t.lockName || !(t.state === 'BLOCKED' || t.lockOwnerId !== null)) continue;
    if (!locks.has(t.lockName)) {
      locks.set(t.lockName, { lock: t.lockName, ownerId: t.lockOwnerId, ownerName: t.lockOwnerName, waiters: [] });
    }
    locks.get(t.lockName).waiters.push({ name: t.name, state: t.state });
  }

  // Deadlock chains reported by ThreadMXBean.findDeadlockedThreads().
  const deadlocks = [];
  const seen = new Set();
  for (const id of dump.deadlockedIds || []) {
    if (seen.has(id)) continue;
    const chain = [];
    let cur = byId.get(id);
    while (cur && !seen.has(cur.id)) {
      seen.add(cur.id);
      chain.push({ id: cur.id, name: cur.name, waitingFor: cur.lockName, heldBy: cur.lockOwnerName });
      cur = cur.lockOwnerId !== null ? byId.get(cur.lockOwnerId) : null;
    }
    if (chain.length) deadlocks.push(chain);
  }

  const findings = [];
  if (deadlocks.length) findings.push({ level: 'critical', text: `데드락 ${deadlocks.length}건이 감지되었습니다.` });
  const blocked = states.BLOCKED || 0;
  if (blocked > 0) {
    findings.push({ level: blocked >= 5 ? 'warning' : 'info', text: `BLOCKED 상태 쓰레드 ${blocked}개 (모니터 락 경합).` });
  }
  const hotLock = [...locks.values()].sort((a, b) => b.waiters.length - a.waiters.length)[0];
  if (hotLock && hotLock.waiters.length >= 3) {
    findings.push({ level: 'warning', text: `락 ${hotLock.lock} 에 ${hotLock.waiters.length}개 쓰레드가 대기 중 (소유: ${hotLock.ownerName || '알 수 없음'}).` });
  }
  const hot = [...stacks.values()].sort((a, b) => b.threads.length - a.threads.length)[0];
  if (hot && hot.threads.length >= 5) {
    const where = hot.frames.find((f) => !/^(java|javax|jdk|sun|com\.sun)\./.test(f)) || hot.frames[0];
    findings.push({ level: 'warning', text: `${hot.threads.length}개 쓰레드가 동일한 스택에 머물러 있습니다: ${where}` });
  }
  for (const p of pools.values()) {
    if (p.total >= 10 && p.idle === 0) {
      findings.push({ level: 'warning', text: `쓰레드 풀 "${p.name}" 의 ${p.total}개 쓰레드가 모두 작업 중입니다 (풀 고갈 가능성).` });
    }
  }
  const dbWaits = threads.filter((t) => t.stack.some((f) => /(\.jca\.core\.connectionmanager\.pool|SemaphoreConcurrentLinkedDeque|PoolBySubject|ManagedConnectionPool)/.test(f.className) && /getConnection|getSimple|acquire|tryAcquire/.test(f.methodName)));
  if (dbWaits.length) {
    findings.push({ level: 'warning', text: `${dbWaits.length}개 쓰레드가 DB 커넥션 풀에서 커넥션을 기다리고 있습니다.` });
  }
  const socketReads = threads.filter((t) => t.state === 'RUNNABLE' && t.stack[0] && /socketRead|SocketInputStream\.read|NioSocketImpl\.(read|park)/.test(frameText(t.stack[0])) && firstAppFrame(t));
  if (socketReads.length >= 3) {
    findings.push({ level: 'info', text: `${socketReads.length}개 쓰레드가 소켓 응답(외부 시스템/DB)을 기다리고 있습니다.` });
  }
  if (!findings.length) findings.push({ level: 'ok', text: '특이 사항이 발견되지 않았습니다.' });

  return {
    total: threads.length,
    states,
    pools: [...pools.values()].sort((a, b) => b.total - a.total),
    hotStacks: [...stacks.values()].filter((s) => s.threads.length > 1).sort((a, b) => b.threads.length - a.threads.length).slice(0, 20),
    locks: [...locks.values()].sort((a, b) => b.waiters.length - a.waiters.length),
    deadlocks,
    findings,
  };
}

/** Formats the dump like `jstack` output so it can be opened in fastThread, TDA, IBM TMDA, etc. */
function toText(dump, server) {
  const lines = [];
  lines.push(new Date(dump.timestamp).toISOString().replace('T', ' ').replace(/\..*$/, ''));
  lines.push(`Full thread dump ${server ? server.name : ''} (via WildFly management API):`);
  lines.push('');
  for (const t of dump.threads) {
    lines.push(`"${t.name}" #${t.id}${t.daemon ? ' daemon' : ''}${t.priority !== undefined ? ' prio=' + t.priority : ''} tid=${t.id}`);
    lines.push(`   java.lang.Thread.State: ${t.state}`);
    const monitorsByDepth = new Map();
    for (const m of t.lockedMonitors) {
      if (!monitorsByDepth.has(m.depth)) monitorsByDepth.set(m.depth, []);
      monitorsByDepth.get(m.depth).push(m);
    }
    t.stack.forEach((f, i) => {
      lines.push(`\tat ${frameText(f)}`);
      if (i === 0 && t.lockName) {
        const verb = t.state === 'BLOCKED' ? 'waiting to lock'
          : /^java\.lang\.Object\.wait/.test(`${f.className}.${f.methodName}`) ? 'waiting on' : 'parking to wait for';
        lines.push(`\t- ${verb} <${t.lockName}>${t.lockOwnerName ? ` (owned by "${t.lockOwnerName}")` : ''}`);
      }
      for (const m of monitorsByDepth.get(i) || []) {
        lines.push(`\t- locked <0x${Number(m.identityHashCode).toString(16)}> (a ${m.className})`);
      }
    });
    if (t.lockedSynchronizers.length) {
      lines.push('');
      lines.push('   Locked ownable synchronizers:');
      for (const s of t.lockedSynchronizers) lines.push(`\t- <0x${Number(s.identityHashCode).toString(16)}> (a ${s.className})`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = { analyze, toText, frameText, poolName };
