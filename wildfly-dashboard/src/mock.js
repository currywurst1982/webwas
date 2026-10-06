'use strict';

// Simulated WildFly management API (DASHBOARD_MOCK=true). Responses use the
// same DMR JSON shape as a real server so the collectors are exercised as-is.

const MB = 1024 * 1024;

function key(address) {
  return (address || []).map((a) => Object.entries(a).map(([k, v]) => `${k}=${v}`).join('')).join('/');
}

function wave(period, amp, base) {
  return base + amp * (0.5 + 0.5 * Math.sin(Date.now() / period));
}

function frame(className, methodName, fileName, lineNumber, nativeMethod = false) {
  return { 'class-name': className, 'method-name': methodName, 'file-name': fileName, 'line-number': lineNumber, 'native-method': nativeMethod };
}

const IDLE_TASK = [
  frame('jdk.internal.misc.Unsafe', 'park', null, -2, true),
  frame('java.util.concurrent.locks.LockSupport', 'park', 'LockSupport.java', 371),
  frame('org.jboss.threads.EnhancedQueueExecutor$PoolThreadNode', 'park', 'EnhancedQueueExecutor.java', 2245),
  frame('org.jboss.threads.EnhancedQueueExecutor$ThreadBody', 'run', 'EnhancedQueueExecutor.java', 1574),
  frame('java.lang.Thread', 'run', 'Thread.java', 1583),
];
const DB_WAIT = [
  frame('jdk.internal.misc.Unsafe', 'park', null, -2, true),
  frame('java.util.concurrent.locks.LockSupport', 'parkNanos', 'LockSupport.java', 269),
  frame('java.util.concurrent.Semaphore', 'tryAcquire', 'Semaphore.java', 415),
  frame('org.jboss.jca.core.connectionmanager.pool.mcp.SemaphoreConcurrentLinkedDequeManagedConnectionPool', 'getConnection', 'SemaphoreConcurrentLinkedDequeManagedConnectionPool.java', 450),
  frame('org.jboss.jca.adapters.jdbc.WrapperDataSource', 'getConnection', 'WrapperDataSource.java', 138),
  frame('com.example.order.OrderRepository', 'findByCustomer', 'OrderRepository.java', 88),
  frame('com.example.order.OrderService', 'list', 'OrderService.java', 41),
  frame('com.example.order.OrderResource', 'get', 'OrderResource.java', 30),
  frame('io.undertow.servlet.handlers.ServletHandler', 'handleRequest', 'ServletHandler.java', 74),
];
const SOCKET_READ = [
  frame('sun.nio.ch.Net', 'poll', null, -2, true),
  frame('sun.nio.ch.NioSocketImpl', 'park', 'NioSocketImpl.java', 191),
  frame('sun.nio.ch.NioSocketImpl', 'read', 'NioSocketImpl.java', 309),
  frame('java.net.Socket$SocketInputStream', 'read', 'Socket.java', 1099),
  frame('org.postgresql.core.VisibleBufferedInputStream', 'readMore', 'VisibleBufferedInputStream.java', 161),
  frame('org.postgresql.jdbc.PgPreparedStatement', 'executeQuery', 'PgPreparedStatement.java', 134),
  frame('com.example.report.ReportDao', 'monthlySummary', 'ReportDao.java', 120),
  frame('com.example.report.ReportService', 'build', 'ReportService.java', 57),
];
const BLOCKED = [
  frame('com.example.cache.LocalCache', 'refresh', 'LocalCache.java', 64),
  frame('com.example.cache.LocalCache', 'get', 'LocalCache.java', 40),
  frame('com.example.product.ProductService', 'find', 'ProductService.java', 23),
  frame('io.undertow.servlet.handlers.ServletHandler', 'handleRequest', 'ServletHandler.java', 74),
];
const ACCEPT = [
  frame('sun.nio.ch.EPoll', 'wait', null, -2, true),
  frame('sun.nio.ch.EPollSelectorImpl', 'doSelect', 'EPollSelectorImpl.java', 121),
  frame('sun.nio.ch.SelectorImpl', 'select', 'SelectorImpl.java', 141),
  frame('org.xnio.nio.WorkerThread', 'run', 'WorkerThread.java', 568),
];

function thread(id, name, state, stack, extra = {}) {
  return {
    'thread-id': id, 'thread-name': name, 'thread-state': state, 'blocked-time': -1, 'blocked-count': extra.blocked || 0,
    'waited-time': -1, 'waited-count': 12, 'lock-name': extra.lock, 'lock-owner-id': extra.ownerId === undefined ? -1 : extra.ownerId,
    'lock-owner-name': extra.ownerName, 'in-native': stack[0] && stack[0]['native-method'], suspended: false, daemon: extra.daemon !== false,
    priority: 5, 'stack-trace': stack, 'locked-monitors': extra.monitors || [], 'locked-synchronizers': [],
  };
}

function threads() {
  const list = [];
  let id = 1;
  list.push(thread(id++, 'main', 'WAITING', [frame('java.lang.Object', 'wait0', null, -2, true), frame('java.lang.Object', 'wait', 'Object.java', 366), frame('org.jboss.as.server.Main', 'main', 'Main.java', 120)], { lock: 'java.lang.Object@1b2c3d', daemon: false }));
  list.push(thread(id++, 'Reference Handler', 'RUNNABLE', [frame('java.lang.ref.Reference', 'waitForReferencePendingList', null, -2, true), frame('java.lang.ref.Reference', 'processPendingReferences', 'Reference.java', 246)]));
  for (let i = 1; i <= 4; i++) list.push(thread(id++, `default I/O-${i}`, 'RUNNABLE', ACCEPT));
  const ownerId = id;
  list.push(thread(id++, 'default task-1', 'RUNNABLE', [
    frame('com.example.cache.LocalCache', 'loadAll', 'LocalCache.java', 92),
    ...BLOCKED.slice(0),
  ], { monitors: [{ 'class-name': 'com.example.cache.LocalCache', 'identity-hash-code': 0x5f3a21, 'locked-stack-depth': 1 }] }));
  for (let i = 2; i <= 5; i++) list.push(thread(id++, `default task-${i}`, 'BLOCKED', BLOCKED, { lock: 'com.example.cache.LocalCache@5f3a21', ownerId, ownerName: 'default task-1', blocked: 30 + i }));
  for (let i = 6; i <= 11; i++) list.push(thread(id++, `default task-${i}`, 'TIMED_WAITING', DB_WAIT, { lock: 'java.util.concurrent.Semaphore$NonfairSync@77aa10' }));
  for (let i = 12; i <= 15; i++) list.push(thread(id++, `default task-${i}`, 'RUNNABLE', SOCKET_READ));
  for (let i = 16; i <= 40; i++) list.push(thread(id++, `default task-${i}`, 'WAITING', IDLE_TASK, { lock: 'org.jboss.threads.EnhancedQueueExecutor@1a2b3c' }));
  for (let i = 1; i <= 8; i++) list.push(thread(id++, `ServerService Thread Pool -- ${60 + i}`, 'WAITING', IDLE_TASK, { lock: 'org.jboss.threads.EnhancedQueueExecutor@4d5e6f' }));
  for (let i = 1; i <= 3; i++) list.push(thread(id++, `EJB default - ${i}`, 'WAITING', IDLE_TASK, { lock: 'org.jboss.threads.EnhancedQueueExecutor@7a8b9c' }));
  list.push(thread(id++, 'Periodic Recovery', 'TIMED_WAITING', [frame('java.lang.Object', 'wait0', null, -2, true), frame('com.arjuna.ats.internal.arjuna.recovery.PeriodicRecovery', 'doPeriodicWait', 'PeriodicRecovery.java', 682)], { lock: 'java.lang.Object@9a8b7c' }));
  list.push(thread(id++, 'Transaction Reaper', 'TIMED_WAITING', [frame('java.lang.Object', 'wait0', null, -2, true), frame('com.arjuna.ats.arjuna.coordinator.TransactionReaper', 'waitForCancellations', 'TransactionReaper.java', 391)], { lock: 'java.lang.Object@123abc' }));
  return list;
}

/**
 * Per-instance simulated state. `profile` comes from the server entry's `mock`
 * object so several mock instances can show different numbers.
 */
function createState(profile = {}) {
  const heapMax = (profile.heapMaxMB || 2048) * MB;
  return {
    name: profile.name || 'wildfly-prod-01',
    host: profile.host || 'wildfly-prod-01.example.com',
    pid: profile.pid || 24816,
    state: profile.state || 'running',
    threads: profile.threads || 63,
    heapMax,
    heapLow: heapMax * (profile.heapLow || 0.27),
    heapHigh: heapMax * (profile.heapHigh || 0.73),
    heapUsed: heapMax * (profile.heapLow || 0.27) + 100 * MB,
    metaBaseMB: profile.metaBaseMB || 214,
    started: Date.now() - (profile.uptimeHours || 77) * 3600 * 1000,
    youngGcs: 4210,
    oldGcs: 380,
    down: Boolean(profile.down),
  };
}

function heapNow(m) {
  // Saw-tooth: allocation grows until a GC drops it again.
  m.heapUsed += (15 + Math.random() * 40) * MB * (m.heapMax / (2048 * MB));
  m.youngGcs += Math.floor(Math.random() * 4);
  if (Math.random() < 0.15) m.oldGcs += 1;
  if (m.heapUsed > m.heapHigh) { m.heapUsed = m.heapLow + Math.random() * 0.06 * m.heapMax; m.oldGcs += 1; }
  return m.heapUsed;
}

const ds = (jndi, url, driver, stats, extra = {}) => ({
  'jndi-name': jndi, 'driver-name': driver, 'connection-url': url, 'user-name': 'app', password: 'secret', enabled: true,
  'statistics-enabled': Boolean(stats), 'min-pool-size': 5, 'max-pool-size': 30, 'initial-pool-size': 5,
  'blocking-timeout-wait-millis': 5000, 'idle-timeout-minutes': 15, 'check-valid-connection-sql': 'select 1',
  'background-validation': true, 'transaction-isolation': 'TRANSACTION_READ_COMMITTED', ...extra,
  statistics: stats ? {
    pool: {
      ActiveCount: 30, AvailableCount: 0, InUseCount: Math.round(wave(7000, 4, 26)), IdleCount: 2, MaxUsedCount: 30,
      CreatedCount: 64, DestroyedCount: 34, TimedOut: 12, WaitCount: 213, MaxWaitCount: 6, AverageBlockingTime: 41,
      MaxWaitTime: 4870, AverageCreationTime: 38, MaxCreationTime: 410, AverageGetTime: 52, AverageUsageTime: 311,
      TotalBlockingTime: 9123, BlockingFailureCount: 3,
    },
    jdbc: { PreparedStatementCacheHitCount: 18231, PreparedStatementCacheMissCount: 911, PreparedStatementCacheCurrentSize: 64 },
  } : { pool: {}, jdbc: {} },
});

function makeHandlers(m) {
  const started = m.started;
  return {
  'read-resource:'() {
    return {
      name: m.name, 'product-name': 'WildFly', 'product-version': '37.0.1.Final', 'release-version': '29.0.1.Final',
      'release-codename': '', 'server-state': m.state, 'running-mode': 'NORMAL', 'suspend-state': 'RUNNING',
      'launch-type': 'STANDALONE', 'process-type': 'Server', 'management-major-version': 29, 'management-minor-version': 0,
      'management-micro-version': 0, uuid: '7f1d2c3b-aaaa-4b2c-9e1f-0123456789ab', 'profile-name': null,
    };
  },
  'read-resource:core-service=platform-mbean/type=runtime'() {
    return {
      name: `${m.pid}@${m.name}`, pid: m.pid, 'vm-name': 'OpenJDK 64-Bit Server VM', 'vm-vendor': 'Eclipse Adoptium',
      'vm-version': '21.0.8+9-LTS', 'spec-version': '21', uptime: Date.now() - started, 'start-time': started,
      'input-arguments': ['-D[Standalone]', '-Xms1024m', `-Xmx${Math.round(m.heapMax / MB)}m`, '-XX:MetaspaceSize=96M', '-XX:MaxMetaspaceSize=512m',
        '-XX:+UseG1GC', '-Djava.net.preferIPv4Stack=true', '-Djboss.modules.system.pkgs=org.jboss.byteman',
        '-Djava.awt.headless=true', '-XX:+HeapDumpOnOutOfMemoryError', '-XX:HeapDumpPath=/opt/wildfly/standalone/log'],
      'system-properties': {
        'java.version': '21.0.8', 'java.home': '/usr/lib/jvm/temurin-21', 'jboss.server.config.file.name': 'standalone-full.xml',
        'jboss.server.base.dir': '/opt/wildfly/standalone',
      },
    };
  },
  'read-resource:core-service=server-environment'() {
    return {
      'base-dir': '/opt/wildfly/standalone', 'config-file': '/opt/wildfly/standalone/configuration/standalone-full.xml',
      'log-dir': '/opt/wildfly/standalone/log', 'qualified-host-name': m.host, 'server-name': m.name,
    };
  },
  'read-resource:core-service=platform-mbean/type=operating-system'() {
    return { name: 'Linux', arch: 'amd64', version: '5.14.0-427.el9.x86_64', 'available-processors': 8, 'system-load-average': +wave(9000, 2.5, 1.2).toFixed(2) };
  },
  'read-children-resources:deployment'() {
    return {
      'order-api.war': { 'runtime-name': 'order-api.war', enabled: true, status: 'OK', 'enabled-time': started + 60000 },
      'admin-portal.war': { 'runtime-name': 'admin-portal.war', enabled: true, status: 'OK', 'enabled-time': started + 62000 },
      'batch-jobs.ear': { 'runtime-name': 'batch-jobs.ear', enabled: false, status: 'STOPPED', 'enabled-time': null },
    };
  },
  'read-children-resources:interface'() {
    return { management: { 'resolved-address': '127.0.0.1' }, public: { 'resolved-address': '10.0.12.34' } };
  },
  'read-resource:core-service=platform-mbean/type=class-loading'() {
    return { 'loaded-class-count': 31842 + Math.round(wave(20000, 40, 0)), 'total-loaded-class-count': 33012, 'unloaded-class-count': 1170 };
  },
  'read-resource:core-service=platform-mbean/type=memory'() {
    const used = heapNow(m);
    return {
      'heap-memory-usage': { init: m.heapMax / 2, used, committed: m.heapMax, max: m.heapMax },
      'non-heap-memory-usage': { init: 7 * MB, used: 312 * MB, committed: 336 * MB, max: -1 },
      'object-pending-finalization-count': 0,
    };
  },
  'read-children-resources:core-service=platform-mbean/type=memory-pool'() {
    const meta = wave(30000, 6, m.metaBaseMB) * MB;
    const eden = m.heapUsed * 0.45;
    return {
      Metaspace: { name: 'Metaspace', type: 'NON_HEAP', usage: { init: 0, used: meta, committed: meta + 6 * MB, max: 512 * MB }, 'peak-usage': { init: 0, used: 221 * MB, committed: 226 * MB, max: 512 * MB }, 'memory-manager-names': ['Metaspace Manager'] },
      Compressed_Class_Space: { name: 'Compressed Class Space', type: 'NON_HEAP', usage: { init: 0, used: 27 * MB, committed: 29 * MB, max: 1024 * MB }, 'peak-usage': { init: 0, used: 27 * MB, committed: 29 * MB, max: 1024 * MB } },
      CodeHeap_non_profiled_nmethods: { name: "CodeHeap 'non-profiled nmethods'", type: 'NON_HEAP', usage: { init: 2.4 * MB, used: 41 * MB, committed: 42 * MB, max: 117 * MB } },
      G1_Eden_Space: { name: 'G1 Eden Space', type: 'HEAP', usage: { init: 54 * MB, used: eden, committed: 1100 * MB, max: -1 }, 'peak-usage': { init: 54 * MB, used: 1050 * MB, committed: 1100 * MB, max: -1 } },
      G1_Old_Gen: { name: 'G1 Old Gen', type: 'HEAP', usage: { init: 970 * MB, used: m.heapUsed - eden, committed: 920 * MB, max: m.heapMax }, 'peak-usage': { init: 970 * MB, used: 880 * MB, committed: 920 * MB, max: 2048 * MB } },
      G1_Survivor_Space: { name: 'G1 Survivor Space', type: 'HEAP', usage: { init: 0, used: 18 * MB, committed: 28 * MB, max: -1 } },
    };
  },
  'read-children-resources:core-service=platform-mbean/type=garbage-collector'() {
    return {
      G1_Young_Generation: { name: 'G1 Young Generation', 'collection-count': m.youngGcs, 'collection-time': m.youngGcs * 14, 'memory-pool-names': ['G1 Eden Space', 'G1 Survivor Space', 'G1 Old Gen'] },
      G1_Concurrent_GC: { name: 'G1 Concurrent GC', 'collection-count': m.oldGcs, 'collection-time': m.oldGcs * 6 },
      G1_Old_Generation: { name: 'G1 Old Generation', 'collection-count': 2, 'collection-time': 1830 },
    };
  },
  'read-resource:core-service=platform-mbean/type=threading'() {
    return { 'thread-count': m.threads, 'peak-thread-count': m.threads + 25, 'daemon-thread-count': 58, 'total-started-thread-count': 412 };
  },
  'dump-all-threads:core-service=platform-mbean/type=threading': threads,
  'find-deadlocked-threads:core-service=platform-mbean/type=threading'() { return undefined; },
  'read-resource:subsystem=datasources'() {
    return {
      'data-source': {
        ExampleDS: ds('java:jboss/datasources/ExampleDS', 'jdbc:h2:mem:test;DB_CLOSE_DELAY=-1', 'h2', false, { 'min-pool-size': undefined, 'max-pool-size': undefined }),
        OrderDS: ds('java:jboss/datasources/OrderDS', 'jdbc:postgresql://db-prod:5432/orders', 'postgresql', true),
      },
      'xa-data-source': {
        BillingXADS: {
          ...ds('java:jboss/datasources/BillingXADS', null, 'oracle', true),
          'xa-datasource-properties': { URL: { value: 'jdbc:oracle:thin:@ora-prod:1521/BILL' } },
          statistics: { pool: { ActiveCount: 8, AvailableCount: 22, InUseCount: 3, IdleCount: 5, MaxUsedCount: 11, CreatedCount: 12, DestroyedCount: 4, TimedOut: 0, WaitCount: 0, MaxWaitCount: 0, AverageBlockingTime: 0, MaxWaitTime: 0, AverageCreationTime: 55, MaxCreationTime: 130, AverageGetTime: 1, AverageUsageTime: 24, TotalBlockingTime: 0, BlockingFailureCount: 0 }, jdbc: {} },
        },
      },
      'jdbc-driver': {
        h2: { 'driver-module-name': 'com.h2database.h2', 'driver-xa-datasource-class-name': 'org.h2.jdbcx.JdbcDataSource', 'driver-major-version': 2, 'driver-minor-version': 2, 'jdbc-compliant': true },
        postgresql: { 'driver-module-name': 'org.postgresql', 'driver-class-name': 'org.postgresql.Driver', 'driver-major-version': 42, 'driver-minor-version': 7, 'jdbc-compliant': true },
        oracle: { 'driver-module-name': 'com.oracle.ojdbc', 'driver-xa-datasource-class-name': 'oracle.jdbc.xa.client.OracleXADataSource', 'driver-major-version': 23, 'driver-minor-version': 5, 'jdbc-compliant': true },
      },
    };
  },
  'test-connection-in-pool:subsystem=datasources/data-source=OrderDS'() { return [true]; },
  'test-connection-in-pool:subsystem=datasources/data-source=ExampleDS'() { return [true]; },
  'test-connection-in-pool:subsystem=datasources/xa-data-source=BillingXADS'() { return [true]; },
  };
}

class MockClient {
  constructor(server) {
    this.server = server;
    this.m = createState(server.mock);
    this.handlers = makeHandlers(this.m);
  }

  run(op) {
    if (op.operation === 'read-attribute') {
      // memory pools are registered by name under the pool list
      const pool = (op.address || []).find((x) => x.name);
      if (!pool) {
        const res = this.run({ ...op, operation: 'read-resource' });
        return res && res[op.name] !== undefined ? res[op.name] : null;
      }
      {
        const parent = this.run({ operation: 'read-children-resources', address: (op.address || []).filter((x) => !x.name) });
        return parent[pool.name] ? parent[pool.name][op.name] : null;
      }
    }
    if (op.operation === 'read-children-names') {
      return Object.keys(this.run({ ...op, operation: 'read-children-resources' }) || {});
    }
    const atRoot = (op.address || []).length === 0;
    const k = op.operation === 'read-children-resources' && atRoot
      ? `${op.operation}:${op['child-type']}`
      : `${op.operation}:${key(op.address)}`;
    if (this.m.down) throw Object.assign(new Error('WildFly 연결 실패: connect ECONNREFUSED'), { status: 502 });
    const h = this.handlers[k];
    if (!h) throw new Error(`WFLYCTL0030: No resource definition is registered for address ${key(op.address)} (${op.operation})`);
    const v = h();
    return v === undefined ? null : JSON.parse(JSON.stringify(v));
  }

  async execute(op) {
    await new Promise((r) => setTimeout(r, 30));
    return this.run(op);
  }

  async composite(steps) {
    await new Promise((r) => setTimeout(r, 30));
    if (this.m.down) throw Object.assign(new Error('WildFly 연결 실패: connect ECONNREFUSED'), { status: 502 });
    return steps.map((s) => {
      try { const v = this.run(s); return v === null ? undefined : v; } catch (_) { return undefined; }
    });
  }
}

module.exports = { MockClient };
