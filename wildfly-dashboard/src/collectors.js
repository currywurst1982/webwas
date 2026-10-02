'use strict';

// Reads monitoring data from WildFly through the management model.
// All JVM data comes from /core-service=platform-mbean, which mirrors the
// java.lang.management MXBeans of the server JVM.

const { addr } = require('./wildfly-client');

const PM = '/core-service=platform-mbean';

const readRes = (path, extra = {}) => ({
  operation: 'read-resource', address: addr(path), 'include-runtime': true, ...extra,
});

async function serverInfo(client) {
  const [root, runtime, os, deployments, classLoading, ifaces, env] = await client.composite([
    readRes('/', { 'attributes-only': true }),
    readRes(`${PM}/type=runtime`),
    readRes(`${PM}/type=operating-system`),
    { operation: 'read-children-resources', address: [], 'child-type': 'deployment', 'include-runtime': true },
    readRes(`${PM}/type=class-loading`),
    { operation: 'read-children-resources', address: [], 'child-type': 'interface', 'include-runtime': true },
    readRes('/core-service=server-environment'),
  ]);
  if (!root) throw new Error('WildFly 서버 정보를 읽지 못했습니다');

  const sysProps = (runtime && runtime['system-properties']) || {};
  const serverEnv = env || {};
  return {
    server: {
      name: root.name,
      productName: root['product-name'],
      productVersion: root['product-version'],
      releaseVersion: root['release-version'],
      releaseCodename: root['release-codename'],
      serverState: root['server-state'],
      runningMode: root['running-mode'],
      suspendState: root['suspend-state'],
      launchType: root['launch-type'],
      processType: root['process-type'],
      managementVersion: [root['management-major-version'], root['management-minor-version'], root['management-micro-version']]
        .filter((v) => v !== undefined).join('.'),
      uuid: root.uuid,
      profile: root['profile-name'],
      configFile: serverEnv['config-file'] || sysProps['jboss.server.config.file.name'] || null,
      baseDir: serverEnv['base-dir'] || sysProps['jboss.server.base.dir'] || null,
      logDir: serverEnv['log-dir'] || null,
      hostName: serverEnv['qualified-host-name'] || serverEnv['host-name'] || null,
    },
    jvm: runtime && {
      name: runtime.name,
      pid: runtime.pid !== undefined ? runtime.pid : parsePid(runtime.name),
      vmName: runtime['vm-name'],
      vmVendor: runtime['vm-vendor'],
      vmVersion: runtime['vm-version'],
      specVersion: runtime['spec-version'],
      javaVersion: sysProps['java.version'],
      javaHome: sysProps['java.home'],
      uptime: runtime.uptime,
      startTime: runtime['start-time'],
      inputArguments: runtime['input-arguments'] || [],
    },
    os: os && {
      name: os.name,
      arch: os.arch,
      version: os.version,
      availableProcessors: os['available-processors'],
      systemLoadAverage: os['system-load-average'],
    },
    classLoading: classLoading && {
      loaded: classLoading['loaded-class-count'],
      totalLoaded: classLoading['total-loaded-class-count'],
      unloaded: classLoading['unloaded-class-count'],
    },
    interfaces: Object.entries(ifaces || {}).map(([name, v]) => ({
      name, address: v['resolved-address'] || v['inet-address'] || null,
    })),
    deployments: Object.entries(deployments || {}).map(([name, d]) => ({
      name,
      runtimeName: d['runtime-name'],
      enabled: d.enabled,
      status: d.status,
      enabledTime: d['enabled-time'],
    })),
  };
}

function parsePid(name) {
  const m = /^(\d+)@/.exec(name || '');
  return m ? Number(m[1]) : null;
}

async function memory(client) {
  const [mem, pools, gcs, classLoading] = await client.composite([
    readRes(`${PM}/type=memory`),
    { operation: 'read-children-resources', address: addr(`${PM}/type=memory-pool`), 'child-type': 'name', 'include-runtime': true },
    { operation: 'read-children-resources', address: addr(`${PM}/type=garbage-collector`), 'child-type': 'name', 'include-runtime': true },
    readRes(`${PM}/type=class-loading`),
  ]);
  if (!mem) throw new Error('메모리 정보를 읽지 못했습니다');

  // WildFly registers pools/collectors with spaces replaced by '_' (e.g. "G1_Old_Gen").
  const poolList = Object.entries(pools || {}).map(([key, p]) => ({
    name: (p.name || key).replace(/_/g, ' '),
    key,
    type: p.type,
    usage: usage(p.usage),
    peak: usage(p['peak-usage']),
    collectionUsage: usage(p['collection-usage']),
    managers: p['memory-manager-names'] || [],
  }));
  const metaspace = poolList.find((p) => /^metaspace$/i.test(p.name));
  const compressedClass = poolList.find((p) => /compressed.class/i.test(p.name));

  return {
    timestamp: Date.now(),
    heap: usage(mem['heap-memory-usage']),
    nonHeap: usage(mem['non-heap-memory-usage']),
    pendingFinalization: mem['object-pending-finalization-count'],
    metaspace: metaspace || null,
    compressedClassSpace: compressedClass || null,
    pools: poolList,
    gc: Object.entries(gcs || {}).map(([key, g]) => ({
      name: (g.name || key).replace(/_/g, ' '),
      count: g['collection-count'],
      time: g['collection-time'],
      pools: g['memory-pool-names'] || [],
    })),
    classLoading: classLoading && {
      loaded: classLoading['loaded-class-count'],
      totalLoaded: classLoading['total-loaded-class-count'],
      unloaded: classLoading['unloaded-class-count'],
    },
  };
}

function usage(u) {
  if (!u) return null;
  const max = u.max === undefined || u.max < 0 ? null : u.max;
  return {
    init: u.init, used: u.used, committed: u.committed, max,
    // Without a max (e.g. Metaspace with no MaxMetaspaceSize) a percentage would be misleading.
    percent: max ? +(100 * u.used / max).toFixed(1) : null,
  };
}

const SECRET_KEYS = /password|credential|secret|security-domain-password/i;

function stripSecrets(obj) {
  if (Array.isArray(obj)) return obj.map(stripSecrets);
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SECRET_KEYS.test(k)) out[k] = v === undefined || v === null ? v : '******';
    else out[k] = stripSecrets(v);
  }
  return out;
}

async function datasources(client) {
  const res = await client.execute({
    operation: 'read-resource', address: addr('/subsystem=datasources'), recursive: true, 'include-runtime': true,
    'resolve-expressions': true,
  });
  const list = [];
  for (const [kind, key] of [['data-source', false], ['xa-data-source', true]]) {
    for (const [name, ds] of Object.entries(res[kind] || {})) {
      const stats = ds.statistics || {};
      const pool = stats.pool || null;
      const jdbc = stats.jdbc || null;
      list.push({
        name,
        xa: key,
        jndiName: ds['jndi-name'],
        driver: ds['driver-name'],
        connectionUrl: ds['connection-url'] || xaUrl(ds),
        userName: ds['user-name'] || null,
        enabled: ds.enabled !== false,
        statisticsEnabled: Boolean(ds['statistics-enabled']),
        // Undefined attributes come back as null; show the IronJacamar defaults.
        minPoolSize: ds['min-pool-size'] ?? 0,
        maxPoolSize: ds['max-pool-size'] ?? 20,
        initialPoolSize: ds['initial-pool-size'],
        blockingTimeout: ds['blocking-timeout-wait-millis'] ?? 30000,
        idleTimeoutMinutes: ds['idle-timeout-minutes'],
        validConnectionSql: ds['check-valid-connection-sql'] || null,
        backgroundValidation: ds['background-validation'],
        transactionIsolation: ds['transaction-isolation'] || null,
        pool: pool && pickPool(pool),
        jdbc: jdbc && {
          preparedStatementCacheHitCount: jdbc.PreparedStatementCacheHitCount,
          preparedStatementCacheMissCount: jdbc.PreparedStatementCacheMissCount,
          preparedStatementCacheCurrentSize: jdbc.PreparedStatementCacheCurrentSize,
        },
      });
    }
  }
  const drivers = Object.entries(res['jdbc-driver'] || {}).map(([name, d]) => ({
    name,
    module: d['driver-module-name'],
    className: d['driver-class-name'] || d['driver-datasource-class-name'] || d['driver-xa-datasource-class-name'] || null,
    version: d['driver-major-version'] !== undefined ? `${d['driver-major-version']}.${d['driver-minor-version']}` : null,
    jdbcCompliant: d['jdbc-compliant'],
  }));
  return { datasources: stripSecrets(list), drivers };
}

function xaUrl(ds) {
  const props = ds['xa-datasource-properties'] || {};
  const url = props.URL || props.Url || props.url;
  if (url) return url.value;
  const host = props.ServerName && props.ServerName.value;
  const db = props.DatabaseName && props.DatabaseName.value;
  return host ? `${host}${db ? '/' + db : ''}` : null;
}

function pickPool(p) {
  return {
    activeCount: p.ActiveCount,
    availableCount: p.AvailableCount,
    inUseCount: p.InUseCount,
    idleCount: p.IdleCount,
    maxUsedCount: p.MaxUsedCount,
    createdCount: p.CreatedCount,
    destroyedCount: p.DestroyedCount,
    timedOut: p.TimedOut,
    waitCount: p.WaitCount,
    maxWaitCount: p.MaxWaitCount,
    averageBlockingTime: p.AverageBlockingTime,
    maxWaitTime: p.MaxWaitTime,
    averageCreationTime: p.AverageCreationTime,
    maxCreationTime: p.MaxCreationTime,
    averageGetTime: p.AverageGetTime,
    averageUsageTime: p.AverageUsageTime,
    totalBlockingTime: p.TotalBlockingTime,
    blockingFailureCount: p.BlockingFailureCount,
    leakDetected: p.ConnectionLeakDetected !== undefined ? p.ConnectionLeakDetected : null,
  };
}

async function testConnection(client, name, xa) {
  const path = `/subsystem=datasources/${xa ? 'xa-data-source' : 'data-source'}=${name}`;
  const started = Date.now();
  const result = await client.execute({ operation: 'test-connection-in-pool', address: addr(path) });
  return { ok: Array.isArray(result) ? result.every(Boolean) : Boolean(result), elapsedMs: Date.now() - started };
}

async function threadDump(client) {
  const [threading, threads, deadlocked] = await client.composite([
    readRes(`${PM}/type=threading`),
    { operation: 'dump-all-threads', address: addr(`${PM}/type=threading`), 'locked-monitors': true, 'locked-synchronizers': true },
    { operation: 'find-deadlocked-threads', address: addr(`${PM}/type=threading`) },
  ]);
  if (!threads) throw new Error('쓰레드 덤프를 가져오지 못했습니다');
  return {
    timestamp: Date.now(),
    summary: threading && {
      threadCount: threading['thread-count'],
      peakThreadCount: threading['peak-thread-count'],
      daemonThreadCount: threading['daemon-thread-count'],
      totalStartedThreadCount: threading['total-started-thread-count'],
    },
    deadlockedIds: Array.isArray(deadlocked) ? deadlocked : [],
    threads: threads.map(normalizeThread),
  };
}

function normalizeThread(t) {
  return {
    id: t['thread-id'],
    name: t['thread-name'],
    state: t['thread-state'],
    blockedCount: t['blocked-count'],
    blockedTime: t['blocked-time'],
    waitedCount: t['waited-count'],
    waitedTime: t['waited-time'],
    lockName: t['lock-name'] || null,
    lockOwnerId: t['lock-owner-id'] >= 0 ? t['lock-owner-id'] : null,
    lockOwnerName: t['lock-owner-name'] || null,
    inNative: t['in-native'],
    suspended: t.suspended,
    daemon: t.daemon,
    priority: t.priority,
    stack: (t['stack-trace'] || []).map((f) => ({
      className: f['class-name'],
      methodName: f['method-name'],
      fileName: f['file-name'] || null,
      lineNumber: f['line-number'],
      nativeMethod: f['native-method'],
    })),
    lockedMonitors: (t['locked-monitors'] || []).map((m) => ({
      className: m['class-name'],
      identityHashCode: m['identity-hash-code'],
      depth: m['locked-stack-depth'],
    })),
    lockedSynchronizers: (t['locked-synchronizers'] || []).map((s) => ({
      className: s['class-name'],
      identityHashCode: s['identity-hash-code'],
    })),
  };
}

module.exports = { serverInfo, memory, datasources, testConnection, threadDump, stripSecrets };
