'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseCommandLine, scan } = require('../src/discovery');

const java = (...extra) => ['/usr/bin/java', '-D[Standalone]', '-Xmx1g', '-jar', '/opt/wildfly/jboss-modules.jar',
  '-mp', '/opt/wildfly/modules', 'org.jboss.as.standalone', '-Djboss.home.dir=/opt/wildfly', ...extra];

test('derives the management URL from the command line', () => {
  assert.strictEqual(parseCommandLine(java()).url, 'http://127.0.0.1:9990/management');
  const r = parseCommandLine(java('-Djboss.socket.binding.port-offset=100', '-bmanagement', '10.0.0.5',
    '-Djboss.server.base.dir=/srv/was02', '-c', 'standalone-full.xml'));
  assert.strictEqual(r.url, 'http://10.0.0.5:10090/management');
  assert.strictEqual(r.baseDir, '/srv/was02');
  assert.strictEqual(r.configFile, 'standalone-full.xml');
  assert.strictEqual(parseCommandLine(java('-bmanagement=0.0.0.0', '-Djboss.management.http.port=19990')).url,
    'http://127.0.0.1:19990/management');
  assert.strictEqual(parseCommandLine(java('-Djboss.bind.address.management=::1')).url, 'http://[::1]:9990/management');
});

test('ignores non-WildFly and domain processes', () => {
  assert.strictEqual(parseCommandLine(['/usr/bin/java', '-jar', 'app.jar']), null);
  const hc = ['/usr/bin/java', '-D[Host Controller]', '-jar', '/opt/wildfly/jboss-modules.jar'];
  assert.strictEqual(parseCommandLine(hc).kind, 'host-controller');
  const ds = ['/usr/bin/java', '-D[Server:server-one]', '-jar', '/opt/wildfly/jboss-modules.jar'];
  assert.strictEqual(parseCommandLine(ds).kind, 'domain-server');
});

test('scans a proc directory for standalone servers', () => {
  const proc = fs.mkdtempSync(path.join(os.tmpdir(), 'proc-'));
  const add = (pid, args) => {
    fs.mkdirSync(path.join(proc, String(pid)));
    fs.writeFileSync(path.join(proc, String(pid), 'cmdline'), `${args.join('\0')}\0`);
    fs.writeFileSync(path.join(proc, String(pid), 'status'), 'Name:\tjava\nUid:\t0\t0\t0\t0\n');
  };
  add(200, java('-Djboss.socket.binding.port-offset=100'));
  add(100, java());
  add(300, ['/bin/bash', 'standalone.sh']);
  const found = scan(proc);
  assert.deepStrictEqual(found.map((f) => [f.pid, f.port]), [[100, 9990], [200, 10090]]);
  assert.strictEqual(found[0].user, 'root');
});
