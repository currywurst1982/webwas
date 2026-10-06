'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseCommandLine, scan, resolveExpression } = require('../src/discovery');

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

test('reads the port offset from the -c configuration file (shared base dir)', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-base-'));
  fs.mkdirSync(path.join(base, 'configuration'));
  const xml = (offset) => `<server><interfaces><interface name="management">
      <inet-address value="\${jboss.bind.address.management:127.0.0.1}"/></interface></interfaces>
    <socket-binding-group name="standard-sockets" default-interface="public" port-offset="${offset}">
      <socket-binding name="management-http" interface="management" port="\${jboss.management.http.port:9990}"/>
    </socket-binding-group></server>`;
  fs.writeFileSync(path.join(base, 'configuration', 'standalone-was1.xml'), xml('${jboss.socket.binding.port-offset:0}'));
  fs.writeFileSync(path.join(base, 'configuration', 'standalone-was2.xml'), xml('${jboss.socket.binding.port-offset:100}'));
  const run = (...extra) => parseCommandLine(java(`-Djboss.server.base.dir=${base}`, ...extra));
  assert.strictEqual(run('-c', 'standalone-was1.xml').url, 'http://127.0.0.1:9990/management');
  assert.strictEqual(run('-c', 'standalone-was2.xml').url, 'http://127.0.0.1:10090/management');
  // a -D on the command line still overrides the default inside the expression
  assert.strictEqual(run('-c', 'standalone-was2.xml', '-Djboss.socket.binding.port-offset=200').port, 10190);
  assert.strictEqual(run('-c', 'standalone-was1.xml', '-bmanagement', '10.1.1.1').address, '10.1.1.1');
});

test('resolves WildFly expressions', () => {
  assert.strictEqual(resolveExpression('${a:5}', {}), '5');
  assert.strictEqual(resolveExpression('${a:5}', { a: '7' }), '7');
  assert.strictEqual(resolveExpression('${a,b:5}', { b: '9' }), '9');
  assert.strictEqual(resolveExpression('100', {}), '100');
});
