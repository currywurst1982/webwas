'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const { WildFlyClient, parseChallenges } = require('../src/wildfly-client');
const collectors = require('../src/collectors');
const { MockClient } = require('../src/mock');

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

// A fake /management endpoint that enforces HTTP Digest like the WildFly ManagementRealm.
function fakeWildFly(user, password) {
  const realm = 'ManagementRealm';
  const nonce = crypto.randomBytes(8).toString('hex');
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const auth = req.headers.authorization || '';
      const p = parseChallenges(auth)[0];
      const ok = p && p.scheme === 'digest' && p.params.username === user && p.params.response ===
        md5(`${md5(`${user}:${realm}:${password}`)}:${p.params.nonce}:${p.params.nc}:${p.params.cnonce}:${p.params.qop}:${md5(`POST:${p.params.uri}`)}`);
      if (!ok) {
        res.writeHead(401, { 'WWW-Authenticate': [
          `Digest realm="${realm}", nonce="${nonce}", opaque="00000000000000000000000000000000", algorithm=SHA-256, qop=auth`,
          `Digest realm="${realm}", nonce="${nonce}", opaque="00000000000000000000000000000000", algorithm=MD5, qop=auth`,
        ] });
        return res.end();
      }
      const op = JSON.parse(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (op.operation === 'composite') {
        return res.end(JSON.stringify({ outcome: 'success', result: { 'step-1': { outcome: 'success', result: 'running' } } }));
      }
      res.end(JSON.stringify({ outcome: 'success', result: { op: op.operation } }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

test('authenticates with HTTP Digest and reuses the challenge', async () => {
  const srv = await fakeWildFly('admin', 's3cret');
  const url = `http://127.0.0.1:${srv.address().port}/management`;
  try {
    const client = new WildFlyClient({ url, username: 'admin', password: 's3cret' });
    assert.deepStrictEqual(await client.execute({ operation: 'read-resource', address: [] }), { op: 'read-resource' });
    assert.strictEqual(client.nc, 1);
    await client.execute({ operation: 'whoami', address: [] });
    assert.strictEqual(client.nc, 2, 'second call should reuse the cached nonce');
    assert.deepStrictEqual(await client.composite([{ operation: 'read-attribute' }]), ['running']);

    const bad = new WildFlyClient({ url, username: 'admin', password: 'wrong' });
    await assert.rejects(bad.execute({ operation: 'read-resource', address: [] }), /인증 실패/);
  } finally {
    srv.close();
  }
});

test('collectors work against the mock management model', async () => {
  const client = new MockClient({});
  const info = await collectors.serverInfo(client);
  assert.strictEqual(info.server.serverState, 'running');
  assert.strictEqual(info.jvm.pid, 24816);
  const mem = await collectors.memory(client);
  assert.ok(mem.heap.used > 0 && mem.heap.max > 0);
  assert.strictEqual(mem.metaspace.name, 'Metaspace');
  const ds = await collectors.datasources(client);
  assert.strictEqual(ds.datasources.length, 3);
  assert.ok(!JSON.stringify(ds).includes('secret'), 'passwords must be masked');
  const td = await collectors.threadDump(client);
  assert.ok(td.threads.length > 10);
});
