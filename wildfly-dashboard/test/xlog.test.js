'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { XLOG_PATTERN, compilePattern, serviceName, FileTail, XLogStore, parseClfTime } = require('../src/xlog');

test('parses the dashboard access-log pattern (real WildFly 37 line)', () => {
  const parse = compilePattern(XLOG_PATTERN);
  const t = parse('127.0.0.1 2026-10-06T00:28:38.067+0000 "GET /shop/order.jsp?ms=3000 HTTP/1.1" 200 8 3482 "default task-3"');
  assert.strictEqual(t.end, Date.UTC(2026, 9, 6, 0, 28, 38, 67));
  assert.strictEqual(t.elapsed, 3482);
  assert.strictEqual(t.status, 200);
  assert.strictEqual(t.uri, '/shop/order.jsp?ms=3000');
  assert.strictEqual(t.thread, 'default task-3');
  // "-" means the request start time was not recorded yet (reload pending): reported as skipped
  assert.deepStrictEqual(parse('127.0.0.1 2026-10-06T00:27:53.826+0000 "GET / HTTP/1.1" 200 1391 - "default task-2"'),
    { skipped: 'no-elapsed', end: Date.UTC(2026, 9, 6, 0, 27, 53, 826) });
  assert.strictEqual(parse('garbage'), null);
});

test('parses common log format with %D or %T, rejects patterns without elapsed time', () => {
  const d = compilePattern('%h %l %u %t "%r" %s %b %D')('10.0.0.1 - - [06/Oct/2026:09:15:01 +0900] "POST /api/orders/1 HTTP/1.1" 500 312 2875');
  assert.deepStrictEqual([d.end, d.elapsed, d.status, d.method], [Date.UTC(2026, 9, 6, 0, 15, 1), 2875, 500, 'POST']);
  const t = compilePattern('%h %l %u %t "%r" %s %b %T')('1.2.3.4 - - [06/Oct/2026:09:15:01 +0000] "GET /a HTTP/1.1" 200 5 0.153');
  assert.strictEqual(t.elapsed, 153);
  assert.strictEqual(compilePattern('common'), null);
  assert.strictEqual(parseClfTime('06/Oct/2026:00:00:00 -0100'), Date.UTC(2026, 9, 6, 1));
});

test('service names fold ids and drop query strings', () => {
  assert.strictEqual(serviceName('GET', '/api/orders/123/items/9;jsessionid=x?q=1'), 'GET /api/orders/{id}/items/{id}');
});

test('tails a file across appends, partial lines and rotation', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tail-'));
  const file = path.join(dir, 'access.log');
  fs.writeFileSync(file, 'old1\nold2\n');
  const tail = new FileTail(file, { backfillBytes: 1024 });
  assert.deepStrictEqual(tail.read().lines, ['old1', 'old2']);
  fs.appendFileSync(file, 'a\nb-par');
  assert.deepStrictEqual(tail.read().lines, ['a']);
  fs.appendFileSync(file, 'tial\n');
  assert.deepStrictEqual(tail.read().lines, ['b-partial']);
  fs.renameSync(file, `${file}.1`); // rotation: a new file appears under the same name
  fs.writeFileSync(file, 'new1\n');
  assert.deepStrictEqual(tail.read().lines, ['new1']);
  fs.writeFileSync(file, ''); // truncation
  fs.appendFileSync(file, 'x\n');
  assert.deepStrictEqual(tail.read().lines, ['x']);
});

test('store returns transactions after a sequence number within the window', () => {
  const s = new XLogStore(3);
  for (let i = 1; i <= 5; i++) s.add({ end: i * 1000 });
  assert.deepStrictEqual(s.items.map((t) => t.seq), [3, 4, 5]);
  assert.deepStrictEqual(s.since(3, 0).map((t) => t.seq), [4, 5]);
  assert.deepStrictEqual(s.since(0, 4500).map((t) => t.seq), [5]);
});
