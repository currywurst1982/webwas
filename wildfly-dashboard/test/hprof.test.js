'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseHprof, parseClassHistogram, prettyClassName } = require('../src/hprof/parser');

// Builds a tiny HPROF 1.0.2 file with 8-byte identifiers.
function buildHprof() {
  const parts = [];
  const u1 = (v) => Buffer.from([v]);
  const u2 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; };
  const u4 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };
  const id = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
  const record = (tag, body) => parts.push(u1(tag), u4(0), u4(body.length), body);

  parts.push(Buffer.from('JAVA PROFILE 1.0.2\0', 'latin1'), u4(8), u4(0), u4(0));
  const names = { 1: 'com/example/Customer', 2: 'java/lang/ClassLoader', 3: '[Ljava/lang/Object;', 4: 'name' };
  for (const [sid, s] of Object.entries(names)) record(0x01, Buffer.concat([id(sid), Buffer.from(s)]));
  record(0x02, Buffer.concat([u4(1), id(0x100), u4(0), id(1)]));
  record(0x02, Buffer.concat([u4(2), id(0x200), u4(0), id(2)]));
  record(0x02, Buffer.concat([u4(3), id(0x300), u4(0), id(3)]));

  const heap = [];
  const classDump = (cid, loader, fields) => Buffer.concat([
    u1(0x20), id(cid), u4(0), id(0), id(loader), id(0), id(0), id(0), id(0), u4(16),
    u2(1), u2(1), u1(10), u4(42), // one constant pool entry (int)
    u2(1), id(4), u1(2), id(0), // one static object field
    u2(fields), ...Array.from({ length: fields }, () => Buffer.concat([id(4), u1(10)])),
  ]);
  heap.push(classDump(0x200, 0, 0));
  heap.push(classDump(0x100, 0x900, 2));
  heap.push(classDump(0x300, 0, 0));
  heap.push(Buffer.concat([u1(0xff), id(0x1000)])); // GC root
  heap.push(Buffer.concat([u1(0x21), id(0x900), u4(0), id(0x200), u4(8), Buffer.alloc(8)])); // the class loader instance
  for (let i = 0; i < 3; i++) heap.push(Buffer.concat([u1(0x21), id(0x1000 + i), u4(0), id(0x100), u4(8), Buffer.alloc(8)]));
  heap.push(Buffer.concat([u1(0x22), id(0x2000), u4(0), u4(4), id(0x300), Buffer.alloc(32)]));
  heap.push(Buffer.concat([u1(0x23), id(0x3000), u4(0), u4(100), u1(8), Buffer.alloc(100)])); // byte[100]
  heap.push(Buffer.concat([u1(0x23), id(0x3001), u4(0), u4(10), u1(10), Buffer.alloc(40)])); // int[10]
  record(0x1c, Buffer.concat(heap));
  record(0x2c, Buffer.alloc(0)); // HEAP DUMP END
  return Buffer.concat(parts);
}

test('parses a synthetic HPROF file', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hprof-')), 'x.hprof');
  fs.writeFileSync(file, buildHprof());
  const progress = [];
  const r = parseHprof(file, { onProgress: (p) => progress.push(p) });

  assert.strictEqual(r.format, 'JAVA PROFILE 1.0.2');
  assert.strictEqual(r.idSize, 8);
  assert.strictEqual(r.totals.instances, 4);
  assert.strictEqual(r.totals.arrays, 3);
  assert.strictEqual(r.totals.classes, 3);
  assert.strictEqual(r.totals.gcRoots, 1);
  const byName = Object.fromEntries(r.histogram.map((h) => [h.className, h]));
  assert.strictEqual(byName['com.example.Customer'].count, 3);
  assert.strictEqual(byName['com.example.Customer'].bytes, 3 * 24); // align8(16 + 8)
  assert.strictEqual(byName['byte[]'].bytes, 120); // align8(16 + 100)
  assert.strictEqual(byName['int[]'].bytes, 56);
  assert.strictEqual(byName['java.lang.Object[]'].bytes, 48);
  const loader = r.classLoaders.find((l) => l.id === '0x900');
  assert.strictEqual(loader.loaderClass, 'java.lang.ClassLoader');
  assert.strictEqual(loader.classCount, 1);
  assert.strictEqual(progress[progress.length - 1], 100);
});

test('rejects non-HPROF files', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hprof-')), 'bad.hprof');
  fs.writeFileSync(file, 'hello world, this is not a heap dump at all');
  assert.throws(() => parseHprof(file), /HPROF/);
});

test('parses jmap -histo output', () => {
  const r = parseClassHistogram(` num     #instances         #bytes  class name (module)
-------------------------------------------------------
   1:          5000        4000000  [B (java.base@21)
   2:          1000        1000000  com.example.Order
Total          6000        5000000
`);
  assert.strictEqual(r.histogram[0].className, 'byte[]');
  assert.strictEqual(r.histogram[1].percent, 20);
  assert.ok(r.findings.some((f) => f.text.includes('com.example.Order')));
});

test('formats JVM class names', () => {
  assert.strictEqual(prettyClassName('[[I'), 'int[][]');
  assert.strictEqual(prettyClassName('[Ljava/lang/String;'), 'java.lang.String[]');
  assert.strictEqual(prettyClassName('java/util/HashMap$Node'), 'java.util.HashMap$Node');
});
