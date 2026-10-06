'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { moduleDriverVersion, jarVersion, parseManifest } = require('../src/driver-version');

/** Writes a minimal zip with the given entries ({ name, text, deflate }). */
function writeZip(file, entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const raw = Buffer.from(e.text);
    const data = e.deflate ? zlib.deflateRawSync(raw) : raw;
    const name = Buffer.from(e.name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(e.deflate ? 8 : 0, 8);
    lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(e.deflate ? 8 : 0, 10);
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    locals.push(lh, name, data);
    centrals.push(ch, name);
    offset += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  fs.writeFileSync(file, Buffer.concat([...locals, cd, eocd]));
}

const manifest = (v) => `Manifest-Version: 1.0\r\nImplementation-Title: Test Driver\r\nImplementation-Version: ${v}\r\n\r\nName: x\r\nImplementation-Version: 0\r\n`;

test('reads the version from stored and deflated manifests', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jar-'));
  writeZip(path.join(dir, 'a.jar'), [{ name: 'a/A.class', text: 'x' }, { name: 'META-INF/MANIFEST.MF', text: manifest('42.7.4') }]);
  writeZip(path.join(dir, 'b.jar'), [{ name: 'META-INF/MANIFEST.MF', text: manifest('23.5.0.24.07'), deflate: true }]);
  writeZip(path.join(dir, 'c.jar'), [{ name: 'a/A.class', text: 'x' }]);
  assert.strictEqual(jarVersion(path.join(dir, 'a.jar')), '42.7.4');
  assert.strictEqual(jarVersion(path.join(dir, 'b.jar')), '23.5.0.24.07');
  assert.strictEqual(jarVersion(path.join(dir, 'c.jar')), null);
  assert.strictEqual(jarVersion(path.join(dir, 'missing.jar')), null);
});

test('manifest continuation lines and main section only', () => {
  const a = parseManifest('Implementation-Version: 1.2.\r\n 3-final\r\n\r\nImplementation-Version: 9\r\n');
  assert.strictEqual(a['Implementation-Version'], '1.2.3-final');
});

test('finds the driver jar of a user module before the base layer', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wfhome-'));
  const user = path.join(home, 'modules', 'org', 'postgresql', 'main');
  const base = path.join(home, 'modules', 'system', 'layers', 'base', 'org', 'postgresql', 'main');
  for (const [dir, v] of [[user, '42.7.4'], [base, '42.2.0']]) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'module.xml'), '<module name="org.postgresql"><resources><resource-root path="postgresql.jar"/></resources></module>');
    writeZip(path.join(dir, 'postgresql.jar'), [{ name: 'META-INF/MANIFEST.MF', text: manifest(v), deflate: true }]);
  }
  assert.deepStrictEqual(moduleDriverVersion(home, 'org.postgresql', 'main'), { version: '42.7.4', jar: 'postgresql.jar' });
  assert.strictEqual(moduleDriverVersion(home, 'com.unknown', 'main'), null);
  assert.strictEqual(moduleDriverVersion(null, 'org.postgresql'), null);
});
