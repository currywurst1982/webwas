'use strict';

// Full JDBC driver versions (e.g. 42.7.4) from the driver jar's MANIFEST.MF.
// The management model only reports major.minor (installed-drivers-list) and
// often nothing at all on the jdbc-driver resource, so when the dashboard runs
// on the WildFly host it reads the module's jar directly.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

/** Reads one entry from a zip/jar without extracting it (central directory lookup). */
function readZipEntry(file, name) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const tailLen = Math.min(size, 65557); // EOCD (22 bytes) + max comment
    const tail = Buffer.alloc(tailLen);
    fs.readSync(fd, tail, 0, tailLen, size - tailLen);
    const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (eocd < 0) return null;
    const entries = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    const cd = Buffer.alloc(cdSize);
    fs.readSync(fd, cd, 0, cdSize, cdOffset);
    let p = 0;
    for (let i = 0; i < entries && p + 46 <= cd.length; i++) {
      if (cd.readUInt32LE(p) !== 0x02014b50) return null;
      const method = cd.readUInt16LE(p + 10);
      const compSize = cd.readUInt32LE(p + 20);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const localOffset = cd.readUInt32LE(p + 42);
      const entryName = cd.toString('utf8', p + 46, p + 46 + nameLen);
      if (entryName === name) {
        const lh = Buffer.alloc(30);
        fs.readSync(fd, lh, 0, 30, localOffset);
        const dataStart = localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
        const data = Buffer.alloc(compSize);
        fs.readSync(fd, data, 0, compSize, dataStart);
        if (method === 0) return data;
        if (method === 8) return zlib.inflateRawSync(data);
        return null;
      }
      p += 46 + nameLen + extraLen + commentLen;
    }
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

/** Manifest main attributes (continuation lines joined). */
function parseManifest(text) {
  const attrs = {};
  let last = null;
  for (const line of String(text).split(/\r?\n/)) {
    if (line === '') break; // end of the main section
    if (line.startsWith(' ') && last) { attrs[last] += line.slice(1); continue; }
    const i = line.indexOf(':');
    if (i > 0) { last = line.slice(0, i).trim(); attrs[last] = line.slice(i + 1).trim(); }
  }
  return attrs;
}

function jarVersion(jar) {
  try {
    const mf = readZipEntry(jar, 'META-INF/MANIFEST.MF');
    if (!mf) return null;
    const a = parseManifest(mf.toString('utf8'));
    return a['Implementation-Version'] || a['Bundle-Version'] || a['Specification-Version'] || null;
  } catch (_) {
    return null;
  }
}

/** Candidate module directories, in the order JBoss Modules resolves them (user modules first, then layers). */
function moduleDirs(home, moduleName, slot = 'main') {
  const rel = path.join(...moduleName.split('.'), slot || 'main');
  const dirs = [path.join(home, 'modules', rel)];
  const layersRoot = path.join(home, 'modules', 'system', 'layers');
  let layers = ['base'];
  try {
    const conf = fs.readFileSync(path.join(home, 'modules', 'layers.conf'), 'utf8');
    const m = /^layers=(.*)$/m.exec(conf);
    if (m) layers = [...m[1].split(',').map((x) => x.trim()).filter(Boolean), 'base'];
  } catch (_) { /* default: base only */ }
  for (const l of layers) dirs.push(path.join(layersRoot, l, rel));
  try {
    for (const a of fs.readdirSync(path.join(home, 'modules', 'system', 'add-ons'))) {
      dirs.push(path.join(home, 'modules', 'system', 'add-ons', a, rel));
    }
  } catch (_) { /* no add-ons */ }
  return dirs;
}

const cache = new Map(); // module dir -> { mtime, version, jar }

/** Full version of the jar(s) declared in the driver module's module.xml, or null when not readable. */
function moduleDriverVersion(home, moduleName, slot) {
  if (!home || !moduleName) return null;
  for (const dir of moduleDirs(home, moduleName, slot)) {
    const xmlPath = path.join(dir, 'module.xml');
    let st;
    try { st = fs.statSync(xmlPath); } catch (_) { continue; }
    const hit = cache.get(dir);
    if (hit && hit.mtime === st.mtimeMs) return hit.result;
    let result = null;
    try {
      const xml = fs.readFileSync(xmlPath, 'utf8');
      const jars = [...xml.matchAll(/<resource-root\s+path="([^"]+\.jar)"/g)].map((m) => path.resolve(dir, m[1]));
      for (const jar of jars) {
        const version = jarVersion(jar);
        if (version) { result = { version, jar: path.basename(jar) }; break; }
      }
      // module.xml may reference the jar via a Maven artifact; fall back to any jar in the directory
      if (!result) {
        for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.jar'))) {
          const version = jarVersion(path.join(dir, f));
          if (version) { result = { version, jar: f }; break; }
        }
      }
    } catch (_) { /* unreadable */ }
    cache.set(dir, { mtime: st.mtimeMs, result });
    return result;
  }
  return null;
}

module.exports = { moduleDriverVersion, jarVersion, readZipEntry, parseManifest };
