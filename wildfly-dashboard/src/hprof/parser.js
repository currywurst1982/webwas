'use strict';

// Streaming parser for HotSpot HPROF heap dumps (JAVA PROFILE 1.0.1 / 1.0.2).
// It makes a single sequential pass over the file and keeps only per-class
// aggregates in memory, so multi-GB dumps can be analysed with a small heap.
// Sizes are shallow sizes estimated from the dump (object header + fields,
// aligned to 8 bytes). Retained sizes need a full object graph (use Eclipse
// MAT for that); this analysis is meant for a quick first look.

const fs = require('fs');

const TAG = {
  UTF8: 0x01, LOAD_CLASS: 0x02, HEAP_DUMP: 0x0c, HEAP_DUMP_SEGMENT: 0x1c,
};
const SUB = {
  ROOT_UNKNOWN: 0xff, ROOT_JNI_GLOBAL: 0x01, ROOT_JNI_LOCAL: 0x02, ROOT_JAVA_FRAME: 0x03,
  ROOT_NATIVE_STACK: 0x04, ROOT_STICKY_CLASS: 0x05, ROOT_THREAD_BLOCK: 0x06,
  ROOT_MONITOR_USED: 0x07, ROOT_THREAD_OBJECT: 0x08,
  CLASS_DUMP: 0x20, INSTANCE_DUMP: 0x21, OBJ_ARRAY_DUMP: 0x22, PRIM_ARRAY_DUMP: 0x23,
};
const PRIM = {
  4: ['boolean', 1], 5: ['char', 2], 6: ['float', 4], 7: ['double', 8],
  8: ['byte', 1], 9: ['short', 2], 10: ['int', 4], 11: ['long', 8],
};
const HEADER = 16; // object header estimate (mark word + klass pointer)
const ARRAY_HEADER = 16;
const align8 = (n) => (n + 7) & ~7;
const TWO32 = 4294967296;

class Reader {
  constructor(fd, size, bufSize = 16 * 1024 * 1024) {
    this.fd = fd;
    this.size = size;
    this.buf = Buffer.allocUnsafe(bufSize);
    this.bufStart = 0;
    this.bufLen = 0;
    this.pos = 0;
  }

  get offset() { return this.bufStart + this.pos; }

  ensure(n) {
    if (this.pos + n <= this.bufLen) return;
    const remaining = this.bufLen - this.pos;
    if (remaining > 0) this.buf.copy(this.buf, 0, this.pos, this.bufLen);
    this.bufStart += this.pos;
    this.pos = 0;
    this.bufLen = remaining;
    while (this.bufLen < n) {
      const read = fs.readSync(this.fd, this.buf, this.bufLen, this.buf.length - this.bufLen, this.bufStart + this.bufLen);
      if (read === 0) throw new Error(`HPROF 파일이 예상보다 일찍 끝났습니다 (offset ${this.offset})`);
      this.bufLen += read;
    }
  }

  u1() { this.ensure(1); return this.buf[this.pos++]; }
  u2() { this.ensure(2); const v = this.buf.readUInt16BE(this.pos); this.pos += 2; return v; }
  u4() { this.ensure(4); const v = this.buf.readUInt32BE(this.pos); this.pos += 4; return v; }
  u8() {
    this.ensure(8);
    const hi = this.buf.readUInt32BE(this.pos);
    const lo = this.buf.readUInt32BE(this.pos + 4);
    this.pos += 8;
    return hi * TWO32 + lo; // object addresses fit in 53 bits on all real platforms
  }

  bytes(n) {
    if (n > this.buf.length) {
      const out = Buffer.allocUnsafe(n);
      fs.readSync(this.fd, out, 0, n, this.offset);
      this.skip(n);
      return out;
    }
    this.ensure(n);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  skip(n) {
    if (this.pos + n <= this.bufLen) {
      this.pos += n;
    } else {
      this.bufStart = this.offset + n;
      this.pos = 0;
      this.bufLen = 0;
    }
  }
}

function prettyClassName(raw) {
  if (!raw) return raw;
  let name = raw.replace(/\//g, '.');
  let dims = 0;
  while (name[dims] === '[') dims++;
  if (dims === 0) return name;
  const rest = name.slice(dims);
  const prim = { Z: 'boolean', C: 'char', F: 'float', D: 'double', B: 'byte', S: 'short', I: 'int', J: 'long' };
  const base = rest[0] === 'L' ? rest.slice(1).replace(/;$/, '') : (prim[rest] || rest);
  return base + '[]'.repeat(dims);
}

class TopN {
  constructor(n) { this.n = n; this.items = []; this.min = 0; }
  offer(size, make) {
    if (this.items.length >= this.n && size <= this.min) return;
    this.items.push(make());
    if (this.items.length > this.n) {
      this.items.sort((a, b) => b.size - a.size);
      this.items.length = this.n;
    }
    this.min = this.items.length >= this.n ? Math.min(...this.items.map((i) => i.size)) : 0;
  }
  sorted() { return this.items.slice().sort((a, b) => b.size - a.size); }
}

function parseHprof(file, { onProgress } = {}) {
  const started = Date.now();
  const fd = fs.openSync(file, 'r');
  const size = fs.fstatSync(fd).size;
  const r = new Reader(fd, size);
  try {
    // --- header -----------------------------------------------------------
    r.ensure(Math.min(64, size));
    const nul = r.buf.indexOf(0, 0);
    if (nul < 0 || nul > 40) throw new Error('HPROF 형식이 아닙니다');
    const format = r.buf.toString('latin1', 0, nul);
    if (!/^JAVA PROFILE 1\.0\.[12]$/.test(format)) throw new Error(`지원하지 않는 힙 덤프 형식입니다: ${format}`);
    r.pos = nul + 1;
    const idSize = r.u4();
    if (idSize !== 4 && idSize !== 8) throw new Error(`지원하지 않는 identifier 크기: ${idSize}`);
    const timestamp = r.u8();
    const id = idSize === 4 ? () => r.u4() : () => r.u8();
    const refSize = idSize;

    const strings = new Map();      // string id -> text
    const classNameIds = new Map(); // class object id -> name string id
    const classes = new Map();      // class object id -> { loaderId, instanceSize, superId }
    const loaderIds = new Set();
    const loaderInstanceClass = new Map(); // loader object id -> class id of the loader
    const hist = new Map();         // class id | 'prim:<type>' -> [count, bytes]
    const largest = new TopN(25);
    let gcRoots = 0;
    let instances = 0;
    let arrays = 0;
    let totalBytes = 0;
    let lastProgress = -1;

    const add = (key, bytes) => {
      let e = hist.get(key);
      if (!e) { e = [0, 0]; hist.set(key, e); }
      e[0]++;
      e[1] += bytes;
      totalBytes += bytes;
    };

    const typeSize = (t) => (t === 2 ? idSize : PRIM[t] ? PRIM[t][1] : (() => { throw new Error(`알 수 없는 기본 타입: ${t}`); })());

    const progress = () => {
      if (!onProgress) return;
      const pct = Math.floor((1000 * r.offset) / size) / 10;
      if (pct !== lastProgress) { lastProgress = pct; onProgress(pct); }
    };

    while (r.offset < size) {
      const tag = r.u1();
      r.u4(); // time
      const len = r.u4();
      if (tag === TAG.UTF8) {
        const sid = id();
        strings.set(sid, r.bytes(len - idSize).toString('utf8'));
      } else if (tag === TAG.LOAD_CLASS) {
        r.u4();
        const cid = id();
        r.u4();
        classNameIds.set(cid, id());
      } else if (tag === TAG.HEAP_DUMP || tag === TAG.HEAP_DUMP_SEGMENT) {
        const end = r.offset + len;
        let n = 0;
        while (r.offset < end) {
          const sub = r.u1();
          switch (sub) {
            case SUB.ROOT_UNKNOWN: case SUB.ROOT_STICKY_CLASS: case SUB.ROOT_MONITOR_USED:
              r.skip(idSize); gcRoots++; break;
            case SUB.ROOT_JNI_GLOBAL: r.skip(idSize * 2); gcRoots++; break;
            case SUB.ROOT_JNI_LOCAL: case SUB.ROOT_JAVA_FRAME: case SUB.ROOT_THREAD_OBJECT:
              r.skip(idSize + 8); gcRoots++; break;
            case SUB.ROOT_NATIVE_STACK: case SUB.ROOT_THREAD_BLOCK:
              r.skip(idSize + 4); gcRoots++; break;
            case SUB.CLASS_DUMP: {
              const cid = id();
              r.u4();
              const superId = id();
              const loaderId = id();
              r.skip(idSize * 4); // signers, protection domain, 2 reserved
              const instanceSize = r.u4();
              const cp = r.u2();
              for (let i = 0; i < cp; i++) { r.u2(); r.skip(typeSize(r.u1())); }
              const statics = r.u2();
              for (let i = 0; i < statics; i++) { r.skip(idSize); r.skip(typeSize(r.u1())); }
              const fields = r.u2();
              r.skip(fields * (idSize + 1));
              classes.set(cid, { loaderId, instanceSize, superId });
              if (loaderId) loaderIds.add(loaderId);
              break;
            }
            case SUB.INSTANCE_DUMP: {
              const oid = id();
              r.u4();
              const cid = id();
              const nbytes = r.u4();
              r.skip(nbytes);
              const sz = align8(HEADER + nbytes);
              add(cid, sz);
              instances++;
              if (loaderIds.has(oid)) loaderInstanceClass.set(oid, cid);
              if (sz > 1024 * 1024) largest.offer(sz, () => ({ id: oid, classId: cid, size: sz, kind: 'instance' }));
              break;
            }
            case SUB.OBJ_ARRAY_DUMP: {
              const oid = id();
              r.u4();
              const count = r.u4();
              const cid = id();
              r.skip(count * idSize);
              const sz = align8(ARRAY_HEADER + count * refSize);
              add(cid, sz);
              arrays++;
              largest.offer(sz, () => ({ id: oid, classId: cid, size: sz, kind: 'array', length: count }));
              break;
            }
            case SUB.PRIM_ARRAY_DUMP: {
              const oid = id();
              r.u4();
              const count = r.u4();
              const type = r.u1();
              const es = typeSize(type);
              r.skip(count * es);
              const sz = align8(ARRAY_HEADER + count * es);
              const key = `prim:${type}`;
              add(key, sz);
              arrays++;
              largest.offer(sz, () => ({ id: oid, classId: key, size: sz, kind: 'array', length: count }));
              break;
            }
            default:
              throw new Error(`알 수 없는 힙 덤프 레코드 0x${sub.toString(16)} (offset ${r.offset - 1})`);
          }
          if ((++n & 0xffff) === 0) progress();
        }
      } else {
        r.skip(len);
      }
      progress();
    }

    // --- aggregate --------------------------------------------------------
    const nameOf = (key) => {
      if (typeof key === 'string' && key.startsWith('prim:')) return `${PRIM[Number(key.slice(5))][0]}[]`;
      const nid = classNameIds.get(key);
      return prettyClassName(nid !== undefined ? strings.get(nid) : null) || `class@0x${Number(key).toString(16)}`;
    };

    const histogram = [...hist.entries()]
      .map(([key, [count, bytes]]) => ({ className: nameOf(key), count, bytes }))
      .sort((a, b) => b.bytes - a.bytes);
    for (const h of histogram) h.percent = totalBytes ? +(100 * h.bytes / totalBytes).toFixed(2) : 0;

    // Classes defined per class loader: a growing number of deployment class
    // loaders (and their classes) is the classic Metaspace leak after redeploys.
    const perLoader = new Map();
    for (const c of classes.values()) perLoader.set(c.loaderId, (perLoader.get(c.loaderId) || 0) + 1);
    const classLoaders = [...perLoader.entries()].map(([lid, classCount]) => ({
      id: `0x${lid.toString(16)}`,
      loaderClass: lid === 0 ? '<bootstrap>' : (loaderInstanceClass.has(lid) ? nameOf(loaderInstanceClass.get(lid)) : '(unknown)'),
      classCount,
    })).sort((a, b) => b.classCount - a.classCount);
    const loaderTypes = {};
    for (const l of classLoaders) loaderTypes[l.loaderClass] = (loaderTypes[l.loaderClass] || 0) + 1;

    const largestObjects = largest.sorted().map((o) => ({
      id: `0x${o.id.toString(16)}`, className: nameOf(o.classId), size: o.size, kind: o.kind, length: o.length,
    }));

    const result = {
      format,
      idSize,
      timestamp: timestamp || null,
      fileSize: size,
      durationMs: Date.now() - started,
      totals: {
        bytes: totalBytes,
        objects: instances + arrays,
        instances,
        arrays,
        classes: classes.size,
        classLoaders: classLoaders.length,
        gcRoots,
      },
      histogram: histogram.slice(0, 300),
      histogramSize: histogram.length,
      classLoaders: classLoaders.slice(0, 50),
      loaderTypes: Object.entries(loaderTypes).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
      largestObjects,
    };
    result.findings = findings(result, histogram);
    if (onProgress) onProgress(100);
    return result;
  } finally {
    fs.closeSync(fd);
  }
}

function count(histogram, name) {
  const h = histogram.find((e) => e.className === name);
  return h ? h.count : 0;
}

function findings(result, histogram) {
  const out = [];
  const total = result.totals.bytes;
  for (const h of histogram.slice(0, 10)) {
    if (h.percent >= 30 && !/^(byte|char)\[\]$/.test(h.className)) {
      out.push({ level: 'critical', text: `${h.className} 이(가) 힙의 ${h.percent}% (${h.count.toLocaleString()}개)를 차지합니다. 누수 의심 1순위입니다.` });
    } else if (h.percent >= 10 && !/^(java|javax|jdk|sun|com\.sun)\.|^\w+\[\]$/.test(h.className)) {
      out.push({ level: 'warning', text: `애플리케이션 클래스 ${h.className} 이(가) 힙의 ${h.percent}% (${h.count.toLocaleString()}개)를 차지합니다. 컬렉션/캐시에 계속 쌓이고 있는지 확인하세요.` });
    } else if (h.percent >= 50 && /^\w+\[\]$/.test(h.className)) {
      out.push({ level: 'info', text: `${h.className} 이(가) 힙의 ${h.percent}% 를 차지합니다. 어떤 객체가 이 배열을 참조하는지 Eclipse MAT 의 dominator tree 로 확인하세요.` });
    }
  }
  for (const o of result.largestObjects.slice(0, 5)) {
    if (total && o.size / total >= 0.1) {
      out.push({ level: 'warning', text: `단일 객체 ${o.className}${o.length !== undefined ? `(length ${o.length.toLocaleString()})` : ''} 가 힙의 ${(100 * o.size / total).toFixed(1)}% 를 차지합니다. 대형 컬렉션/캐시를 확인하세요.` });
    }
  }
  const finalizers = count(histogram, 'java.lang.ref.Finalizer');
  if (finalizers > 10000) out.push({ level: 'warning', text: `java.lang.ref.Finalizer ${finalizers.toLocaleString()}개 - finalize() 대기 객체가 많습니다.` });
  const threads = count(histogram, 'java.lang.Thread');
  if (threads > 1000) out.push({ level: 'warning', text: `java.lang.Thread 인스턴스 ${threads.toLocaleString()}개 - 쓰레드 누수 가능성이 있습니다.` });
  const moduleLoaders = result.classLoaders.filter((l) => /ModuleClassLoader/.test(l.loaderClass)).length;
  if (result.totals.classes > 60000) {
    out.push({ level: 'warning', text: `로드된 클래스 ${result.totals.classes.toLocaleString()}개 - Metaspace 사용량이 큽니다. 재배포 후 이전 배포의 ClassLoader 가 남아있는지 확인하세요 (ModuleClassLoader ${moduleLoaders}개).` });
  }
  const sessions = histogram.filter((h) => /\.session\.(InMemorySession|SessionImpl)$|InfinispanSession|StandardSession$/.test(h.className)).reduce((a, h) => a + h.count, 0);
  if (sessions > 50000) out.push({ level: 'warning', text: `HTTP 세션 객체 ${sessions.toLocaleString()}개 - 세션 타임아웃/세션 저장 데이터를 확인하세요.` });
  if (!out.length) out.push({ level: 'ok', text: '특정 클래스에 편중된 메모리 사용은 발견되지 않았습니다.' });
  return out;
}

/** Parses `jmap -histo` / `jcmd <pid> GC.class_histogram` output. */
function parseClassHistogram(text) {
  const histogram = [];
  let totalBytes = 0;
  let totalCount = 0;
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*\d+:\s+(\d+)\s+(\d+)\s+(\S+)/);
    if (m) {
      const count = Number(m[1]);
      const bytes = Number(m[2]);
      histogram.push({ className: prettyClassName(m[3]), count, bytes });
      totalBytes += bytes;
      totalCount += count;
    }
  }
  if (!histogram.length) throw new Error('클래스 히스토그램 형식이 아닙니다 (jmap -histo / jcmd GC.class_histogram 출력)');
  histogram.sort((a, b) => b.bytes - a.bytes);
  for (const h of histogram) h.percent = +(100 * h.bytes / totalBytes).toFixed(2);
  const result = {
    format: 'class-histogram',
    totals: { bytes: totalBytes, objects: totalCount, classes: histogram.length },
    histogram: histogram.slice(0, 300),
    histogramSize: histogram.length,
    classLoaders: [],
    loaderTypes: [],
    largestObjects: [],
  };
  result.findings = findings({ ...result, totals: { ...result.totals, classes: 0 } }, histogram);
  return result;
}

module.exports = { parseHprof, parseClassHistogram, prettyClassName };
