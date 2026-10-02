'use strict';

// Heap dump storage, generation (jcmd on the WildFly host) and background analysis.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { pipeline } = require('stream/promises');
const { execFile } = require('child_process');
const { Worker } = require('worker_threads');

const ID_RE = /^[a-f0-9]{16}$/;

class HeapDumpManager {
  constructor(cfg) {
    this.dir = path.join(cfg.dataDir, 'heapdumps');
    this.jcmd = cfg.heapDump.jcmd;
    this.jobs = new Map(); // id -> { status, progress, error }
  }

  newId() { return crypto.randomBytes(8).toString('hex'); }
  metaFile(id) { return path.join(this.dir, `${id}.json`); }
  analysisFile(id) { return path.join(this.dir, `${id}.analysis.json`); }

  check(id) {
    if (!ID_RE.test(id)) throw Object.assign(new Error('잘못된 덤프 ID'), { status: 400 });
    if (!fs.existsSync(this.metaFile(id))) throw Object.assign(new Error('덤프를 찾을 수 없습니다'), { status: 404 });
  }

  readMeta(id) {
    this.check(id);
    return JSON.parse(fs.readFileSync(this.metaFile(id), 'utf8'));
  }

  writeMeta(meta) {
    fs.writeFileSync(this.metaFile(meta.id), JSON.stringify(meta, null, 2));
    return meta;
  }

  list() {
    return fs.readdirSync(this.dir)
      .filter((f) => /^[a-f0-9]{16}\.json$/.test(f))
      .map((f) => {
        const meta = JSON.parse(fs.readFileSync(path.join(this.dir, f), 'utf8'));
        const job = this.jobs.get(meta.id);
        return {
          ...meta,
          analyzed: fs.existsSync(this.analysisFile(meta.id)),
          job: job ? { status: job.status, progress: job.progress, error: job.error } : null,
        };
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  /** Registers an uploaded file (moved from multer's temp location). Gzipped dumps are decompressed. */
  async addUpload(tmpPath, originalName, user) {
    const id = this.newId();
    const lower = originalName.toLowerCase();
    const isHistogram = /\.(txt|histo|log)$/.test(lower);
    const dataFile = path.join(this.dir, `${id}.${isHistogram ? 'txt' : 'hprof'}`);
    try {
      if (lower.endsWith('.gz')) {
        await pipeline(fs.createReadStream(tmpPath), zlib.createGunzip(), fs.createWriteStream(dataFile));
        fs.unlinkSync(tmpPath);
      } else {
        fs.renameSync(tmpPath, dataFile);
      }
    } catch (e) {
      fs.rmSync(tmpPath, { force: true });
      fs.rmSync(dataFile, { force: true });
      throw Object.assign(new Error(`업로드 파일 처리 실패: ${e.message}`), { status: 400 });
    }
    return this.writeMeta({
      id,
      name: path.basename(originalName),
      kind: isHistogram ? 'histogram' : 'hprof',
      file: path.basename(dataFile),
      size: fs.statSync(dataFile).size,
      source: 'upload',
      createdBy: user,
      createdAt: new Date().toISOString(),
    });
  }

  /**
   * Creates a heap dump of a WildFly JVM running on the same host as the dashboard,
   * using `jcmd <pid> GC.heap_dump`. The dashboard must run as the same OS user as
   * WildFly (or root) and the data directory must be writable by the WildFly process.
   */
  async generate(server, pid, { live = true, user } = {}) {
    if (!Number.isInteger(pid) || pid <= 0) throw Object.assign(new Error('WildFly 프로세스 ID를 확인할 수 없습니다'), { status: 400 });
    const id = this.newId();
    const dataFile = path.join(this.dir, `${id}.hprof`);
    const args = [String(pid), 'GC.heap_dump'];
    if (!live) args.push('-all');
    args.push(dataFile);
    const out = await new Promise((resolve, reject) => {
      execFile(this.jcmd, args, { timeout: 30 * 60 * 1000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) {
          const msg = err.code === 'ENOENT'
            ? `jcmd 를 찾을 수 없습니다 (${this.jcmd}). JDK 의 jcmd 경로를 heapDump.jcmd 에 설정하세요`
            : `jcmd 실행 실패: ${(stderr || stdout || err.message).trim()}`;
          return reject(Object.assign(new Error(msg), { status: 500 }));
        }
        resolve(String(stdout));
      });
    });
    if (!fs.existsSync(dataFile)) {
      throw Object.assign(new Error(`힙 덤프 파일이 생성되지 않았습니다: ${out.trim()}`), { status: 500 });
    }
    return this.writeMeta({
      id,
      name: `${server.id}-pid${pid}-${new Date().toISOString().replace(/[:.]/g, '-')}.hprof`,
      kind: 'hprof',
      file: path.basename(dataFile),
      size: fs.statSync(dataFile).size,
      source: `jcmd (${server.name}, pid ${pid}${live ? ', live objects' : ', all objects'})`,
      createdBy: user,
      createdAt: new Date().toISOString(),
    });
  }

  analyze(id) {
    const meta = this.readMeta(id);
    const running = this.jobs.get(id);
    if (running && running.status === 'running') return running;
    const job = { status: 'running', progress: 0, error: null, startedAt: Date.now() };
    this.jobs.set(id, job);
    const worker = new Worker(path.join(__dirname, 'hprof', 'worker.js'), {
      workerData: { file: path.join(this.dir, meta.file), kind: meta.kind },
      resourceLimits: { maxOldGenerationSizeMb: 2048 },
    });
    worker.on('message', (msg) => {
      if (msg.type === 'progress') job.progress = msg.pct;
      else if (msg.type === 'done') {
        fs.writeFileSync(this.analysisFile(id), JSON.stringify({ ...msg.result, analyzedAt: new Date().toISOString() }));
        Object.assign(job, { status: 'done', progress: 100 });
      } else if (msg.type === 'error') Object.assign(job, { status: 'error', error: msg.message });
    });
    worker.on('error', (e) => Object.assign(job, { status: 'error', error: e.message }));
    worker.on('exit', (code) => {
      if (job.status === 'running') Object.assign(job, { status: 'error', error: `분석 작업이 비정상 종료되었습니다 (exit ${code})` });
    });
    return job;
  }

  analysis(id) {
    this.check(id);
    const f = this.analysisFile(id);
    if (!fs.existsSync(f)) return null;
    return JSON.parse(fs.readFileSync(f, 'utf8'));
  }

  filePath(id) {
    const meta = this.readMeta(id);
    return { path: path.join(this.dir, meta.file), name: meta.name };
  }

  remove(id) {
    const meta = this.readMeta(id);
    const job = this.jobs.get(id);
    if (job && job.status === 'running') throw Object.assign(new Error('분석 중인 덤프는 삭제할 수 없습니다'), { status: 409 });
    for (const f of [path.join(this.dir, meta.file), this.analysisFile(id), this.metaFile(id)]) fs.rmSync(f, { force: true });
    this.jobs.delete(id);
  }
}

module.exports = { HeapDumpManager };
