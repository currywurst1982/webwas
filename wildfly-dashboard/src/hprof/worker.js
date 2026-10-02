'use strict';

const { parentPort, workerData } = require('worker_threads');
const fs = require('fs');
const { parseHprof, parseClassHistogram } = require('./parser');

try {
  let result;
  if (workerData.kind === 'histogram') {
    result = parseClassHistogram(fs.readFileSync(workerData.file, 'utf8'));
  } else {
    result = parseHprof(workerData.file, { onProgress: (pct) => parentPort.postMessage({ type: 'progress', pct }) });
  }
  parentPort.postMessage({ type: 'done', result });
} catch (e) {
  parentPort.postMessage({ type: 'error', message: e.message });
}
