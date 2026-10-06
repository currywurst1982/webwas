'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { BUILD } = require('../src/build');

test('server, script and page carry the same build id', () => {
  const js = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'app.js'), 'utf8');
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.html'), 'utf8');
  assert.strictEqual(/const BUILD = '([^']+)'/.exec(js)[1], BUILD);
  assert.strictEqual(/name="dashboard-build" content="([^"]+)"/.exec(html)[1], BUILD);
});
