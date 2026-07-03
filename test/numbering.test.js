const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createNumbering } = require('../lib/numbering');

describe('createNumbering', () => {
  let tmpDir;

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-test-'));
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('starts from 001 when directory is empty', () => {
    const { next } = createNumbering(tmpDir);
    assert.strictEqual(next(), '001');
  });

  it('increments sequentially 001 → 002 → 003', () => {
    const { next } = createNumbering(tmpDir);
    assert.strictEqual(next(), '001');
    assert.strictEqual(next(), '002');
    assert.strictEqual(next(), '003');
  });

  it('pads single and double digits with zeros', () => {
    const { next } = createNumbering(tmpDir);
    for (let i = 0; i < 9; i++) next();
    assert.strictEqual(next(), '010');
  });

  it('wraps from 999 back to 001', () => {
    // create fake dirs first so createNumbering scans them
    for (let i = 1; i <= 998; i++) {
      fs.mkdirSync(path.join(tmpDir, `${String(i).padStart(3, '0')}-skip`));
    }
    const { next } = createNumbering(tmpDir);
    assert.strictEqual(next(), '999');
    assert.strictEqual(next(), '001');
  });

  it('scans existing directories and starts from max+1', () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-test-'));
    fs.mkdirSync(path.join(emptyDir, '005-old.example.com'));
    fs.mkdirSync(path.join(emptyDir, '003-older.example.com'));
    fs.mkdirSync(path.join(emptyDir, 'not-a-match'));
    const { next } = createNumbering(emptyDir);
    assert.strictEqual(next(), '006');
    fs.rmSync(emptyDir, { recursive: true, force: true });
  });
});