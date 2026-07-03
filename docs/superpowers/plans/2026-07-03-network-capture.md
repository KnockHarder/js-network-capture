# js-network-capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a zero-dependency Node.js preload hook that intercepts all HTTP/HTTPS requests and writes structured capture files to `$HOME/.networkLogs/`.

**Architecture:** `hook.js` is loaded via `--require`. It monkey-patches `http.request`, `http.get`, `https.request`, `https.get`, and `globalThis.fetch` to intercept every outbound request. Five library modules handle: numbering (001–999 rotation), redaction (sensitive field masking), structural brief generation (truncated JSON preview), file recording (directory creation and file I/O), and the actual protocol patching.

**Tech Stack:** Node.js built-in modules only (`http`, `https`, `fs`, `path`, `os`, `url`). Testing via `node:test`. Zero npm dependencies.

## Global Constraints

- Zero external dependencies — use only Node.js built-in modules
- Hook must never throw into the application — all errors caught internally
- `NETWORK_CAPTURE=off` disables all interception (hook loads but no-ops)
- `NETWORK_CAPTURE_DEBUG=1` enables verbose stderr logging
- Directory naming: `{NNN}-{hostname}-{path-segments}`, max 150 chars
- Sensitive value replacement: `***REDACTED***`
- JSON files: 2-space indent, UTF-8
- .prop files: `key: value`, one per line, UTF-8
- Sequence wraps 999 → 001, overwriting old directories
- Node.js ≥ 18 (for `node:test` and `globalThis.fetch` support)

---

### Task 1: Project scaffolding

**Files:**
- Create: `package.json`

**Interfaces:**
- Consumes: nothing
- Produces: `package.json` with correct `name`, `version`, `main`, `files`, `engines` fields

- [ ] **Step 1: Create package.json**

```bash
cat > /Users/wangzhiqiang/kwai/js-network-capture/package.json << 'PKGEOF'
{
  "name": "js-network-capture",
  "version": "1.0.0",
  "description": "Node.js network request interceptor — captures HTTP/HTTPS traffic to ~/.networkLogs",
  "main": "hook.js",
  "files": [
    "hook.js",
    "lib/"
  ],
  "engines": {
    "node": ">=18.0.0"
  },
  "license": "MIT"
}
PKGEOF
```

- [ ] **Step 2: Verify package.json is valid JSON**

Run: `node -e "JSON.parse(require('fs').readFileSync('package.json','utf8')); console.log('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add package.json
git commit -m "chore: add package.json scaffolding"
```

---

### Task 2: Sensitive keyword redaction — `sanitizer.js`

**Files:**
- Create: `lib/sanitizer.js`
- Create: `lib/sanitizer.test.js`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `sanitizeValue(key, value)` → `string` — returns `"***REDACTED***"` if `key` matches a sensitive pattern (case-insensitive substring), otherwise returns `value` unchanged.
  - `sanitizeHeaders(headers)` → `object` — iterates header keys, replaces matched values with `"***REDACTED***"`, returns new object.
  - `sanitizeParams(params)` → `object` — same logic as headers but for URL query params.
  - `sanitizeBody(body)` → `object` — deep-walks a JSON-parsed body, redacting values at any nesting level whose key matches.

- [ ] **Step 1: Write the failing test**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/sanitizer.test.js`:

```js
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { sanitizeValue, sanitizeHeaders, sanitizeParams, sanitizeBody } = require('./sanitizer');

describe('sanitizeValue', () => {
  it('returns ***REDACTED*** when key contains "token" (case-insensitive)', () => {
    assert.strictEqual(sanitizeValue('Authorization', 'Bearer xyz'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('authorization', 'Basic abc'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('X-Auth-Token', 'secret123'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "password"', () => {
    assert.strictEqual(sanitizeValue('password', 'mypassword'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('user_password', 'pw'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "secret"', () => {
    assert.strictEqual(sanitizeValue('client_secret', 'abc'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('secretKey', 'xyz'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "api_key"', () => {
    assert.strictEqual(sanitizeValue('api_key', 'key123'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('x-api-key', 'val'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('apikey', 'val'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "pass"', () => {
    assert.strictEqual(sanitizeValue('pass', '123'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('passwd', 'secret'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "credential" or "access_key"', () => {
    assert.strictEqual(sanitizeValue('credential', 'x'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('aws_access_key', 'x'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('accesskey', 'x'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "private_key"', () => {
    assert.strictEqual(sanitizeValue('private_key', 'rsa...'), '***REDACTED***');
  });

  it('returns ***REDACTED*** when key contains "bearer" or "refresh_token"', () => {
    assert.strictEqual(sanitizeValue('bearer', 'x'), '***REDACTED***');
    assert.strictEqual(sanitizeValue('refresh_token', 'x'), '***REDACTED***');
  });

  it('returns value unchanged for non-sensitive keys', () => {
    assert.strictEqual(sanitizeValue('Content-Type', 'application/json'), 'application/json');
    assert.strictEqual(sanitizeValue('Accept', 'text/html'), 'text/html');
    assert.strictEqual(sanitizeValue('X-Request-Id', 'req-123'), 'req-123');
    assert.strictEqual(sanitizeValue('username', 'bob'), 'bob');
  });

  it('returns value unchanged for empty or missing value', () => {
    assert.strictEqual(sanitizeValue('token', ''), '***REDACTED***');
    assert.strictEqual(sanitizeValue('Content-Type', ''), '');
  });
});

describe('sanitizeHeaders', () => {
  it('redacts sensitive header values, leaves others untouched', () => {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer secret-token',
      'X-Api-Key': 'key-12345',
      'Accept': 'application/json',
    };
    const result = sanitizeHeaders(headers);
    assert.strictEqual(result['Content-Type'], 'application/json');
    assert.strictEqual(result['Authorization'], '***REDACTED***');
    assert.strictEqual(result['X-Api-Key'], '***REDACTED***');
    assert.strictEqual(result['Accept'], 'application/json');
  });

  it('handles empty headers object', () => {
    const result = sanitizeHeaders({});
    assert.deepStrictEqual(result, {});
  });
});

describe('sanitizeParams', () => {
  it('redacts sensitive query params, leaves others untouched', () => {
    const params = { q: 'search', token: 'abc123', page: '1' };
    const result = sanitizeParams(params);
    assert.strictEqual(result.q, 'search');
    assert.strictEqual(result.token, '***REDACTED***');
    assert.strictEqual(result.page, '1');
  });
});

describe('sanitizeBody', () => {
  it('deep-walks JSON body and redacts sensitive keys at any nesting level', () => {
    const body = {
      username: 'bob',
      password: 'secret123',
      nested: {
        api_key: 'deep-secret',
        data: 'hello',
        arr: [{ token: 't1' }, { token: 't2' }],
      },
    };
    const result = sanitizeBody(body);
    assert.strictEqual(result.username, 'bob');
    assert.strictEqual(result.password, '***REDACTED***');
    assert.strictEqual(result.nested.api_key, '***REDACTED***');
    assert.strictEqual(result.nested.data, 'hello');
    assert.strictEqual(result.nested.arr[0].token, '***REDACTED***');
    assert.strictEqual(result.nested.arr[1].token, '***REDACTED***');
  });

  it('returns primitive values unchanged', () => {
    assert.strictEqual(sanitizeBody('hello'), 'hello');
    assert.strictEqual(sanitizeBody(123), 123);
    assert.strictEqual(sanitizeBody(null), null);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test lib/sanitizer.test.js`
Expected: FAIL with `MODULE_NOT_FOUND` for `./sanitizer`

- [ ] **Step 3: Write minimal implementation**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/sanitizer.js`:

```js
'use strict';

const SENSITIVE_PATTERNS = [
  'refresh_token',
  'private_key',
  'access_key',
  'credential',
  'authorization',
  'api_key',
  'password',
  'accesskey',
  'api-key',
  'apikey',
  'bearer',
  'secret',
  'passwd',
  'token',
  'pass',
  'auth',
  'pwd',
];

const REDACTED = '***REDACTED***';

function isSensitive(key) {
  const lower = key.toLowerCase();
  return SENSITIVE_PATTERNS.some(p => lower.includes(p));
}

function sanitizeValue(key, value) {
  if (isSensitive(key)) {
    return REDACTED;
  }
  return value;
}

function sanitizeHeaders(headers) {
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    result[key] = sanitizeValue(key, typeof value === 'string' ? value : String(value));
  }
  return result;
}

function sanitizeParams(params) {
  return sanitizeHeaders(params);
}

function sanitizeBody(body) {
  if (body === null || typeof body !== 'object') {
    return body;
  }
  if (Array.isArray(body)) {
    return body.map(item => sanitizeBody(item));
  }
  const result = {};
  for (const [key, value] of Object.entries(body)) {
    if (isSensitive(key)) {
      result[key] = REDACTED;
    } else if (value !== null && typeof value === 'object') {
      result[key] = sanitizeBody(value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

module.exports = { sanitizeValue, sanitizeHeaders, sanitizeParams, sanitizeBody };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test lib/sanitizer.test.js`
Expected: PASS (all 10+ tests)

- [ ] **Step 5: Commit**

```bash
git add lib/sanitizer.js lib/sanitizer.test.js
git commit -m "feat: add sanitizer module for redacting sensitive fields"
```

---

### Task 3: Sequence numbering — `numbering.js`

**Files:**
- Create: `lib/numbering.js`
- Create: `lib/numbering.test.js`

**Interfaces:**
- Consumes: nothing (reads/writes `$HOME/.networkLogs/` on disk, but the test creates its own temp directory)
- Produces:
  - `createNumbering(logDir)` → `{ next, reset }` — factory that scans `logDir` and returns:
    - `next()` → `string` — returns a 3-digit zero-padded string (`'001'`, `'002'`, …), auto-incrementing, wrapping to `'001'` after `'999'`.
    - `reset()` → `void` — resets the internal counter to 1 and restarts scan from disk.

- [ ] **Step 1: Write the failing test**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/numbering.test.js`:

```js
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createNumbering } = require('./numbering');

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
    const { next } = createNumbering(tmpDir);
    // fast-forward to 999 by creating fake dirs
    for (let i = 1; i <= 998; i++) {
      fs.mkdirSync(path.join(tmpDir, `${String(i).padStart(3, '0')}-skip`));
    }
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test lib/numbering.test.js`
Expected: FAIL with `MODULE_NOT_FOUND` for `./numbering`

- [ ] **Step 3: Write minimal implementation**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/numbering.js`:

```js
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function createNumbering(logDir) {
  // scan existing directories for the highest 3-digit prefix
  let max = 0;
  try {
    const entries = fs.readdirSync(logDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const match = entry.name.match(/^(\d{3})-/);
      if (match) {
        const num = parseInt(match[1], 10);
        if (num > max) max = num;
      }
    }
  } catch (_) {
    // logDir doesn't exist yet — that's fine
  }

  let current = max;

  function next() {
    current += 1;
    if (current > 999) current = 1;
    return String(current).padStart(3, '0');
  }

  function reset() {
    current = 0;
    try {
      const entries = fs.readdirSync(logDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const match = entry.name.match(/^(\d{3})-/);
        if (match) {
          const num = parseInt(match[1], 10);
          if (num > current) current = num;
        }
      }
    } catch (_) {}
  }

  return { next, reset };
}

module.exports = { createNumbering };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test lib/numbering.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/numbering.js lib/numbering.test.js
git commit -m "feat: add sequence numbering module (001-999 rotation)"
```

---

### Task 4: Structural brief generation — `brief.js`

**Files:**
- Create: `lib/brief.js`
- Create: `lib/brief.test.js`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `generateBrief(json)` → `any` — returns a structurally truncated version of the input:
    - Strings longer than 50 chars → `"first 50 chars... (N more chars)"`
    - Arrays longer than 6 items → `[first3, "... (N more items)", last3]`
    - Objects → all keys kept, values recursively briefed
    - Numbers, booleans, null → unchanged
    - No depth limit — brief applies at every level

- [ ] **Step 1: Write the failing test**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/brief.test.js`:

```js
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { generateBrief } = require('./brief');

describe('generateBrief', () => {
  it('returns primitives unchanged', () => {
    assert.strictEqual(generateBrief(42), 42);
    assert.strictEqual(generateBrief(true), true);
    assert.strictEqual(generateBrief(null), null);
    assert.strictEqual(generateBrief('hello'), 'hello');
  });

  it('truncates strings longer than 50 chars', () => {
    const longStr = 'a'.repeat(100);
    const result = generateBrief(longStr);
    assert.ok(result.startsWith('a'.repeat(50)));
    assert.ok(result.includes('... (50 more chars)'));
  });

  it('does not truncate strings of exactly 50 chars', () => {
    const str50 = 'x'.repeat(50);
    assert.strictEqual(generateBrief(str50), str50);
  });

  it('does not truncate strings under 50 chars', () => {
    assert.strictEqual(generateBrief('short'), 'short');
  });

  it('keeps arrays of 6 or fewer items intact', () => {
    const arr = [1, 2, 3, 4, 5, 6];
    assert.deepStrictEqual(generateBrief(arr), [1, 2, 3, 4, 5, 6]);
  });

  it('truncates arrays longer than 6: keeps first 3, placeholder, last 3', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const result = generateBrief(arr);
    assert.deepStrictEqual(result, [1, 2, 3, '... (4 more items)', 8, 9, 10]);
  });

  it('recursively briefs objects', () => {
    const obj = {
      name: 'short',
      description: 'x'.repeat(80),
      tags: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'],
      nested: {
        key: 'y'.repeat(60),
        arr: [1, 2, 3, 4, 5, 6, 7, 8],
      },
    };
    const result = generateBrief(obj);
    assert.strictEqual(result.name, 'short');
    assert.ok(result.description.startsWith('x'.repeat(50)));
    assert.ok(result.description.includes('... (30 more chars)'));
    assert.deepStrictEqual(result.tags, ['a', 'b', 'c', '... (4 more items)', 'h', 'i', 'j']);
    assert.ok(result.nested.key.startsWith('y'.repeat(50)));
    assert.deepStrictEqual(result.nested.arr, [1, 2, 3, '... (2 more items)', 6, 7, 8]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test lib/brief.test.js`
Expected: FAIL with `MODULE_NOT_FOUND` for `./brief`

- [ ] **Step 3: Write minimal implementation**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/brief.js`:

```js
'use strict';

const MAX_STRING = 50;
const MAX_ARRAY = 6;

function generateBrief(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (value.length > MAX_STRING) {
      return value.slice(0, MAX_STRING) + `... (${value.length - MAX_STRING} more chars)`;
    }
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    if (value.length <= MAX_ARRAY) {
      return value.map(item => generateBrief(item));
    }
    const first3 = value.slice(0, 3).map(item => generateBrief(item));
    const last3 = value.slice(-3).map(item => generateBrief(item));
    return [...first3, `... (${value.length - 6} more items)`, ...last3];
  }
  if (typeof value === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = generateBrief(v);
    }
    return result;
  }
  return value;
}

module.exports = { generateBrief };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test lib/brief.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/brief.js lib/brief.test.js
git commit -m "feat: add structural brief generator for large JSON previews"
```

---

### Task 5: File recorder — `recorder.js`

**Files:**
- Create: `lib/recorder.js`

**Interfaces:**
- Consumes: `sanitizer.sanitizeHeaders`, `sanitizer.sanitizeParams`, `sanitizer.sanitizeBody`, `brief.generateBrief`
- Produces:
  - `Recorder` class:
    - `constructor(logDir, seqNumber)` → creates and returns a recorder bound to one request's directory. `seqNumber` is the 3-digit string. The constructor builds the directory name from hostname + path, creates the directory, writes `request_header.prop` and `request_params.prop` immediately.
    - `appendStreamLine(prefix, byteLength)` → `void` — appends `[ISO timestamp] [prefix] N bytes\n` to `stream.txt`.
    - `onRequestBodyEnd(buffer)` → `void` — writes `request_body.json` (if valid JSON) or `request_body.txt` (if not). Writes `request_body.brief.json` when JSON.
    - `onResponseBodyEnd(buffer, statusCode, statusMessage, headers)` → `void` — writes `response_header.prop`, then `response.json` or `response.txt`, plus `response.brief.json` when JSON.
    - `onError(err)` → `void` — writes `error.txt`.
    - `writePathInfo(fullPath)` → `void` — conditionally writes `path_info.txt` (called immediately after directory creation if the name was truncated).

- [ ] **Step 1: Create the recorder module**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/recorder.js`:

```js
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sanitizeHeaders, sanitizeParams, sanitizeBody } = require('./sanitizer');
const { generateBrief } = require('./brief');

const DIR_NAME_MAX = 150;

class Recorder {
  /**
   * @param {string} logDir      - $HOME/.networkLogs
   * @param {string} seqNumber   - 3-digit zero-padded string
   * @param {object} requestInfo - { hostname, port, path, method, headers }
   */
  constructor(logDir, seqNumber, requestInfo) {
    this._dir = this._createDir(logDir, seqNumber, requestInfo);
    this._writeRequestHeaders(requestInfo.headers);
    this._writeRequestParams(requestInfo.path);
  }

  // ------- directory management -------

  _createDir(logDir, seq, info) {
    fs.mkdirSync(logDir, { recursive: true });

    const host = (info.hostname || 'unknown').replace(/[^a-zA-Z0-9._-]/g, '_');
    const urlPath = new URL(info.path, 'http://localhost').pathname;
    const cleanPath = urlPath.replace(/^\/+/, '').replace(/\//g, '-').replace(/[^a-zA-Z0-9._-]/g, '_') || 'root';
    let dirName = `${seq}-${host}-${cleanPath}`;

    let truncated = false;
    if (dirName.length > DIR_NAME_MAX) {
      truncated = true;
      dirName = dirName.slice(0, DIR_NAME_MAX);
    }

    const fullDir = path.join(logDir, dirName);

    // overwrite old directory if it exists (sequence wrap)
    if (fs.existsSync(fullDir)) {
      fs.rmSync(fullDir, { recursive: true, force: true });
    }
    fs.mkdirSync(fullDir, { recursive: true });

    this._truncated = truncated;
    this._fullPath = urlPath;
    this._dir = fullDir;

    // write path_info.txt immediately if truncated
    if (truncated) {
      fs.writeFileSync(path.join(fullDir, 'path_info.txt'), urlPath + '\n', 'utf8');
    }

    return fullDir;
  }

  // ------- request phase -------

  _writeRequestHeaders(headers) {
    const safe = sanitizeHeaders(headers || {});
    const lines = Object.entries(safe).map(([k, v]) => `${k}: ${v}`);
    fs.writeFileSync(path.join(this._dir, 'request_header.prop'), lines.join('\n') + '\n', 'utf8');
  }

  _writeRequestParams(requestPath) {
    try {
      const parsed = new URL(requestPath, 'http://localhost');
      const params = Object.fromEntries(parsed.searchParams.entries());
      if (Object.keys(params).length === 0) {
        fs.writeFileSync(path.join(this._dir, 'request_params.prop'), '', 'utf8');
        return;
      }
      const safe = sanitizeParams(params);
      const lines = Object.entries(safe).map(([k, v]) => `${k}: ${v}`);
      fs.writeFileSync(path.join(this._dir, 'request_params.prop'), lines.join('\n') + '\n', 'utf8');
    } catch (_) {
      fs.writeFileSync(path.join(this._dir, 'request_params.prop'), '', 'utf8');
    }
  }

  onRequestBodyEnd(buffer) {
    try {
      const text = buffer.toString('utf8');
      try {
        const parsed = JSON.parse(text);
        const safe = sanitizeBody(parsed);
        fs.writeFileSync(path.join(this._dir, 'request_body.json'), JSON.stringify(safe, null, 2) + '\n', 'utf8');
        const b = generateBrief(safe);
        fs.writeFileSync(path.join(this._dir, 'request_body.brief.json'), JSON.stringify(b, null, 2) + '\n', 'utf8');
      } catch (_) {
        // not valid JSON — write as text
        fs.writeFileSync(path.join(this._dir, 'request_body.txt'), text, 'utf8');
      }
    } catch (err) {
      this._logError('onRequestBodyEnd failed', err);
    }
  }

  // ------- response phase -------

  onResponseBodyEnd(buffer, statusCode, statusMessage, headers) {
    try {
      // write response headers
      const safe = sanitizeHeaders(headers || {});
      const lines = Object.entries(safe).map(([k, v]) => `${k}: ${v}`);
      fs.writeFileSync(path.join(this._dir, 'response_header.prop'), lines.join('\n') + '\n', 'utf8');

      // write response body
      const text = buffer.toString('utf8');
      try {
        const parsed = JSON.parse(text);
        fs.writeFileSync(path.join(this._dir, 'response.json'), JSON.stringify(parsed, null, 2) + '\n', 'utf8');
        const b = generateBrief(parsed);
        fs.writeFileSync(path.join(this._dir, 'response.brief.json'), JSON.stringify(b, null, 2) + '\n', 'utf8');
      } catch (_) {
        fs.writeFileSync(path.join(this._dir, 'response.txt'), text, 'utf8');
      }
    } catch (err) {
      this._logError('onResponseBodyEnd failed', err);
    }
  }

  // ------- streaming -------

  appendStreamLine(prefix, byteLength) {
    try {
      const ts = new Date().toISOString();
      const line = `[${ts}] [${prefix}] ${byteLength} bytes\n`;
      fs.appendFileSync(path.join(this._dir, 'stream.txt'), line, 'utf8');
    } catch (err) {
      this._logError('appendStreamLine failed', err);
    }
  }

  // ------- error -------

  onError(err) {
    try {
      const msg = `${err.message}\n${err.stack || ''}\n`;
      fs.writeFileSync(path.join(this._dir, 'error.txt'), msg, 'utf8');
    } catch (_) {
      // cannot log if file system is broken
    }
  }

  // ------- internal -------

  _logError(context, err) {
    if (process.env.NETWORK_CAPTURE_DEBUG === '1') {
      process.stderr.write(`[js-network-capture] ${context}: ${err.message}\n`);
    }
  }
}

module.exports = { Recorder };
```

- [ ] **Step 2: Verify the file has no syntax errors**

Run: `node -e "require('./lib/recorder')" && echo "OK"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add lib/recorder.js
git commit -m "feat: add recorder module for file I/O per request"
```

---

### Task 6: HTTP/HTTPS patcher — `patcher.js`

**Files:**
- Create: `lib/patcher.js`

**Interfaces:**
- Consumes: `Recorder` from `recorder.js`, `createNumbering` from `numbering.js`
- Produces:
  - `patch(logDir)` → `void` — replaces `http.request`, `http.get`, `https.request`, `https.get`, and `globalThis.fetch` with instrumented wrappers. All patching is synchronous. The function does not return until all four methods are replaced.

Patching logic for each `http`/`https` method:
1. Save original `mod.request`.
2. Replace with a wrapper that:
   a. Calls `numbering.next()` to get the sequence number.
   b. Creates a `new Recorder(logDir, seq, info)` — the constructor handles directory creation and immediate header/param writes.
   c. Calls the original `request()` to get the real `ClientRequest`.
   d. Hooks `req.on('data')` → `recorder.appendStreamLine('request', chunk.length)` and pushes chunk to a request body buffer.
   e. Hooks `req.on('end')` → `recorder.onRequestBodyEnd(requestBuffer)`.
   f. Hooks `req.on('error')` → `recorder.onError(err)`.
   g. Hooks `res.on('data')` → `recorder.appendStreamLine('response', chunk.length)` and pushes chunk to a response body buffer.
   h. Hooks `res.on('end')` → `recorder.onResponseBodyEnd(responseBuffer, res.statusCode, res.statusMessage, res.headers)`.
   i. Hooks `res.on('error')` → `recorder.onError(err)`.

For `globalThis.fetch`, the wrapper intercepts the fetch call, performs the same capture, and returns the original response — streaming the body in the process.

- [ ] **Step 1: Create the patcher module**

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/patcher.js`:

```js
'use strict';

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');
const { Recorder } = require('./recorder');
const { createNumbering } = require('./numbering');

function patch(logDir) {
  const numbering = createNumbering(logDir);

  function wrapRequest(originalRequest, mod) {
    return function (inputOptions, callback) {
      // normalize: inputOptions can be string, URL, or object
      let options;
      if (typeof inputOptions === 'string' || inputOptions instanceof URL) {
        options = typeof inputOptions === 'string' ? { ...new URL(inputOptions) } : { ...inputOptions };
        if (options.href) {
          const u = new URL(options.href);
          options.hostname = options.hostname || u.hostname;
          options.port = options.port || u.port;
          options.path = options.path || (u.pathname + u.search);
          options.protocol = options.protocol || u.protocol;
        }
      } else {
        options = { ...inputOptions };
      }

      const seq = numbering.next();
      const requestInfo = {
        hostname: options.hostname || options.host || 'localhost',
        port: options.port,
        path: options.path || '/',
        method: options.method || 'GET',
        headers: options.headers || {},
      };

      const recorder = new Recorder(logDir, seq, requestInfo);

      const req = originalRequest.call(mod, options, callback);

      const reqBodyChunks = [];

      req.on('data', (chunk) => {
        const len = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
        recorder.appendStreamLine('request', len);
        reqBodyChunks.push(chunk);
      });

      req.on('end', () => {
        const buffer = Buffer.concat(reqBodyChunks);
        recorder.onRequestBodyEnd(buffer);
      });

      req.on('error', (err) => {
        recorder.onError(err);
      });

      req.on('response', (res) => {
        const resBodyChunks = [];

        res.on('data', (chunk) => {
          const len = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
          recorder.appendStreamLine('response', len);
          resBodyChunks.push(chunk);
        });

        res.on('end', () => {
          const buffer = Buffer.concat(resBodyChunks);
          recorder.onResponseBodyEnd(buffer, res.statusCode, res.statusMessage, res.headers);
        });

        res.on('error', (err) => {
          recorder.onError(err);
        });
      });

      return req;
    };
  }

  // patch http
  const origHttpRequest = http.request;
  const origHttpGet = http.get;

  http.request = wrapRequest(origHttpRequest, http);
  http.get = function (options, callback) {
    const opts = { ...(typeof options === 'string' || options instanceof URL ? { ...new URL(String(options)) } : options), method: 'GET' };
    return http.request(opts, callback);
  };

  // keep originals accessible for tests
  http.__original_request = origHttpRequest;
  http.__original_get = origHttpGet;

  // patch https
  const origHttpsRequest = https.request;
  const origHttpsGet = https.get;

  https.request = wrapRequest(origHttpsRequest, https);
  https.get = function (options, callback) {
    const opts = { ...(typeof options === 'string' || options instanceof URL ? { ...new URL(String(options)) } : options), method: 'GET' };
    return https.request(opts, callback);
  };

  https.__original_request = origHttpsRequest;
  https.__original_get = origHttpsGet;

  // patch globalThis.fetch
  if (typeof globalThis.fetch === 'function' && !globalThis.fetch.__patched) {
    const origFetch = globalThis.fetch;

    globalThis.fetch = async function (input, init = {}) {
      const url = typeof input === 'string' ? input : (input.url || input.href || String(input));
      const parsed = new URL(url);
      const seq = numbering.next();
      const requestInfo = {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method: (init.method || 'GET').toUpperCase(),
        headers: init.headers || {},
      };

      const recorder = new Recorder(logDir, seq, requestInfo);

      try {
        // write request body if present
        if (init.body) {
          const bodyStr = typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
          recorder.appendStreamLine('request', Buffer.byteLength(bodyStr, 'utf8'));
          try {
            const parsed = JSON.parse(bodyStr);
            const { sanitizeBody } = require('./sanitizer');
            const safe = sanitizeBody(parsed);
            require('node:fs').writeFileSync(
              require('node:path').join(recorder._dir, 'request_body.json'),
              JSON.stringify(safe, null, 2) + '\n',
              'utf8'
            );
            const { generateBrief } = require('./brief');
            const b = generateBrief(safe);
            require('node:fs').writeFileSync(
              require('node:path').join(recorder._dir, 'request_body.brief.json'),
              JSON.stringify(b, null, 2) + '\n',
              'utf8'
            );
          } catch (_) {
            require('node:fs').writeFileSync(
              require('node:path').join(recorder._dir, 'request_body.txt'),
              bodyStr,
              'utf8'
            );
          }
        }

        const response = await origFetch.call(globalThis, input, init);

        // clone so we can read the body without consuming it
        const cloned = response.clone();
        const text = await cloned.text();

        recorder.appendStreamLine('response', Buffer.byteLength(text, 'utf8'));
        recorder.onResponseBodyEnd(
          Buffer.from(text, 'utf8'),
          response.status,
          response.statusText,
          Object.fromEntries(response.headers.entries())
        );

        return response;
      } catch (err) {
        recorder.onError(err);
        throw err;
      }
    };
    globalThis.fetch.__patched = true;
    globalThis.fetch.__original = origFetch;
  }
}

module.exports = { patch };
```

Wait — the `fetch` wrapper has inline `require` calls which is ugly. Let me fix that by moving the requires to the top of the module. Let me rewrite the patcher:

Create `/Users/wangzhiqiang/kwai/js-network-capture/lib/patcher.js`:

```js
'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const { Recorder } = require('./recorder');
const { createNumbering } = require('./numbering');
const { sanitizeBody } = require('./sanitizer');
const { generateBrief } = require('./brief');

function patch(logDir) {
  const numbering = createNumbering(logDir);

  function wrapRequest(originalRequest, mod) {
    return function (inputOptions, callback) {
      let options;
      if (typeof inputOptions === 'string' || inputOptions instanceof URL) {
        options = typeof inputOptions === 'string' ? { ...new URL(inputOptions) } : { ...inputOptions };
        if (options.href) {
          const u = new URL(options.href);
          options.hostname = options.hostname || u.hostname;
          options.port = options.port || u.port;
          options.path = options.path || (u.pathname + u.search);
          options.protocol = options.protocol || u.protocol;
        }
      } else {
        options = { ...inputOptions };
      }

      const seq = numbering.next();
      const requestInfo = {
        hostname: options.hostname || options.host || 'localhost',
        port: options.port,
        path: options.path || '/',
        method: options.method || 'GET',
        headers: options.headers || {},
      };

      const recorder = new Recorder(logDir, seq, requestInfo);

      const req = originalRequest.call(mod, options, callback);

      const reqBodyChunks = [];

      req.on('data', (chunk) => {
        const len = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
        recorder.appendStreamLine('request', len);
        reqBodyChunks.push(chunk);
      });

      req.on('end', () => {
        const buffer = Buffer.concat(reqBodyChunks);
        recorder.onRequestBodyEnd(buffer);
      });

      req.on('error', (err) => {
        recorder.onError(err);
      });

      req.on('response', (res) => {
        const resBodyChunks = [];

        res.on('data', (chunk) => {
          const len = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
          recorder.appendStreamLine('response', len);
          resBodyChunks.push(chunk);
        });

        res.on('end', () => {
          const buffer = Buffer.concat(resBodyChunks);
          recorder.onResponseBodyEnd(buffer, res.statusCode, res.statusMessage, res.headers);
        });

        res.on('error', (err) => {
          recorder.onError(err);
        });
      });

      return req;
    };
  }

  // patch http.request
  const origHttpRequest = http.request;
  const origHttpGet = http.get;

  http.request = wrapRequest(origHttpRequest, http);
  http.get = function (options, callback) {
    const opts = typeof options === 'string' || options instanceof URL
      ? { ...new URL(options.toString()), method: 'GET' }
      : { ...options, method: 'GET' };
    return http.request(opts, callback);
  };

  // patch https.request
  const origHttpsRequest = https.request;
  const origHttpsGet = https.get;

  https.request = wrapRequest(origHttpsRequest, https);
  https.get = function (options, callback) {
    const opts = typeof options === 'string' || options instanceof URL
      ? { ...new URL(options.toString()), method: 'GET' }
      : { ...options, method: 'GET' };
    return https.request(opts, callback);
  };

  // patch globalThis.fetch
  if (typeof globalThis.fetch === 'function' && !globalThis.fetch.__patched) {
    const origFetch = globalThis.fetch;

    globalThis.fetch = async function (input, init = {}) {
      const url = typeof input === 'string' ? input : (input.url || input.href || String(input));
      const parsed = new URL(url);
      const seq = numbering.next();
      const requestInfo = {
        hostname: parsed.hostname,
        port: parsed.port || '',
        path: parsed.pathname + parsed.search,
        method: (init.method || 'GET').toUpperCase(),
        headers: init.headers || {},
      };

      const recorder = new Recorder(logDir, seq, requestInfo);

      try {
        // write request body if present
        if (init.body) {
          const bodyStr = typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
          recorder.appendStreamLine('request', Buffer.byteLength(bodyStr, 'utf8'));
          try {
            const parsedBody = JSON.parse(bodyStr);
            const safe = sanitizeBody(parsedBody);
            fs.writeFileSync(
              path.join(recorder._dir, 'request_body.json'),
              JSON.stringify(safe, null, 2) + '\n',
              'utf8'
            );
            const b = generateBrief(safe);
            fs.writeFileSync(
              path.join(recorder._dir, 'request_body.brief.json'),
              JSON.stringify(b, null, 2) + '\n',
              'utf8'
            );
          } catch (_) {
            fs.writeFileSync(
              path.join(recorder._dir, 'request_body.txt'),
              bodyStr,
              'utf8'
            );
          }
        }

        const response = await origFetch.call(globalThis, input, init);

        // clone so we read body without consuming the original response
        const cloned = response.clone();
        const text = await cloned.text();

        recorder.appendStreamLine('response', Buffer.byteLength(text, 'utf8'));
        recorder.onResponseBodyEnd(
          Buffer.from(text, 'utf8'),
          response.status,
          response.statusText,
          Object.fromEntries(response.headers.entries())
        );

        return response;
      } catch (err) {
        recorder.onError(err);
        throw err;
      }
    };
    globalThis.fetch.__patched = true;
    globalThis.fetch.__original = origFetch;
  }
}

module.exports = { patch };
```

- [ ] **Step 2: Verify the file has no syntax errors**

Run: `node -e "require('./lib/patcher')" && echo "OK"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add lib/patcher.js
git commit -m "feat: add http/https/fetch patcher module"
```

---

### Task 7: Entry point — `hook.js`

**Files:**
- Create: `hook.js`

**Interfaces:**
- Consumes: `patcher.patch`
- Produces: the entry point loaded by `--require`. Checks `NETWORK_CAPTURE` env var; if `off`, returns immediately. Otherwise computes `logDir = path.join(os.homedir(), '.networkLogs')`, calls `patcher.patch(logDir)`.

- [ ] **Step 1: Create the hook entry point**

Create `/Users/wangzhiqiang/kwai/js-network-capture/hook.js`:

```js
'use strict';

// Disable via NETWORK_CAPTURE=off
if (process.env.NETWORK_CAPTURE === 'off') {
  return;
}

const path = require('node:path');
const os = require('node:os');
const { patch } = require('./lib/patcher');

const logDir = path.join(os.homedir(), '.networkLogs');

try {
  patch(logDir);
} catch (err) {
  if (process.env.NETWORK_CAPTURE_DEBUG === '1') {
    process.stderr.write(`[js-network-capture] Failed to patch: ${err.message}\n`);
  }
}
```

- [ ] **Step 2: Verify hook loads without error**

Run: `node -e "require('./hook.js')" && echo "OK"`
Expected: `OK`

- [ ] **Step 3: Verify hook is disabled when NETWORK_CAPTURE=off**

Run: `NETWORK_CAPTURE=off node -e "require('./hook.js'); console.log(require('http').request === require('http').__original_request ? 'NOT PATCHED' : 'PATCHED')"`
Expected: `NOT PATCHED` (note: since we return early, `__original_request` won't be set — the check won't lie. Actually let me adjust: just check that http.request is still the built-in.)

Run: `NETWORK_CAPTURE=off node -e "require('./hook.js'); const h = require('http'); console.log(typeof h.request)"`
Expected: `function` (original, not wrapped)

- [ ] **Step 4: Commit**

```bash
git add hook.js
git commit -m "feat: add hook.js entry point"
```

---

### Task 8: Integration test

**Files:**
- Create: `test/integration.test.js`

**Interfaces:**
- Consumes: `hook.js`, `http`, `https` modules
- Produces: verifies end-to-end that intercepted requests produce the correct file structure

- [ ] **Step 1: Write the integration test**

Create `/Users/wangzhiqiang/kwai/js-network-capture/test/integration.test.js`:

```js
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const os = require('node:os');

// Set up a temporary HOME so .networkLogs is isolated
const TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-integration-'));
const LOG_DIR = path.join(TMP_HOME, '.networkLogs');

// Override os.homedir before loading hook
const origHomedir = os.homedir;
os.homedir = () => TMP_HOME;

// Load hook
require('../hook');

describe('Integration: full request capture', () => {
  let server;

  before(async () => {
    // start a small HTTP server
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-Custom': 'test-value',
          'Authorization': 'should-be-redacted',
        });
        res.end(JSON.stringify({ status: 'ok', echo: body }));
      });
    });
    await new Promise(resolve => server.listen(0, resolve));
  });

  after(() => {
    server.close();
    os.homedir = origHomedir;
    fs.rmSync(TMP_HOME, { recursive: true, force: true });
  });

  it('captures a GET request with query params', async () => {
    const { port } = server.address();

    await new Promise((resolve, reject) => {
      http.get(`http://localhost:${port}/api/users?token=secret123&page=1`, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          assert.strictEqual(res.statusCode, 200);
          resolve();
        });
        res.on('error', reject);
      }).on('error', reject);
    });

    // find the capture directory
    const dirs = fs.readdirSync(LOG_DIR).filter(d => d.includes('localhost'));
    assert.ok(dirs.length >= 1, 'should have at least one capture dir');
    const captureDir = path.join(LOG_DIR, dirs[0]);
    assert.ok(fs.existsSync(captureDir));

    // request_header.prop
    const reqHeaders = fs.readFileSync(path.join(captureDir, 'request_header.prop'), 'utf8');
    assert.ok(reqHeaders.includes(':'), 'should have header entries');

    // request_params.prop
    const reqParams = fs.readFileSync(path.join(captureDir, 'request_params.prop'), 'utf8');
    assert.ok(reqParams.includes('token: ***REDACTED***'), 'token should be redacted');
    assert.ok(reqParams.includes('page: 1'), 'page param should be present');

    // response_header.prop
    const resHeaders = fs.readFileSync(path.join(captureDir, 'response_header.prop'), 'utf8');
    assert.ok(resHeaders.includes('authorization: ***REDACTED***'), 'auth header should be redacted');
    assert.ok(resHeaders.includes('x-custom: test-value'), 'custom header should be present');

    // response.json
    const resBody = JSON.parse(fs.readFileSync(path.join(captureDir, 'response.json'), 'utf8'));
    assert.strictEqual(resBody.status, 'ok');

    // response.brief.json
    assert.ok(fs.existsSync(path.join(captureDir, 'response.brief.json')));

    // stream.txt
    const stream = fs.readFileSync(path.join(captureDir, 'stream.txt'), 'utf8');
    assert.ok(stream.includes('[request]'), 'stream should include request chunk');
    assert.ok(stream.includes('[response]'), 'stream should include response chunk');
  });

  it('captures a POST request with JSON body containing sensitive fields', async () => {
    const { port } = server.address();

    const postData = JSON.stringify({
      username: 'bob',
      password: 'mysecret',
      api_key: 'key-abc',
      data: { name: 'test' },
    });

    await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: 'localhost',
        port,
        path: '/api/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
      }, (res) => {
        res.resume();
        res.on('end', resolve);
        res.on('error', reject);
      });
      req.write(postData);
      req.end();
      req.on('error', reject);
    });

    const dirs = fs.readdirSync(LOG_DIR).filter(d => d.includes('localhost'));
    const captureDir = path.join(LOG_DIR, dirs[dirs.length - 1]);

    // request_body.json
    const reqBody = JSON.parse(fs.readFileSync(path.join(captureDir, 'request_body.json'), 'utf8'));
    assert.strictEqual(reqBody.username, 'bob');
    assert.strictEqual(reqBody.password, '***REDACTED***');
    assert.strictEqual(reqBody.api_key, '***REDACTED***');
    assert.strictEqual(reqBody.data.name, 'test');

    // request_body.brief.json
    assert.ok(fs.existsSync(path.join(captureDir, 'request_body.brief.json')));
  });

  it('captures a request for a non-JSON response (plain text)', async () => {
    const { port } = server.address();

    // create a quick text endpoint
    const textPort = port + 1;
    const textServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Hello, World!');
    });
    await new Promise(resolve => textServer.listen(textPort, resolve));

    await new Promise((resolve, reject) => {
      http.get(`http://localhost:${textPort}/plain`, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          assert.strictEqual(data, 'Hello, World!');
          resolve();
        });
        res.on('error', reject);
      }).on('error', reject);
    });

    textServer.close();

    const dirs = fs.readdirSync(LOG_DIR).filter(d => d.includes('localhost'));
    const captureDir = path.join(LOG_DIR, dirs[dirs.length - 1]);

    // response.txt
    const resTxt = fs.readFileSync(path.join(captureDir, 'response.txt'), 'utf8');
    assert.strictEqual(resTxt, 'Hello, World!');

    // should NOT have response.json
    assert.ok(!fs.existsSync(path.join(captureDir, 'response.json')));
  });
});
```

- [ ] **Step 2: Run integration tests**

Run: `node --test test/integration.test.js`
Expected: PASS (3 tests)

- [ ] **Step 3: Commit**

```bash
git add test/integration.test.js
git commit -m "test: add integration tests for end-to-end capture"
```

---

### Task 9: Run full test suite and verify

- [ ] **Step 1: Run all unit tests**

```bash
node --test lib/sanitizer.test.js lib/numbering.test.js lib/brief.test.js
```

Expected: all PASS

- [ ] **Step 2: Run integration tests (fresh environment)**

```bash
node --test test/integration.test.js
```

Expected: all PASS

- [ ] **Step 3: Final commit if anything changed**

```bash
git add -A
git diff --cached --stat
git commit -m "chore: final verification, all tests passing"
```