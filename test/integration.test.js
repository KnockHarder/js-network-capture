const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const os = require('node:os');

// Set up a temporary HOME so .networkLogs is isolated
const TMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-integration-'));
const LOG_DIR = path.join(TMP_HOME, '.networkLogs');
const origHome = process.env.HOME;

// Override HOME before loading hook
process.env.HOME = TMP_HOME;

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
    process.env.HOME = origHome;
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

    // request_header.prop — may be empty for simple GET with no explicit headers
    const reqHeaders = fs.readFileSync(path.join(captureDir, 'request_header.prop'), 'utf8');
    assert.ok(typeof reqHeaders === 'string', 'request_header.prop should exist');

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

    // stream.txt — GET has no request body, so only response chunks
    const stream = fs.readFileSync(path.join(captureDir, 'stream.txt'), 'utf8');
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

    // create a quick text endpoint on a separate port
    const textPort = port + 1;
    const textServer = http.createServer((_req, res) => {
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