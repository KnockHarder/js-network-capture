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