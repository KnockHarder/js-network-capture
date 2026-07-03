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

function urlToRequestOptions(url) {
  const u = typeof url === 'string' ? new URL(url) : url;
  return {
    hostname: u.hostname,
    port: u.port || (u.protocol === 'https:' ? 443 : 80),
    path: u.pathname + u.search,
    protocol: u.protocol,
  };
}

function normalizeOptions(inputOptions) {
  if (typeof inputOptions === 'string') {
    return urlToRequestOptions(new URL(inputOptions));
  }
  if (inputOptions instanceof URL) {
    return urlToRequestOptions(inputOptions);
  }
  // URL fields may be on the prototype (spread doesn't copy them)
  if (inputOptions.href) {
    const u = new URL(inputOptions.href);
    return {
      hostname: inputOptions.hostname || u.hostname,
      port: inputOptions.port || u.port || (inputOptions.protocol === 'https:' ? 443 : 80),
      path: inputOptions.path || (u.pathname + u.search),
      protocol: inputOptions.protocol || u.protocol,
      method: inputOptions.method,
      headers: inputOptions.headers || {},
    };
  }
  return {
    hostname: inputOptions.hostname || inputOptions.host || 'localhost',
    port: inputOptions.port,
    path: inputOptions.path || '/',
    method: inputOptions.method || 'GET',
    headers: inputOptions.headers || {},
  };
}

function patch(logDir) {
  const numbering = createNumbering(logDir);

  function wrapRequest(originalRequest, mod) {
    return function (inputOptions, callback) {
      const options = normalizeOptions(inputOptions);

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
      const origWrite = req.write.bind(req);
      const origEnd = req.end.bind(req);

      req.write = function (chunk, encoding, cb) {
        if (chunk) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
          recorder.appendStreamLine('request', buf.length);
          reqBodyChunks.push(buf);
        }
        return origWrite(chunk, encoding, cb);
      };

      req.end = function (chunk, encoding, cb) {
        if (chunk) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
          recorder.appendStreamLine('request', buf.length);
          reqBodyChunks.push(buf);
        }
        recorder.onRequestBodyEnd(
          reqBodyChunks.length > 0 ? Buffer.concat(reqBodyChunks) : Buffer.alloc(0)
        );
        return origEnd(chunk, encoding, cb);
      };

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
  http.request = wrapRequest(http.request, http);
  http.get = function (options, callback) {
    return http.request(options, callback).end();
  };

  // patch https.request
  https.request = wrapRequest(https.request, https);
  https.get = function (options, callback) {
    return https.request(options, callback).end();
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