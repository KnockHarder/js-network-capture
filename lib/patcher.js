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
  http.request = wrapRequest(http.request, http);
  http.get = function (options, callback) {
    const opts = typeof options === 'string' || options instanceof URL
      ? { ...new URL(options.toString()), method: 'GET' }
      : { ...options, method: 'GET' };
    return http.request(opts, callback);
  };

  // patch https.request
  https.request = wrapRequest(https.request, https);
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