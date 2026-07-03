'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sanitizeHeaders, sanitizeParams, sanitizeBody } = require('./sanitizer');
const { generateBrief } = require('./brief');

const DIR_NAME_MAX = 150;

/**
 * Try to decode a buffer as UTF-8 text.
 * Returns the string if successful, null if the buffer contains binary data.
 */
function tryDecodeText(buffer) {
  if (buffer.length === 0) return '';
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch (_) {
    return null;
  }
}

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

    // write request_info.prop
    const infoLines = [
      `method: ${info.method || 'GET'}`,
      `hostname: ${info.hostname || 'unknown'}`,
      `port: ${info.port || ''}`,
      `path: ${info.path || '/'}`,
    ];
    fs.writeFileSync(path.join(fullDir, 'request_info.prop'), infoLines.join('\n') + '\n', 'utf8');

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
      if (buffer.length === 0) return;
      const text = tryDecodeText(buffer);
      if (text === null) {
        // binary data — save raw
        fs.writeFileSync(path.join(this._dir, 'request_body.bin'), buffer);
        return;
      }
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
      if (buffer.length === 0) return;
      const text = tryDecodeText(buffer);
      if (text === null) {
        // binary data — save raw
        fs.writeFileSync(path.join(this._dir, 'response.bin'), buffer);
        return;
      }
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