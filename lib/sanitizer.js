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