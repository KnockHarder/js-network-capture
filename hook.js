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