'use strict';

const fs = require('node:fs');
const path = require('node:path');

function createNumbering(logDir) {
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