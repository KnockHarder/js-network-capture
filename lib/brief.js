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