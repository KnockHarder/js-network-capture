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