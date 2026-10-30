import { expect, it } from 'vitest';
import deepmerge from 'deepmerge';
import Mock from 'mockjs';
import decode from 'decode-uri-component';

it('null-prototype merges reject poison keys and preserve normal options', () => {
  const source = JSON.parse(
    '{"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted":"yes"}},"safe":{"x":1}}',
  );
  const result = deepmerge<{ safe: { x: number } }>(
    Object.create(null),
    source,
  );
  expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
  expect(({} as { polluted?: string }).polluted).toBeUndefined();
  expect(result.safe).toEqual({ x: 1 });
  expect(deepmerge.all([{ a: [1] }, { a: [2] }])).toEqual({ a: [1, 2] });
});
it('Mock extension entry points reject prototype pollution', () => {
  const payload = JSON.parse(
    '{"__proto__":{"ciPolluted":"yes"},"constructor":{"prototype":{"ciPolluted":"yes"}}}',
  );
  for (const target of [Mock.Util, Mock.Random, Mock.Handler])
    target.extend(payload);
  expect(({} as { ciPolluted?: string }).ciPolluted).toBeUndefined();
  expect(Mock.mock({ 'list|3': [{ value: 1 }] }).list).toHaveLength(3);
});
it('the CJS decoder preserves valid and malformed URL behavior', () => {
  expect(decode('%E4%B8%AD%E6%96%87')).toBe('中文');
  expect(decode('%E0%A4%A')).toBe('%E0%A4%A');
});
