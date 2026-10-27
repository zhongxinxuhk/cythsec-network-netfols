// format.test.ts - 展示格式化工具的边界行为测试。
// 这些函数直接决定控制台上显示的流量数字是否可信，因此边界值必须锁死。
import { describe, expect, it } from 'vitest';
import { fmtBytes, fmtInt } from './format';

describe('fmtBytes', () => {
  it('0 与负数一律归一化为 "0 B"（负数来自计数器回绕，不应显示负流量）', () => {
    expect(fmtBytes(0)).toBe('0 B');
    expect(fmtBytes(-1)).toBe('0 B');
    expect(fmtBytes(-1024)).toBe('0 B');
  });

  it('小于 1KiB 时按整数显示字节', () => {
    expect(fmtBytes(1)).toBe('1 B');
    expect(fmtBytes(512)).toBe('512 B');
    expect(fmtBytes(1023)).toBe('1023 B');
  });

  it('恰好 1024 应进位到 KiB，而不是显示 1024 B', () => {
    expect(fmtBytes(1024)).toBe('1.00 KiB');
  });

  it('按数值大小自适应小数位：<10 两位、<100 一位、>=100 零位', () => {
    expect(fmtBytes(1536)).toBe('1.50 KiB'); // 1.5
    expect(fmtBytes(10 * 1024)).toBe('10.0 KiB'); // 10 走一位
    expect(fmtBytes(100 * 1024)).toBe('100 KiB'); // 100 走零位
  });

  it('正确逐级进位到 MiB / GiB / TiB', () => {
    expect(fmtBytes(1024 ** 2)).toBe('1.00 MiB');
    expect(fmtBytes(1024 ** 3)).toBe('1.00 GiB');
    expect(fmtBytes(1024 ** 4)).toBe('1.00 TiB');
  });

  it('超过 TiB 后不再进位，避免出现无单位可用的超范围输出', () => {
    // 单位表最大到 TiB，因此 1PB 会显示为 1024 TiB
    expect(fmtBytes(1024 ** 5)).toBe('1024 TiB');
  });
});

describe('fmtInt', () => {
  it('按千分位分组', () => {
    expect(fmtInt(0)).toBe('0');
    expect(fmtInt(999)).toBe('999');
    expect(fmtInt(1000)).toBe('1,000');
    expect(fmtInt(1234567)).toBe('1,234,567');
  });
});
