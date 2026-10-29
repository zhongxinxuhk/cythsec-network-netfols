const numberFormatter = new Intl.NumberFormat('en-US');

/**
 * Format a number with thousand separators.
 * Replaces numeral(val).format('0,0')
 */
export const formatNumber = (val: number | string): string => {
  const parsed = Number(val);
  return Number.isFinite(parsed) ? numberFormatter.format(parsed) : '';
};

/**
 * Format a number as yuan currency string.
 * Replaces `¥ ${numeral(val).format('0,0')}`
 */
export const formatYuan = (val: number | string) => `¥ ${formatNumber(val)}`;

// format.ts - 通用展示格式化工具。
// 移除 utils 目录占位 .gitkeep，这里放首个真实工具函数。

/** 字节数转人类可读字符串（B/KB/MB/GB/TB）。 */
export function fmtBytes(n: number): string {
  if (!n || n < 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  // 字节是离散计数，不存在 1.00 B 这种语义（小数点下无有效信息），
  // 因此 kB 以下固定取整；进位后的单位才按量级决定小数位。
  if (i === 0) return `${v} B`;
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${u[i]}`;
}

/** 整数加千分位逗号。 */
export function fmtInt(n: number): string {
  return n.toLocaleString('en-US');
}
