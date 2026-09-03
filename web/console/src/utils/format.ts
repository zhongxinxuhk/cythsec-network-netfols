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
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${u[i]}`;
}

/** 整数加千分位逗号。 */
export function fmtInt(n: number): string {
  return n.toLocaleString('en-US');
}
