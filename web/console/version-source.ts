// version-source.ts —— 前端构建/测试配置共用的「版本真源读取」实现。
//
// 为什么单独成文件：这段逻辑此前在 vite.config.ts 与 vitest.config.ts 里**各写了一份**。
// 上游修掉了自己那份的路径错误（三级上溯 -> 两级），却没有同步下游副本，于是
// vitest 侧仍在读仓库**外**的 ../../../VERSION，ENOENT 又被自身的 catch 吞掉、
// 静默回落 'dev'。结果是 version.test.ts 的两个用例红灯，而它本来的职责恰恰是
// 「证明版本注入链路是通的」—— 测试自己带着同一个 bug，就只能验证出降级值。
//
// 这正是 vite.config.ts 注释里警告过的「同类问题再次隐身」。两份副本是根因，
// 因此把实现收敛为一处：以后不论改路径还是改兜底策略，都只可能改在这里。
//
// 定位方式：本文件位于 web/console，仓库根在其上两级。
import { readFileSync } from 'fs';
import { resolve } from 'path';

/** 版本真源相对 web/console 的路径。 */
export const VERSION_FILE_REL = '../../VERSION';

/**
 * 从仓库根 VERSION 读取版本号。
 *
 * @param baseDir 调用方所在目录（构建配置文件里传 `__dirname`）。本文件自身不计算
 *   目录，是因为被 import 后 `__dirname` 指向本文件所在目录，而调用方的位置才是
 *   决定相对路径的基准 —— 让调用方显式传入，路径语义才不会被 import 关系悄悄改变。
 *
 * **刻意不静默兜底**：读不到就抛出，让构建/测试直接失败。
 * 静默回落到 'dev' 会让「版本号没接上真源」表现为「版本号看起来有值」，
 * 这类隐性退化正是本模块存在的原因。
 */
export function readRootVersion(baseDir: string): string {
  const file = resolve(baseDir, VERSION_FILE_REL);
  let raw: string;
  try {
    raw = readFileSync(file, 'utf-8');
  } catch (err) {
    throw new Error(
      `无法读取版本真源 ${file}：${err instanceof Error ? err.message : String(err)}` +
        `（期望位置为仓库根 VERSION，路径按 ${VERSION_FILE_REL} 从 ${baseDir} 解析）`,
    );
  }
  const v = raw.trim();
  if (!v) {
    throw new Error(`版本真源 ${file} 为空 —— 单一真源缺失，无法继续`);
  }
  return v;
}
