// version.ts - 应用版本号（唯一真源的读取出口）。
//
// 版本值由 config/config.ts 在构建期从仓库根 VERSION 读取并注入为编译期常量
// __APP_VERSION__，与 C++ / Rust / Go 三端同源。
//
// 为什么包一层而不是各处直接用全局：集中处理「常量未注入」这一情况。
// 该常量由构建期文本替换产生，正常构建下必然存在；但若在未经 Umi 构建处理的
// 环境（某些测试运行器、被单独引用的模块）里取值，会抛 ReferenceError。
// 统一降级为 'dev'，使界面仍可渲染，同时不掩盖真实构建下取到的值。

/** 构建期注入的应用版本号；无法取得时为 'dev'。 */
export function appVersion(): string {
  try {
    return typeof __APP_VERSION__ === 'string' && __APP_VERSION__ !== '' ? __APP_VERSION__ : 'dev';
  } catch {
    // 常量未注入时该标识符未声明，取值抛 ReferenceError。
    return 'dev';
  }
}

/** 带前缀的版本标签，便于直接放进 UI。 */
export function versionLabel(): string {
  return `v${appVersion()}`;
}

/** 版本号是否形如 semver（含预发布/构建后缀）；'dev' 视为非 semver。 */
export function isSemver(v: string): boolean {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(v);
}
