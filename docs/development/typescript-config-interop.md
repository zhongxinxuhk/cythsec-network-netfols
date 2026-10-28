# TypeScript 构建配置互操作修复

问题位置为 `web/console/config/config.ts` 的 webpack-chain 默认类型导入。
该库使用 CommonJS `export =` 声明，单独检查构建配置时会依赖默认导入互操作选项。

修复使用 `@umijs/bundler-webpack` 的具名 `IConfig` 导出提取 `chainWebpack` 参数类型，
移除对 CommonJS 默认类型导入的依赖。不能直接删除参数注解：独立 Node 配置没有 Umi
生成的插件别名时，`defineConfig` 的上下文类型不足，会产生 TS7006。

主项目与 Node 项目均显式启用 `esModuleInterop` 和 `allowSyntheticDefaultImports`。
主项目同时纳入 `config/**/*.ts`、根级构建配置及 `version-source.ts`，使 IDE 与命令行
都能检查这些文件。保留严格模式，没有增加 `any`、忽略注释或关闭类型检查。

验证证据保留在本机 `build/typescript-interop/`：两套 `tsc --noEmit`、关闭互操作选项的
Node 配置回归检查、CLion 文件诊断、完整 lint、默认完整测试与生产构建。
本记录的门禁结果在验证结束后补齐。
