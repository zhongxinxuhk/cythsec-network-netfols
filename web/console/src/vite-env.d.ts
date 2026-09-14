/// <reference types="vite/client" />

// vite.config.ts 通过 define 注入的编译期常量。
//
// 之所以要显式声明：`define` 只做编译期文本替换 —— 源码中若无人引用
// `__APP_VERSION__`，产物里根本不会出现版本号（注入空转）。此前该常量
// 在源码中零引用，故前端这一端「版本号单一来源」实际并未生效。
// 版本值取自仓库根 VERSION，与 C++ / Rust / Go 三端同源。
declare const __APP_VERSION__: string;
