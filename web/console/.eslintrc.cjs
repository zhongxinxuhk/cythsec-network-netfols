// .eslintrc.cjs - cythsec console 的 ESLint 配置。
// 目标：类型感知的规则 + React Hooks 规则 + 与 TS 编译关口互补（tsc 管类型，eslint 管风格与陷阱）。
// 注意：本文件是 CJS，因为 package.json 里 "type": "module"。
module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    ecmaFeatures: { jsx: true },
    // 开启类型感知能力所需的 project 指向。
    project: ['./tsconfig.json', './tsconfig.node.json'],
    tsconfigRootDir: __dirname,
  },
  plugins: ['@typescript-eslint', 'react-hooks', 'react-refresh'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  ignorePatterns: ['dist', 'node_modules', '*.cjs', 'vite.config.ts', 'vitest.config.ts', 'coverage', 'src/.umi', 'src/.umi-production'],
  overrides: [{ files: ['config/**/*.ts', '*.config.ts', 'version-source.ts'], env: { node: true } }, {
    files: ['src/pages/**/*.tsx', 'src/components/**/*.tsx'],
    excludedFiles: ['**/*.test.tsx'],
    rules: { 'no-restricted-syntax': ['error', { selector: 'JSXOpeningElement[name.name=/^(button|input|select|textarea|table|meter)$/]', message: '前端标准：使用 Ant Design / ProComponents 控件，规则见 AGENTS.md。' }] },
  }],
  rules: {
    // React Hooks 规则：条件调用、依赖数组遗漏会直接导致运行时 bug，必须拦截。
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    // 热更新完整性：组件文件只应导出组件，避免 fast-refresh 失效。
    'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    // 未使用变量：允许以 _ 前缀显式忽略（常见于解构丢弃）。
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    // 本项目需要与后端 JSON 字段精确对应，允许显式 any 之外的宽松度由 tsc 把关；
    // 但禁止非空断言滥用带来的空指针风险。
    '@typescript-eslint/no-non-null-assertion': 'warn',
    // 生产代码不应留调试输出。
    'no-console': ['warn', { allow: ['warn', 'error'] }],
    // 与 tsc 的 strict 保持一致，避免两套标准冲突。
    eqeqeq: ['error', 'always'],
    'prefer-const': 'error',
  },
};
