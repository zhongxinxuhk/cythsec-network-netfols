// Standalone design artifact; reuse installed packages without changing production routes.
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir, writeFile } from "node:fs/promises";

const directory = dirname(fileURLToPath(import.meta.url));
const root = resolve(directory, "../..");
const require = createRequire(resolve(root, "web/console/package.json"));
const { build } = require("esbuild");
const output = resolve(root, "build/console-design-preview");
await mkdir(output, { recursive: true });
const ts = require("typescript");
const modules = resolve(root, "web/console/node_modules");
const program = ts.createProgram([resolve(directory, "preview.tsx")], {
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  jsx: ts.JsxEmit.ReactJSX,
  strict: true,
  noEmit: true,
  noUnusedLocals: true,
  noUnusedParameters: true,
  esModuleInterop: true,
  skipLibCheck: true,
  baseUrl: modules,
  paths: {
    react: ["@types/react"],
    "react/*": ["@types/react/*"],
    "react-dom/*": ["@types/react-dom/*"],
  },
  typeRoots: [resolve(modules, "@types")],
});
const diagnostics = ts.getPreEmitDiagnostics(program);
if (diagnostics.length) {
  console.error(
    ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCanonicalFileName: (value) => value,
      getCurrentDirectory: () => root,
      getNewLine: () => "\n",
    }),
  );
  process.exitCode = 1;
} else {
  const { ESLint } = require("eslint");
  const eslint = new ESLint({
    useEslintrc: false,
    overrideConfigFile: resolve(root, "web/console/.eslintrc.cjs"),
    // This design artifact lives outside the production tsconfig; strict TS ran above.
    overrideConfig: {
      parserOptions: { project: null },
      // Standalone static bundle has no development Fast Refresh runtime.
      rules: { "react-refresh/only-export-components": "off" },
    },
  });
  const lintResults = await eslint.lintFiles([
    resolve(directory, "preview.tsx"),
  ]);
  if (lintResults.some((result) => result.errorCount || result.warningCount)) {
    console.error(
      await (await eslint.loadFormatter("stylish")).format(lintResults),
    );
    process.exit(1);
  }
  await build({
    entryPoints: [resolve(directory, "preview.tsx")],
    outfile: resolve(output, "preview.js"),
    bundle: true,
    minify: true,
    sourcemap: false,
    platform: "browser",
    mainFields: ["browser", "module", "main"],
    target: ["es2022"],
    jsx: "automatic",
    nodePaths: [resolve(root, "web/console/node_modules")],
    define: { "process.env.NODE_ENV": '"production"' },
  });
  await writeFile(
    resolve(output, "index.html"),
    '<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CythSec 控制台设计预览</title><link rel="stylesheet" href="preview.css"></head><body><div id="root"></div><script src="preview.js"></script></body></html>\n',
  );
  console.log(
    `Design preview built: ${output}/index.html (synthetic data, no API requests)`,
  );
}
