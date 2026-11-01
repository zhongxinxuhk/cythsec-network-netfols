# Umi dependency security compatibility packages

These private, repository-owned packages preserve the configured Umi Max 4 / React 18 / webpack application
while using upstream security fixes. They are installed with ordinary `npm ci`; no post-install edits,
audit suppression, fabricated upstream releases, or peer-dependency bypass flags are used.

| Local adapter | Upstream implementation / behavior |
| --- | --- |
| `decode-uri-component-cjs` | Exposes the actual `decode-uri-component@0.5.1` default export as the CommonJS function expected by query-string 6. The implementation is not copied or renamed. |
| `react-router-dom-compat` | Re-exports actual `react-router-dom@7.18.4`; its legacy `/server` entry forwards StaticRouter / StaticRouterProvider from actual `react-router@7.18.4`. It does not implement a router. |
| `browser-node-builtins` | Derived from node-libs-browser 2.2.1 under its retained MIT license. Removes its crypto-browserify dependency and maps Node crypto to a module that throws. Other mappings preserve the original common polyfills. |
| `deepmerge-safe` | Vendored deepmerge 4.3.1 under its MIT license with `__proto__`, `constructor` and `prototype` keys rejected during merge. The merge algorithm is otherwise unchanged. |
| `minimatch-safe` | Thin entry around the actual `minimatch@11.0.3`: keeps the callable CommonJS export expected by older ESLint plugins and also exposes the v11 named exports used by glob 14. Matching logic is not reimplemented. |

The decoder and router packages are npm aliases with exact upstream versions and lock-file integrity.
The adapters' own version is 1.0.0; they do not pretend to be patched releases of their upstream packages.
Direct file dependencies plus `$name` override references keep transitive resolution rooted in this project.
The router override is restricted to the 6/7 generation; Dva's separate 4.3.1 API is retained.

The audit remediation also pins build-only packages that have no compatible in-range update:
`@hono/node-server@2.1.5`, `glob@14.0.3`, `rimraf@6.1.3` and `test-exclude@8.0.0`.
`minimatch` is replaced by `minimatch-safe` because the fixed v11 release is not callable from
CommonJS consumers that still use the v3 function API. These packages are development/build tooling;
the browser bundle and production dependencies are unchanged.

The browser application does not use Node-style signing/ECDH APIs. Those APIs are explicitly unsupported;
new features must use browser Web Crypto or an authenticated server API. The native Node crypto module,
Go cryptography and browser TLS are unaffected. This is removal of unused browser functionality, not a
replacement implementation of elliptic curves. Both node-libs-browser package names use this policy map.

Umi's broad react-router directory alias bypasses v7 package subpath exports. The webpack configuration
removes that alias so normal package exports choose consistent modules for the root and `/dom`.

Acceptance covers the configured webpack build, query parsing, same-origin backslash navigation, legacy
server imports and the existing console routes. Mako / Utoo / Vite bundler modes and full Umi SSR deployment
are not validated. Changes to these upstream versions or enabling another bundler/SSR require new acceptance.

Regression tests: `tests/dependency-security.test.tsx`. Upstream advisory details and verification records:
[Dependency remediation](../../../docs/development/dependency-remediation.md).
