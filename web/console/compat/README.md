# Umi dependency security compatibility packages

These private, repository-owned packages preserve the configured Umi Max 4 / React 18 / webpack application
while using upstream security fixes. They are installed with ordinary `npm ci`; no post-install edits,
audit suppression, fabricated upstream releases, or peer-dependency bypass flags are used.

| Local adapter | Upstream implementation / behavior |
| --- | --- |
| `decode-uri-component-cjs` | Exposes the actual `decode-uri-component@0.5.1` default export as the CommonJS function expected by query-string 6. The implementation is not copied or renamed. |
| `react-router-dom-compat` | Re-exports actual `react-router-dom@7.18.4`; its legacy `/server` entry forwards StaticRouter / StaticRouterProvider from actual `react-router@7.18.4`. It does not implement a router. |
| `browser-node-builtins` | Derived from node-libs-browser 2.2.1 under its retained MIT license. Removes its crypto-browserify dependency and maps Node crypto to a module that throws. Other mappings preserve the original common polyfills. |

The decoder and router packages are npm aliases with exact upstream versions and lock-file integrity.
The adapters' own version is 1.0.0; they do not pretend to be patched releases of their upstream packages.
Direct file dependencies plus `$name` override references keep transitive resolution rooted in this project.
The router override is restricted to the 6/7 generation; Dva's separate 4.3.1 API is retained.

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
