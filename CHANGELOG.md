# CHANGELOG


## v0.1.0 (2026-06-28)

### Bug Fixes

- Array variables
  ([`b17e3ff`](https://github.com/kgmcquate/graphql-authz-proxy/commit/b17e3ff18b841511caac95f6f4c92becae842f00))

### Features

- #13 Set up releases and tags
  ([`3ddd0b9`](https://github.com/kgmcquate/graphql-authz-proxy/commit/3ddd0b9762231d12b2f31af847c833f0d35c005c))

- #14 Rewrite in Rust
  ([`c19c03e`](https://github.com/kgmcquate/graphql-authz-proxy/commit/c19c03e0325f88bf3d42270b64f4e4e1895c4704))

Establish the Rust<->Python interop foundation for the incremental rewrite:

- rust/ crate (PyO3 + maturin) compiled to the optional graphql_authz_proxy_rs extension module,
  with cargo unit tests. - graphql_authz_proxy._rust loader shim exposing RUST_AVAILABLE and native
  functions, with a pure-Python fallback when the extension is not built. - Port
  extract_user_from_headers to Rust; utils.extract_user_from_headers now delegates to the native
  impl when available and falls back otherwise. - CI builds and installs the extension so the native
  path is exercised. - Document the native components in the README.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

- #15 Publish to PyPI
  ([`e3cf5ad`](https://github.com/kgmcquate/graphql-authz-proxy/commit/e3cf5ad34100aa2b8bbbfbbc7efb7d30057e2390))

### Testing

- #13 add failing tests
  ([`bcb4f12`](https://github.com/kgmcquate/graphql-authz-proxy/commit/bcb4f129d8102aea83a455b4cf0eccc9fb0f5571))

- #14 add failing tests
  ([`75b3906`](https://github.com/kgmcquate/graphql-authz-proxy/commit/75b39061f6a5dede762eadfde0c2dee3cddc3b43))

- #15 add failing tests
  ([`e5edb7f`](https://github.com/kgmcquate/graphql-authz-proxy/commit/e5edb7f1a2c293f81729666a728b687c6921b95f))


## v0.0.1 (2025-09-18)
