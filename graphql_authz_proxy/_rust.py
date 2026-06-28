"""Loader shim for the optional native Rust extension.

This module is the single integration point between the Python package and the
compiled ``graphql_authz_proxy_rs`` extension produced by the ``rust/`` crate
(see issue #14). It exposes:

* ``RUST_AVAILABLE`` -- ``True`` when the native extension is importable.
* The native functions (e.g. ``extract_user_from_headers``, ``version``) when
  available, so callers can prefer them while keeping a pure-Python fallback.

Keeping the ``try/except`` import isolated here means the rest of the codebase
can simply do ``from graphql_authz_proxy import _rust`` and branch on
``_rust.RUST_AVAILABLE`` without scattering import guards everywhere.
"""

try:  # pragma: no cover - exercised via RUST_AVAILABLE branches in callers
    import graphql_authz_proxy_rs as _native

    RUST_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on whether the crate is built
    _native = None
    RUST_AVAILABLE = False


def extract_user_from_headers(headers: object) -> tuple[str, str, str, list[str]]:
    """Native implementation of header extraction.

    Raises:
        RuntimeError: If the native extension is not available.

    """
    if _native is None:
        raise RuntimeError("Rust extension 'graphql_authz_proxy_rs' is not available")
    return _native.extract_user_from_headers(headers)


def version() -> str:
    """Return the version reported by the native extension.

    Raises:
        RuntimeError: If the native extension is not available.

    """
    if _native is None:
        raise RuntimeError("Rust extension 'graphql_authz_proxy_rs' is not available")
    return _native.version()
