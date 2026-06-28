"""Tests for the Rust <-> Python interop layer.

These tests cover the first step of the incremental Rust rewrite (issue #14):
a native extension module is wired into the package through a thin Python
loader (``graphql_authz_proxy._rust``) that transparently falls back to the
pure-Python implementation when the compiled extension is unavailable.

The interop is validated from two angles:

* The public ``extract_user_from_headers`` helper must behave identically
  regardless of whether the Rust extension is loaded (parity), and
* When the Rust extension *is* built, its native function must produce the
  exact same results as the pure-Python reference implementation.
"""

import pytest

from graphql_authz_proxy import _rust
from graphql_authz_proxy.authz.utils import (
    _extract_user_from_headers_py,
    extract_user_from_headers,
)

# A representative set of proxy headers as forwarded by oauth2-proxy.
SAMPLE_HEADERS = {
    "X-Forwarded-Email": "alice@example.com",
    "X-Forwarded-User": "alice",
    "X-Forwarded-Access-Token": "tok-123",
    "X-Forwarded-Groups": "admins, viewers ,  team-a",
}


def test_rust_loader_exposes_availability_flag() -> None:
    """The loader always exposes a boolean availability flag."""
    assert isinstance(_rust.RUST_AVAILABLE, bool)


def test_extract_user_from_headers_basic() -> None:
    """The public helper extracts and trims user/group information."""
    email, user, token, groups = extract_user_from_headers(SAMPLE_HEADERS)
    assert email == "alice@example.com"
    assert user == "alice"
    assert token == "tok-123"
    # Groups are comma-split and individually stripped of surrounding spaces.
    assert groups == ["admins", "viewers", "team-a"]


def test_extract_user_from_headers_defaults_to_empty() -> None:
    """Missing headers default to empty strings; empty groups -> ['']."""
    email, user, token, groups = extract_user_from_headers({})
    assert email == ""
    assert user == ""
    assert token == ""
    assert groups == [""]


def test_public_helper_matches_pure_python_reference() -> None:
    """The public helper (Rust or not) matches the pure-Python reference."""
    assert extract_user_from_headers(SAMPLE_HEADERS) == _extract_user_from_headers_py(SAMPLE_HEADERS)


@pytest.mark.skipif(not _rust.RUST_AVAILABLE, reason="Rust extension not built")
def test_native_extract_matches_reference() -> None:
    """When built, the native function matches the pure-Python reference."""
    native = _rust.extract_user_from_headers(SAMPLE_HEADERS)
    assert native == _extract_user_from_headers_py(SAMPLE_HEADERS)


@pytest.mark.skipif(not _rust.RUST_AVAILABLE, reason="Rust extension not built")
def test_native_version_is_reported() -> None:
    """The native module reports a non-empty semantic-ish version string."""
    version = _rust.version()
    assert isinstance(version, str)
    assert version
