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
    _get_value_of_jsonpath_py,
    extract_user_from_headers,
    get_value_of_jsonpath,
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


# A collection of (data, path, expected) cases that both the pure-Python and
# the native JSONPath implementations must agree on. These mirror the
# behaviour of ``jsonpath_ng.parse(f"$.{path}")`` for the subset of JSONPath
# used by the proxy (dotted field access, integer indices and wildcards).
JSONPATH_CASES = [
    # Falsy data or path short-circuit to None.
    (None, "a", None),
    ({}, "a", None),
    ({"a": 1}, "", None),
    # Simple and nested dotted field access.
    ({"a": 1}, "a", 1),
    ({"a": {"b": 5}}, "a.b", 5),
    ({"a": {"b": {"c": "z"}}}, "a.b.c", "z"),
    ({"a": "hello"}, "a", "hello"),
    # A single match that is itself a list is returned as-is.
    ({"a": [1, 2, 3]}, "a", [1, 2, 3]),
    # Missing keys / traversing through scalars yield no match -> None.
    ({"a": 1}, "a.b", None),
    ({"a": {"b": 5}}, "a.x", None),
    # Integer indices, including negative ones.
    ({"a": [1, 2, 3]}, "a[0]", 1),
    ({"a": [1, 2, 3]}, "a[-1]", 3),
    ({"a": [1]}, "a[5]", None),
    # Wildcards over lists and dict values.
    ({"a": [1, 2, 3]}, "a[*]", [1, 2, 3]),
    ({"a": [9]}, "a[*]", 9),
    ({"a": {"x": 1, "y": 2}}, "a.*", [1, 2]),
    # A value of None is a valid match and is returned as None.
    ({"a": None}, "a", None),
]


@pytest.mark.parametrize(("data", "path", "expected"), JSONPATH_CASES)
def test_get_value_of_jsonpath(data: object, path: str, expected: object) -> None:
    """The public helper resolves JSONPath expressions to the expected value."""
    assert get_value_of_jsonpath(data, path) == expected


@pytest.mark.parametrize(("data", "path", "expected"), JSONPATH_CASES)
def test_get_value_of_jsonpath_pure_python(data: object, path: str, expected: object) -> None:
    """The pure-Python reference resolves JSONPath expressions identically."""
    assert _get_value_of_jsonpath_py(data, path) == expected


@pytest.mark.parametrize(("data", "path", "_expected"), JSONPATH_CASES)
def test_public_jsonpath_matches_pure_python_reference(data: object, path: str, _expected: object) -> None:
    """The public helper (Rust or not) matches the pure-Python reference."""
    assert get_value_of_jsonpath(data, path) == _get_value_of_jsonpath_py(data, path)


@pytest.mark.skipif(not _rust.RUST_AVAILABLE, reason="Rust extension not built")
@pytest.mark.parametrize(("data", "path", "_expected"), JSONPATH_CASES)
def test_native_jsonpath_matches_reference(data: object, path: str, _expected: object) -> None:
    """When built, the native function matches the pure-Python reference."""
    assert _rust.get_value_of_jsonpath(data, path) == _get_value_of_jsonpath_py(data, path)
