//! Native Rust components for `graphql-authz-proxy`.
//!
//! This crate is the foundation of the incremental Rust rewrite (issue #14).
//! It is compiled by [maturin](https://www.maturin.rs/) into a Python
//! extension module named `graphql_authz_proxy_rs` and loaded from Python
//! through the `graphql_authz_proxy._rust` shim, which falls back to the
//! pure-Python implementation when this extension is not built.

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

/// Parse a raw `X-Forwarded-Groups` header value into a list of group names.
///
/// Mirrors the Python reference exactly: the value is split on commas and each
/// element is stripped of surrounding whitespace. Note that an empty string
/// yields `[""]` (a single empty group), matching `"".split(",")` in Python.
fn parse_groups(raw: &str) -> Vec<String> {
    raw.split(',').map(|group| group.trim().to_string()).collect()
}

/// Read a header value via the mapping's `get(key, "")` method.
///
/// Accepting any object with a `.get()` method (rather than a concrete dict)
/// preserves the behaviour of Werkzeug's case-insensitive `Headers` object as
/// well as plain dicts, exactly like the Python implementation.
fn header_get(headers: &Bound<'_, PyAny>, key: &str) -> PyResult<String> {
    let value = headers.call_method1("get", (key, ""))?;
    value
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err(format!("{key} header is not a string")))
}

/// Extract `(user_email, username, access_token, groups)` from proxy headers.
///
/// This is a faithful Rust port of
/// `graphql_authz_proxy.authz.utils.extract_user_from_headers`.
#[pyfunction]
fn extract_user_from_headers(
    headers: &Bound<'_, PyAny>,
) -> PyResult<(String, String, String, Vec<String>)> {
    let user_email = header_get(headers, "X-Forwarded-Email")?;
    let user = header_get(headers, "X-Forwarded-User")?;
    let access_token = header_get(headers, "X-Forwarded-Access-Token")?;
    let groups = parse_groups(&header_get(headers, "X-Forwarded-Groups")?);
    Ok((user_email, user, access_token, groups))
}

/// Return the version of the native crate, for diagnostics/health checks.
#[pyfunction]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The `graphql_authz_proxy_rs` Python module definition.
#[pymodule]
fn graphql_authz_proxy_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(extract_user_from_headers, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims_groups() {
        assert_eq!(
            parse_groups("admins, viewers ,  team-a"),
            vec!["admins", "viewers", "team-a"]
        );
    }

    #[test]
    fn empty_groups_yields_single_empty_string() {
        // Matches Python's `"".split(",")` behaviour.
        assert_eq!(parse_groups(""), vec![""]);
    }

    #[test]
    fn single_group_has_no_separator() {
        assert_eq!(parse_groups("admins"), vec!["admins"]);
    }
}
