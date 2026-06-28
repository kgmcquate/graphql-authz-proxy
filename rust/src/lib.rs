//! Native Rust components for `graphql-authz-proxy`.
//!
//! This crate is the foundation of the incremental Rust rewrite (issue #14).
//! It is compiled by [maturin](https://www.maturin.rs/) into a Python
//! extension module named `graphql_authz_proxy_rs` and loaded from Python
//! through the `graphql_authz_proxy._rust` shim, which falls back to the
//! pure-Python implementation when this extension is not built.

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

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

/// A single step in a JSONPath expression.
///
/// Only the subset of JSONPath actually exercised by the proxy is modelled:
/// dotted field access, integer indices (including negative ones) and
/// wildcards (`a.*` / `a[*]`). Anything outside this grammar fails to parse,
/// which the caller maps to "no match" -- mirroring how the pure-Python
/// reference swallows `jsonpath_ng` errors and returns `None`.
#[derive(Debug, PartialEq)]
enum Step {
    /// Access a mapping key by name.
    Field(String),
    /// Index into a sequence (negative indices count from the end).
    Index(isize),
    /// Match every element of a sequence or every value of a mapping.
    Wildcard,
}

/// Parse a `$.`-relative JSONPath string into a list of [`Step`]s.
///
/// Returns `None` for any syntax outside the supported subset, so the caller
/// can treat unparseable paths as a non-match.
fn parse_path(path: &str) -> Option<Vec<Step>> {
    let mut steps = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                // A leading or doubled '.' (empty field name) is invalid.
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
                    i += 1;
                }
                let name = &path[start..i];
                if name.is_empty() {
                    return None;
                }
                steps.push(field_or_wildcard(name));
            }
            b'[' => {
                let end = path[i..].find(']')? + i;
                let inner = &path[i + 1..end];
                steps.push(parse_bracket(inner)?);
                i = end + 1;
            }
            _ => {
                // The very first segment has no leading separator.
                if !steps.is_empty() {
                    return None;
                }
                let start = i;
                while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
                    i += 1;
                }
                steps.push(field_or_wildcard(&path[start..i]));
            }
        }
    }
    Some(steps)
}

/// Map a bare segment name to a [`Step::Wildcard`] or [`Step::Field`].
fn field_or_wildcard(name: &str) -> Step {
    if name == "*" {
        Step::Wildcard
    } else {
        Step::Field(name.to_string())
    }
}

/// Parse the contents of a `[...]` selector into a [`Step`].
fn parse_bracket(inner: &str) -> Option<Step> {
    if inner == "*" {
        Some(Step::Wildcard)
    } else {
        inner.parse::<isize>().ok().map(Step::Index)
    }
}

/// Recursively collect every value reachable from `data` via `steps`.
fn collect_matches<'py>(
    data: &Bound<'py, PyAny>,
    steps: &[Step],
    out: &mut Vec<Bound<'py, PyAny>>,
) {
    let Some((step, rest)) = steps.split_first() else {
        out.push(data.clone());
        return;
    };
    match step {
        Step::Field(name) => {
            if let Ok(dict) = data.downcast::<PyDict>() {
                if let Ok(Some(value)) = dict.get_item(name) {
                    collect_matches(&value, rest, out);
                }
            }
        }
        Step::Index(index) => {
            if let Ok(list) = data.downcast::<PyList>() {
                let len = list.len() as isize;
                let resolved = if *index < 0 { index + len } else { *index };
                if resolved >= 0 && resolved < len {
                    if let Ok(value) = list.get_item(resolved as usize) {
                        collect_matches(&value, rest, out);
                    }
                }
            }
        }
        Step::Wildcard => {
            if let Ok(list) = data.downcast::<PyList>() {
                for value in list.iter() {
                    collect_matches(&value, rest, out);
                }
            } else if let Ok(dict) = data.downcast::<PyDict>() {
                for (_key, value) in dict.iter() {
                    collect_matches(&value, rest, out);
                }
            }
        }
    }
}

/// Resolve a JSONPath expression against `data`, mirroring
/// `graphql_authz_proxy.authz.utils.get_value_of_jsonpath`.
///
/// The `path` is the JSONPath body without the leading `$.`. Returns `None`
/// when `data` or `path` is falsy, when the path does not parse, or when it
/// matches nothing. A single match is returned unwrapped; multiple matches are
/// returned as a list.
#[pyfunction]
fn get_value_of_jsonpath(
    py: Python<'_>,
    data: &Bound<'_, PyAny>,
    path: &str,
) -> PyResult<PyObject> {
    if path.is_empty() || !data.is_truthy()? {
        return Ok(py.None());
    }
    let Some(steps) = parse_path(path) else {
        return Ok(py.None());
    };
    let mut matches = Vec::new();
    collect_matches(data, &steps, &mut matches);
    match matches.len() {
        0 => Ok(py.None()),
        1 => Ok(matches.into_iter().next().unwrap().unbind()),
        _ => Ok(PyList::new(py, matches)?.into_any().unbind()),
    }
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
    m.add_function(wrap_pyfunction!(get_value_of_jsonpath, m)?)?;
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

    #[test]
    fn parses_dotted_field_path() {
        assert_eq!(
            parse_path("a.b.c"),
            Some(vec![
                Step::Field("a".into()),
                Step::Field("b".into()),
                Step::Field("c".into()),
            ])
        );
    }

    #[test]
    fn parses_indices_and_wildcards() {
        assert_eq!(
            parse_path("a[0].b[-1].c[*]"),
            Some(vec![
                Step::Field("a".into()),
                Step::Index(0),
                Step::Field("b".into()),
                Step::Index(-1),
                Step::Field("c".into()),
                Step::Wildcard,
            ])
        );
        assert_eq!(parse_path("a.*"), Some(vec![Step::Field("a".into()), Step::Wildcard]));
    }

    #[test]
    fn rejects_malformed_paths() {
        // Doubled separators (empty field names) and unterminated brackets.
        assert_eq!(parse_path("a..b"), None);
        assert_eq!(parse_path("a["), None);
        assert_eq!(parse_path("a[x]"), None);
    }
}
