"""Tests that the packaging pipeline compiles the native Rust extension.

Issue #20: ``uv build`` with the hatchling backend produced a pure-Python
wheel (``...-py3-none-any.whl``) that did *not* contain the compiled
``graphql_authz_proxy_rs`` crate, so end users had no native acceleration and
no way to get it without compiling Rust themselves.

These tests pin the build configuration that makes wheels ship the compiled
extension:

* the project builds through ``maturin`` (the PyO3 build backend) against the
  ``rust/`` crate, in a mixed Python/Rust layout;
* the native module name stays wired consistently across ``pyproject.toml``,
  the Rust ``#[pymodule]`` and the ``_rust`` loader shim; and
* both the PyPI publish workflow and the Docker image actually compile Rust.
"""
import os
import re

import tomllib


def _repo_root() -> str:
    """Walk up from this test file until the directory containing pyproject.toml."""
    current = os.path.dirname(os.path.abspath(__file__))
    while current != os.path.dirname(current):
        if os.path.isfile(os.path.join(current, "pyproject.toml")):
            return current
        current = os.path.dirname(current)
    raise FileNotFoundError("Could not locate pyproject.toml above the test file")


def _load_pyproject() -> dict:
    with open(os.path.join(_repo_root(), "pyproject.toml"), "rb") as handle:
        return tomllib.load(handle)


def _read(*parts: str) -> str:
    with open(os.path.join(_repo_root(), *parts), encoding="utf-8") as handle:
        return handle.read()


def _workflow_text() -> str:
    """Concatenate every workflow file so assertions are placement-agnostic."""
    workflows_dir = os.path.join(_repo_root(), ".github", "workflows")
    text = ""
    for name in sorted(os.listdir(workflows_dir)):
        if name.endswith((".yml", ".yaml")):
            text += _read(".github", "workflows", name)
    return text


def test_build_backend_is_maturin() -> None:
    """A pure-Python backend can't compile Rust; maturin must drive the build."""
    build_system = _load_pyproject()["build-system"]
    assert build_system["build-backend"] == "maturin"
    assert any("maturin" in req for req in build_system["requires"]), (
        "[build-system].requires must pull in maturin"
    )


def test_maturin_builds_the_rust_crate() -> None:
    """maturin must be pointed at the rust/ crate in a mixed Python/Rust layout."""
    maturin = _load_pyproject().get("tool", {}).get("maturin")
    assert maturin is not None, "[tool.maturin] configuration must be present"
    assert maturin.get("manifest-path") == "rust/Cargo.toml", (
        "maturin must build the crate defined in rust/Cargo.toml"
    )
    # python-source keeps the existing pure-Python package shipping alongside
    # the compiled extension (mixed layout).
    assert maturin.get("python-source"), "maturin must declare python-source for the mixed layout"
    assert maturin.get("module-name"), "maturin must declare the native module-name"


def test_native_module_name_is_wired_consistently() -> None:
    """The maturin module-name, the #[pymodule] fn and the loader must agree."""
    module_name = _load_pyproject()["tool"]["maturin"]["module-name"]
    # Mixed layout: the extension is a submodule of the Python package.
    assert module_name.startswith("graphql_authz_proxy."), (
        "in a mixed layout the native module must be a submodule of the package"
    )
    leaf = module_name.rsplit(".", 1)[-1]

    lib_rs = _read("rust", "src", "lib.rs")
    assert re.search(rf"#\[pymodule\]\s*(?:#\[[^\]]*\]\s*)*fn\s+{re.escape(leaf)}\b", lib_rs), (
        f"rust/src/lib.rs must expose a #[pymodule] fn named '{leaf}'"
    )

    shim = _read("graphql_authz_proxy", "_rust.py")
    assert leaf in shim, f"the _rust loader shim must import the '{leaf}' native module"


def test_publish_workflow_compiles_rust() -> None:
    """The PyPI publish pipeline must build compiled wheels via maturin."""
    text = _workflow_text()
    assert "maturin" in text, "the publish workflow must use maturin to build compiled wheels"
    # The official publish action must still upload the artifacts to PyPI.
    assert "pypa/gh-action-pypi-publish" in text


def test_publish_workflow_does_not_ship_pure_python_wheel() -> None:
    """The old pure-Python ``uv build`` step must not produce the published wheel."""
    publish = _read(".github", "workflows", "publish-pypi.yml")
    assert "uv build --sdist --wheel" not in publish, (
        "uv build with hatchling produced a pure-Python wheel; use maturin instead"
    )


def test_dockerfile_compiles_rust() -> None:
    """The Docker image must compile the Rust extension, not skip it."""
    dockerfile = _read("Dockerfile")
    # The crate sources have to be present in the build context to compile.
    assert "rust" in dockerfile, "the Dockerfile must COPY the rust/ crate into the image"
    # A Rust toolchain (cargo/rustup) must be available so the extension builds.
    assert re.search(r"cargo|rustup|rust", dockerfile), (
        "the Dockerfile must install a Rust toolchain to compile the extension"
    )
