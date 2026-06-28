"""Tests covering the requirements for publishing the project to PyPI.

These assert that ``pyproject.toml`` carries PyPI-ready metadata and that a
GitHub Actions workflow is configured to publish the built distribution.
"""
import os
import tomllib

import graphql_authz_proxy


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


def test_build_system_is_defined() -> None:
    """A ``[build-system]`` table is required to build a distribution."""
    pyproject = _load_pyproject()
    assert "build-system" in pyproject, "pyproject.toml must define a [build-system] table"
    assert pyproject["build-system"].get("requires"), "[build-system] must list build requirements"
    assert pyproject["build-system"].get("build-backend"), "[build-system] must declare a build-backend"


def test_description_is_not_placeholder() -> None:
    """PyPI shows the project description, so the placeholder must be replaced."""
    project = _load_pyproject()["project"]
    description = project.get("description", "")
    assert description, "project.description must be set"
    assert description != "Add your description here", "project.description is still the placeholder"


def test_pypi_metadata_is_present() -> None:
    """PyPI listings need authors, a license, classifiers and project URLs."""
    project = _load_pyproject()["project"]
    assert project.get("authors"), "project.authors must be set"
    assert project.get("license"), "project.license must be set"
    assert project.get("classifiers"), "project.classifiers must be set"
    assert project.get("urls"), "project.urls must be set"


def test_distribution_version_matches_package_version() -> None:
    """The distribution version must match ``graphql_authz_proxy.__version__``."""
    version = _load_pyproject()["project"]["version"]
    assert hasattr(graphql_authz_proxy, "__version__"), "package must expose __version__"
    assert version == graphql_authz_proxy.__version__, (
        "pyproject version must match graphql_authz_proxy.__version__"
    )


def test_pypi_publish_workflow_exists() -> None:
    """A GitHub Actions workflow must publish to PyPI via the official action."""
    workflows_dir = os.path.join(_repo_root(), ".github", "workflows")
    contents = ""
    for name in os.listdir(workflows_dir):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(workflows_dir, name), encoding="utf-8") as handle:
                contents += handle.read()
    assert "pypa/gh-action-pypi-publish" in contents, (
        "a workflow must use pypa/gh-action-pypi-publish to publish to PyPI"
    )
