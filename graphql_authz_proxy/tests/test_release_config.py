"""Tests for the release, versioning and tagging configuration.

These tests guard the project's automated release setup (semantic versioning,
git tags and GitHub releases via python-semantic-release). They assert that the
version is exposed by the package, kept consistent across files, and that the
release automation is wired up with a non-broken, modern configuration.
"""

import os
import re

import tomllib

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")
INIT_FILE = os.path.join(REPO_ROOT, "graphql_authz_proxy", "__init__.py")
RELEASE_WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "release.yml")
CHANGELOG = os.path.join(REPO_ROOT, "CHANGELOG.md")
LEGACY_CONFIG = os.path.join(REPO_ROOT, ".python-semantic-release")

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _load_pyproject() -> dict:
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def _load_workflow() -> dict:
    with open(RELEASE_WORKFLOW) as fh:
        return yaml.safe_load(fh)


def _workflow_triggers(workflow: dict) -> dict:
    # PyYAML parses the bare ``on:`` key as the boolean ``True`` (YAML 1.1).
    return workflow.get("on", workflow.get(True, {}))


def test_package_exposes_version() -> None:
    import graphql_authz_proxy

    assert hasattr(graphql_authz_proxy, "__version__")
    assert SEMVER_RE.match(graphql_authz_proxy.__version__)


def test_version_matches_pyproject() -> None:
    import graphql_authz_proxy

    data = _load_pyproject()
    assert graphql_authz_proxy.__version__ == data["project"]["version"]


def test_init_declares_version_variable() -> None:
    # semantic-release rewrites this assignment by string substitution, so the
    # literal ``__version__ = "x.y.z"`` form must be present.
    with open(INIT_FILE) as fh:
        contents = fh.read()
    assert re.search(r'^__version__\s*=\s*["\']\d+\.\d+\.\d+["\']', contents, re.M)


def test_semantic_release_configured_in_pyproject() -> None:
    data = _load_pyproject()
    sr = data.get("tool", {}).get("semantic_release")
    assert sr is not None, "[tool.semantic_release] must be configured in pyproject.toml"
    version_variables = sr.get("version_variables", [])
    assert any(
        "graphql_authz_proxy/__init__.py:__version__" in v for v in version_variables
    ), "semantic-release must track __version__ in the package __init__"


def test_semantic_release_build_command_has_no_setup_py() -> None:
    # The project has no setup.py; the build command must not reference it.
    data = _load_pyproject()
    sr = data["tool"]["semantic_release"]
    build_command = sr.get("build_command", "")
    assert "setup.py" not in build_command


def test_legacy_semantic_release_config_removed() -> None:
    # Configuration lives in pyproject.toml now; the legacy v7 file is gone.
    assert not os.path.exists(LEGACY_CONFIG)


def test_release_workflow_is_valid_yaml() -> None:
    workflow = _load_workflow()
    assert isinstance(workflow, dict)
    assert "jobs" in workflow


def test_release_workflow_triggers_on_main_and_dispatch() -> None:
    triggers = _workflow_triggers(_load_workflow())
    assert "workflow_dispatch" in triggers
    push = triggers.get("push", {})
    assert "main" in push.get("branches", [])


def test_release_workflow_runs_semantic_release() -> None:
    text = _read_workflow_text()
    assert "semantic-release" in text
    # The project has no setup.py, so the release pipeline must never call it.
    assert "setup.py" not in text


def _read_workflow_text() -> str:
    with open(RELEASE_WORKFLOW) as fh:
        return fh.read()


def test_changelog_exists() -> None:
    assert os.path.exists(CHANGELOG)
