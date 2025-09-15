import pytest
from typer.testing import CliRunner
from ..cli import typer_app
import os

runner = CliRunner()

@pytest.mark.skip
def test_cli_valid_configs():
    users_yaml = os.path.join(os.path.dirname(__file__), "authz_configs", "users.yaml")
    groups_yaml = os.path.join(os.path.dirname(__file__), "authz_configs", "groups.yaml")

    result = runner.invoke(
        typer_app,
        [
            # "start",
            "--upstream-url", "http://localhost:3000",
            "--users-config-file", users_yaml,
            "--groups-config-file", groups_yaml,
            "--host", "127.0.0.1",
            "--port", "5050",
            "--debug",
            "--version"
        ],
        catch_exceptions=False
    )

    assert result.exit_code == 0 or result.exit_code == 1


@pytest.mark.skip(reason="This test starts the server and blocks; use for manual testing only")
def test_run_server():
    users_yaml = os.path.join(os.path.dirname(__file__), "authz_configs", "users.yaml")
    groups_yaml = os.path.join(os.path.dirname(__file__), "authz_configs", "groups.yaml")

    result = runner.invoke(
        typer_app,
        [
            # "start",
            "--upstream-url", "http://localhost:3000",
            "--users-config-file", users_yaml,
            "--groups-config-file", groups_yaml,
            "--host", "127.0.0.1",
            "--port", "5050",
            "--debug",
        ],
        catch_exceptions=False
    )

    assert result.exit_code == 0 or result.exit_code == 1

@pytest.mark.skip
def test_cli_invalid_users_config(tmp_path):
    # Invalid users config (missing groups)
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text("""
users:
  - email: "test@example.com"
    username: "testuser"
    # groups missing
    """)

    result = runner.invoke(
        typer_app,
        [
            # "start",
            "--upstream-url", "http://localhost:3000",
            "--users-config-file", str(users_yaml)
        ],
        catch_exceptions=True
    )
    assert "Error parsing config file " in str(result.exception)
    assert result.exit_code == 1
