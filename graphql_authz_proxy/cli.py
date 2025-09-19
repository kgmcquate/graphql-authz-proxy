"""Entry point for the GraphQL Authz Proxy CLI using Typer."""
import logging

import typer

from graphql_authz_proxy.flask_app import get_flask_app
from graphql_authz_proxy.gunicorn_runner import run_with_gunicorn
from graphql_authz_proxy.models import Groups, Users

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

typer_app = typer.Typer()


@typer_app.command()
def start(  # noqa: PLR0913
    upstream_url: str = typer.Option(..., help="Upstream URL to forward requests to", envvar="UPSTREAM_URL"),
    upstream_graphql_path: str = \
        typer.Option(
            "/graphql",
            help="Path to the GraphQL endpoint on the upstream server",
            envvar="UPSTREAM_GRAPHQL_PATH"
        ),
    users_config_file: str = \
        typer.Option("users.yaml", help="Users config file name", envvar="USERS_CONFIG_FILE"),
    groups_config_file: str = \
        typer.Option("groups.yaml", help="Groups config file name", envvar="GROUPS_CONFIG_FILE"),
    enable_config_jinja: bool = \
        typer.Option(False, help="Enable Jinja templating in config files", envvar="ENABLE_CONFIG_JINJA"),
    validate_token: bool = \
        typer.Option(False, help="Enable token validation with the identity provider", envvar="VALIDATE_TOKEN"),
    idp: str = \
        typer.Option("github", help="Identity provider for token validation (github, azure, custom)", envvar="IDP"),
    host: str = \
        typer.Option("127.0.0.1", help="Host to run the Flask app on", envvar="HOST"),
    port: int = \
        typer.Option(5000, help="Port to run the Flask app on", envvar="PORT"),
    workers: int = \
        typer.Option(2, help="Number of Gunicorn workers to use", envvar="WORKERS"),
    healthcheck_path: str = \
        typer.Option("/gqlproxy/health", help="Path for health check endpoint", envvar="HEALTHCHECK_PATH"),
    debug: bool = \
        typer.Option(False, help="Run Flask in debug mode", envvar="DEBUG"),
    version: bool = \
        typer.Option(False, "--version", "-v", help="Show version and exit", envvar="VERSION"),
) -> None:
    """Start the GraphQL Authz Proxy server using Gunicorn.
    Loads user and group configs, sets up Flask app, and runs with Gunicorn.

    Args:
        upstream_url (str): Upstream server URL.
        upstream_graphql_path (str): Path to upstream GraphQL endpoint.
        users_config_file (str): Path to users config YAML file.
        groups_config_file (str): Path to groups config YAML file.
        enable_config_jinja (bool): Enable Jinja templating in config files.
        validate_token (bool): Enable token validation.
        idp (str): Identity provider name.
        host (str): Host to bind server.
        port (int): Port to bind server.
        workers (int): Number of Gunicorn workers.
        healthcheck_path (str): Health check endpoint path.
        debug (bool): Enable Flask debug mode.
        version (bool): Show version and exit.

    """
    users_config = Users.parse_config(users_config_file)
    logger.info(f"Users config loaded from {users_config_file}: {len(users_config.users)} users")

    groups_config = Groups.parse_config(groups_config_file)
    logger.info(f"Groups config loaded from {groups_config_file}: {len(groups_config.groups)} groups")

    flask_app = get_flask_app(
        upstream_url=upstream_url,
        upstream_graphql_path=upstream_graphql_path,
        users_config=users_config,
        groups_config=groups_config,
        enable_config_jinja=enable_config_jinja,
        healthcheck_path=healthcheck_path,
        debug=debug,
        version=version,
        validate_token=validate_token,
        idp=idp,
    )

    run_with_gunicorn(flask_app, host=host, port=port, workers=workers)


if __name__ == "__main__":
    typer_app()
