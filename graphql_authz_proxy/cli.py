import typer
from graphql_authz_proxy.gunicorn_runner import run_with_gunicorn
from graphql_authz_proxy.flask_app import get_flask_app
from graphql_authz_proxy.models import UsersConfig, GroupsConfig
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

typer_app = typer.Typer()


@typer_app.command()
def start(
    upstream_url: str = typer.Option(..., help="Upstream URL to forward requests to", envvar="UPSTREAM_URL"),
    upstream_graphql_path: str = typer.Option("/graphql", help="Path to the GraphQL endpoint on the upstream server", envvar="UPSTREAM_GRAPHQL_PATH"),
    users_config_file: str = typer.Option("users.yaml", help="Users config file name", envvar="USERS_CONFIG_FILE"),
    groups_config_file: str = typer.Option("groups.yaml", help="Groups config file name", envvar="GROUPS_CONFIG_FILE"),
    host: str = typer.Option("127.0.0.1", help="Host to run the Flask app on", envvar="HOST"),
    port: int = typer.Option(5000, help="Port to run the Flask app on", envvar="PORT"),
    workers: int = typer.Option(2, help="Number of Gunicorn workers to use", envvar="WORKERS"),
    healthcheck_path: str = typer.Option("/gqlproxy/health", help="Path for health check endpoint", envvar="HEALTHCHECK_PATH"),
    debug: bool = typer.Option(False, help="Run Flask in debug mode", envvar="DEBUG"),
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit", envvar="VERSION"),
):
    users_config = UsersConfig.parse_config(users_config_file)
    logger.info(f"Users config loaded from {users_config_file}: {len(users_config.users)} users")

    groups_config = GroupsConfig.parse_config(groups_config_file)
    logger.info(f"Groups config loaded from {groups_config_file}: {len(groups_config.groups)} groups")

    flask_app = get_flask_app(
        upstream_url=upstream_url,
        upstream_graphql_path=upstream_graphql_path,
        users_config=users_config,
        groups_config=groups_config,
        healthcheck_path=healthcheck_path,
        debug=debug,
        version=version
    )

    run_with_gunicorn(flask_app, host=host, port=port, workers=workers)


if __name__ == "__main__":
    typer_app()
