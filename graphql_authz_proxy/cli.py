import typer
import os
import sys
from flask import Flask, app, logging
from graphql_authz_proxy.models import UsersConfig, GroupsConfig

flask_app = Flask(__name__) 

logger = logging.create_logger(flask_app)
typer_app = typer.Typer()

@typer_app.command()
def start(
	upstream_url: str = typer.Option(..., help="Upstream URL to forward requests to"),
	users_config_file: str = typer.Option("users.yaml", help="Users config file name"),
	groups_config_file: str = typer.Option("groups.yaml", help="Groups config file name"),
	host: str = typer.Option("127.0.0.1", help="Host to run the Flask app on"),
	port: int = typer.Option(5000, help="Port to run the Flask app on"),
	debug: bool = typer.Option(False, help="Run Flask in debug mode"),
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit")
):
    flask_app.config['users_config'] = UsersConfig.parse_config(users_config_file)
    logger.info(f"Users config loaded from {users_config_file}: {len(flask_app.config['users_config'].users)} users")

    flask_app.config['groups_config'] = GroupsConfig.parse_config(groups_config_file)
    logger.info(f"Groups config loaded from {groups_config_file}: {len(flask_app.config['groups_config'].groups)} groups")

    flask_app.config['upstream_url'] = upstream_url

    if version:
        sys.exit(0)

    flask_app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
	app()

