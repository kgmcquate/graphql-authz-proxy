"""Get the Flask app instance with configured routes and settings."""

import sys

from flask import Flask, logging

from graphql_authz_proxy.models import Groups, Users
from graphql_authz_proxy.routes import register_routes


def get_flask_app(  # noqa: PLR0913
    upstream_url: str,
    upstream_graphql_path: str,
    users_config: Users,
    groups_config: Groups,
    enable_config_jinja: bool = False,
    healthcheck_path: str = "/health",
    version: bool = False,
    validate_token: bool = False,
    idp: str = "github",
    debug: bool = False,  # noqa: ARG001
) -> Flask:
    """Create and configure the Flask app instance."""
    flask_app = Flask(__name__)
    logging.create_logger(flask_app)

    register_routes(flask_app, graphql_path=upstream_graphql_path, healthcheck_path=healthcheck_path)

    flask_app.config["users_config"] = users_config
    flask_app.config["groups_config"] = groups_config
    flask_app.config["upstream_url"] = upstream_url
    flask_app.config["upstream_graphql_path"] = upstream_graphql_path
    flask_app.config["enable_config_jinja"] = enable_config_jinja
    flask_app.config["validate_token"] = validate_token
    flask_app.config["idp"] = idp

    if version:
        sys.exit(0)
    
    return flask_app
