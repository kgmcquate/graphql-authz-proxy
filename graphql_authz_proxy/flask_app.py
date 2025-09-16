import sys
from flask import Flask, app, logging
from graphql_authz_proxy.models import UsersConfig, GroupsConfig
from graphql_authz_proxy.routes import register_routes


def get_flask_app(
    upstream_url: str,
    upstream_graphql_path: str,
    users_config: UsersConfig,
    groups_config: GroupsConfig,
    healthcheck_path: str,
    version: bool,
    debug: bool,
):

    flask_app = Flask(__name__)
    logger = logging.create_logger(flask_app)

    register_routes(flask_app, graphql_path=upstream_graphql_path, healthcheck_path=healthcheck_path)

    flask_app.config['users_config'] = users_config
    flask_app.config['groups_config'] = groups_config
    flask_app.config['upstream_url'] = upstream_url
    flask_app.config['upstream_graphql_path'] = upstream_graphql_path

    if version:
        sys.exit(0)
    
    return flask_app