from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from graphql_authz_proxy.flask_app import get_flask_app
from graphql_authz_proxy.models import Groups, Users


def get_test_headers(user_email, github_username, access_token=None):
    headers = {
        "X-Forwarded-Email": user_email,
        "X-Forwarded-Preferred-Username": github_username,
    }
    if access_token:
        headers["X-Forwarded-Access-Token"] = access_token
    return headers


@pytest.fixture
def users_config():
    config_path = Path(__file__).parent / "authz_configs" / "users.yaml"
    return Users.parse_config(str(config_path))

@pytest.fixture
def groups_config():
    config_path = Path(__file__).parent / "authz_configs" / "groups.yaml"
    return Groups.parse_config(str(config_path))

@pytest.fixture
def client(users_config, groups_config):
    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
        healthcheck_path="/health",
        version=False,
        debug=False,
    )

    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def client2(users_config, groups_config):
    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/",
        users_config=users_config,
        groups_config=groups_config,
        healthcheck_path="/health",
        version=False,
        debug=False,
    )

    with flask_app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def mock_requests_post():
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"data": {"result": "mocked"}}'
        mock_response.headers = {"Content-Type": "application/json"}
        mock_post.return_value = mock_response
        yield mock_post