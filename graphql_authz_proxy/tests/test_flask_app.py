from unittest.mock import patch, Mock
import pytest
from flask import Flask
from graphql_authz_proxy.routes import flask_app
import json
from pathlib import Path
from graphql_authz_proxy.models import UsersConfig, GroupsConfig

def get_test_headers(user_email, github_username, access_token=None):
    headers = {
        'X-Forwarded-Email': user_email,
        'X-Forwarded-Preferred-Username': github_username,
    }
    if access_token:
        headers['X-Forwarded-Access-Token'] = access_token
    return headers

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    flask_app.config['users_config'] = UsersConfig.parse_config(Path(__file__).parent / 'authz_configs' / 'users.yaml')
    flask_app.config['groups_config'] = GroupsConfig.parse_config(Path(__file__).parent / 'authz_configs' / 'groups.yaml')
    flask_app.config['upstream_url'] = 'http://localhost:4000/'  # Example upstream

    with flask_app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def mock_requests_post():
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"data": {"result": "mocked"}}'
        mock_response.headers = {}
        mock_post.return_value = mock_response
        yield mock_post

def test_query_allowed(client):
    query = '{ __typename }'
    response = client.post('/graphql', json={'query': query}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code in (200, 502)  # 502 if upstream not running
    # If upstream is mocked, check for expected data


def test_mutation_denied(client):
    mutation = 'mutation { deletePipelineRun { id } }'
    response = client.post('/graphql', json={'query': mutation}, headers=get_test_headers('bob@company.com', 'bob-gh'))
    assert response.status_code == 403
    data = response.get_json()
    assert 'errors' in data
    assert data['errors'][0]['extensions']['code'] == 'FORBIDDEN'


def test_mutation_allowed(client):
    mutation = 'mutation { launchPipelineExecution { id } }'
    response = client.post('/graphql', json={'query': mutation}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    # Should be allowed for admin/data-engineers
    assert response.status_code in (200, 502)  # 502 if upstream not running
    # If upstream is mocked, check for expected data
