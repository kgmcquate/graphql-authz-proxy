from unittest.mock import patch, Mock
import pytest
from graphql_authz_proxy.flask_app import get_flask_app
from pathlib import Path
from graphql_authz_proxy.models import FieldRule, Group, MutationPolicy, Permissions, PolicyEffect, QueryPolicy, User, Users, Groups, ArgumentRule

def get_test_headers(user_email, github_username, access_token=None):
    headers = {
        'X-Forwarded-Email': user_email,
        'X-Forwarded-Preferred-Username': github_username,
    }
    if access_token:
        headers['X-Forwarded-Access-Token'] = access_token
    return headers


@pytest.fixture
def users_config():
    config_path = Path(__file__).parent / 'authz_configs' / 'users.yaml'
    return Users.parse_config(str(config_path))

@pytest.fixture
def groups_config():
    config_path = Path(__file__).parent / 'authz_configs' / 'groups.yaml'
    return Groups.parse_config(str(config_path))

@pytest.fixture
def client(users_config, groups_config):
    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/graphql',
        users_config=users_config,
        groups_config=groups_config,
        healthcheck_path='/health',
        version=False,
        debug=False,
    )

    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def client2(users_config, groups_config):
    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/',
        users_config=users_config,
        groups_config=groups_config,
        healthcheck_path='/health',
        version=False,
        debug=False,
    )

    with flask_app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def mock_requests_post():
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"data": {"result": "mocked"}}'
        mock_response.headers = {"Content-Type": "application/json"}
        mock_post.return_value = mock_response
        yield mock_post


def test_health_endpoint(client):
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert 'authorization' in data
    assert 'groups_configured' in data['authorization']

def test_query_allowed(client):
    query = '{ __typename }'
    response = client.post('/graphql', json={'query': query}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data or 'result' in data.get('data', {})


def test_mutation_denied(client):
    mutation = 'mutation { deletePipelineRun { id } }'
    response = client.post('/graphql', json={'query': mutation}, headers=get_test_headers('bob@company.com', 'bob-gh'))
    print(response.get_json())
    assert response.status_code == 403
    data = response.get_json()
    assert 'errors' in data
    assert data['errors'][0]['extensions']['code'] == 'FORBIDDEN'


def test_mutation_allowed(client):
    mutation = 'mutation { launchPipelineExecution { id } }'
    response = client.post('/graphql', json={'query': mutation}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code in (200, 502)
    data = response.get_json()
    assert 'data' in data or 'result' in data.get('data', {})


def test_graphql_path_variation(client2):
    query = '{ __typename }'
    response = client2.post('/', json={'query': query}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code == 200

# Proxy logic
def test_proxy_arbitrary_route(client):
    response = client.get('/foo/bar', headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code in (200, 502)

def test_proxy_upstream_error(client):
    with patch('requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.content = b''
        mock_response.headers = {}
        mock_request.return_value = mock_response
        response = client.get('/foo/bar', headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
        assert response.status_code == 500

# Header handling
def test_missing_headers(client):
    query = '{ __typename }'
    response = client.post('/graphql', json={'query': query})
    assert response.status_code == 403

# Edge cases
def test_empty_body(client):
    response = client.post('/graphql', data='', headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code in (400, 403, 500)

def test_malformed_query(client):
    response = client.post('/graphql', json={'query': 'not a valid graphql'}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code == 500

def test_large_payload(client):
    large_query = '{' + 'a' * 10000 + '}'
    response = client.post('/graphql', json={'query': large_query}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code in (200, 502, 400, 413)


def test_unknown_user():
    users_config = Users(
        users=[]
    )

    groups_config = Groups(
        groups=[
            Group(
                name="viewers",
                description="Read-only access",
                permissions=Permissions(
                    mutations=MutationPolicy(
                        effect=PolicyEffect.DENY,
                        fields=[
                            FieldRule(name="*")
                        ]
                    ),
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[
                            FieldRule(name="getUser")
                        ]
                    )
                )
            )
        ]
    )

    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/graphql',
        users_config=users_config,
        groups_config=groups_config,
        healthcheck_path='/health',
        version=False,
        debug=False,
    )

    with flask_app.test_client() as client:
        query = """
        query {
          getUser(name: "Ann") {
            id
            name
          }
        }
        """
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
        assert resp.status_code == 403
        data = resp.get_json()
        assert 'errors' in data
        assert data['errors'][0]['extensions']['code'] == 'FORBIDDEN'


def test_unknown_user():
    users_config = Users(
        users=[]
    )

    groups_config = Groups(
        groups=[
            Group(
                name="viewers",
                description="Read-only access",
                permissions=Permissions(
                    mutations=MutationPolicy(
                        effect=PolicyEffect.DENY,
                        fields=[
                            FieldRule(field_name="*")
                        ]
                    ),
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[
                            FieldRule(field_name="getUser")
                        ]
                    )
                )
            )
        ]
    )

    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/graphql',
        users_config=users_config,
        groups_config=groups_config
    )

    with flask_app.test_client() as client:
        query = """
        query {
          getUser(name: "Ann") {
            id
            name
          }
        }
        """
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
        assert resp.status_code == 403
        data = resp.get_json()
        assert 'errors' in data
        assert data['errors'][0]['extensions']['code'] == 'FORBIDDEN'


def test_restricted_field_argument():
    users_config = Users(
        users=[
            User(
                username="test_user",
                email="test_user@gmail.com",
                groups=["viewers"]
            )
        ]
    )

    groups_config = Groups(
        groups=[
            Group(
                name="viewers",
                description="Read-only access",
                permissions=Permissions(
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[
                            FieldRule(
                                field_name="getUser",
                                arguments=[
                                    ArgumentRule(
                                        argument_name="name",
                                        values=["Alice", "Bob"]
                                    )
                                ]
                            )
                        ]
                    )
                )
            )
        ]
    )

    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/graphql',
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        # Allowed argument value
        query = """
        query {
          getUser(name: "Alice") {
            id
            name
          }
        }
        """
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('test_user@gmail.com', 'test_user'))

        assert resp.status_code in (200, 502)

        # Disallowed argument value
        query = """
        query {
          getUser(name: "Eve") {
            id
            name
          }
        }
        """
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('test_user@gmail.com', 'test_user'))

        assert resp.status_code == 403
        data = resp.get_json()
        assert 'errors' in data
        assert data['errors'][0]['extensions']['code'] == 'FORBIDDEN'


def test_user_with_multiple_groups():
    users_config = Users(
        users=[
            User(
                username="multi_group_user",
                email="multi@company.com",
                groups=["admin", "viewers"]
            )
        ]
    )

    groups_config = Groups(
        groups=[
            Group(
                name="admin",
                description="Full administrative access",
                permissions=Permissions(
                    mutations=MutationPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[FieldRule(field_name="*")]
                    ),
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[FieldRule(field_name="*")]
                    )
                )
            ),
            Group(
                name="viewers",
                description="Read-only access",
                permissions=Permissions(
                    mutations=MutationPolicy(
                        effect=PolicyEffect.DENY,
                        fields=[FieldRule(field_name="*")]
                    ),
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[FieldRule(field_name="getUser")]
                    )
                )
            )
        ]
    )

    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/graphql',
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        # Should be allowed due to admin group
        mutation = 'mutation { launchPipelineExecution { id } }'
        resp = client.post('/graphql', json={'query': mutation}, headers=get_test_headers('multi@company.com', 'multi_group_user'))
        assert resp.status_code in (200, 502)
        # Should be allowed due to viewers group
        query = '{ getUser(name: "Ann") { id name } }'
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('multi@company.com', 'multi_group_user'))
        assert resp.status_code in (200, 502)


def test_multi_group_nested_query():
    users_config = Users(
        users=[
            User(
                username="nested_user",
                email="nested@company.com",
                groups=["engineering", "viewers"]
            )
        ]
    )

    groups_config = Groups(
        groups=[
            Group(
                name="engineering",
                description="Dev team",
                permissions=Permissions(
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[
                            FieldRule(
                                field_name="user",
                                arguments=[
                                    ArgumentRule(argument_name="name", values=["Ann Berry"])
                                ],
                                fields=[
                                    FieldRule(field_name="profile", fields=[
                                        FieldRule(field_name="address", fields=[
                                            FieldRule(field_name="city")
                                        ])
                                    ])
                                ]
                            )
                        ]
                    )
                )
            ),
            Group(
                name="viewers",
                description="Read-only",
                permissions=Permissions(
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[
                            FieldRule(
                                field_name="user",
                                arguments=[
                                    ArgumentRule(argument_name="name", values=["Ann"])
                                ]
                            )
                        ]
                    )
                )
            )
        ]
    )

    flask_app = get_flask_app(
        upstream_url='http://localhost:4000/',
        upstream_graphql_path='/graphql',
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        # Allowed: matches engineering group, 3-layer nested
        query = '''
        query {
            user(name: "Ann Berry") {
            profile {
                address {
                city
                }
            }
            }
        }
        '''
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('nested@company.com', 'nested_user'))
        assert resp.status_code in (200, 502)

        # Denied: argument not allowed in either group
        query = '''
        query {
            user(name: "Eve") {
            profile {
                address {
                city
                }
            }
            }
        }
        '''
        resp = client.post('/graphql', json={'query': query}, headers=get_test_headers('nested@company.com', 'nested_user'))
        assert resp.status_code == 403
        data = resp.get_json()
        assert 'errors' in data
        assert data['errors'][0]['extensions']['code'] == 'FORBIDDEN'


def test_dagster_request(client2):
    query = """query AssetsFreshnessInfoQuery($assetKeys: [AssetKeyInput!]!) {\n  assetNodes(assetKeys: $assetKeys) {\n    id\n    assetKey {\n      path\n      __typename\n    }\n    freshnessInfo {\n      ...AssetNodeLiveFreshnessInfoFragment\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment AssetNodeLiveFreshnessInfoFragment on AssetFreshnessInfo {\n  currentMinutesLate\n  __typename\n}"""

    response = client2.post('/', json={'query': query, 'variables': {'assetKeys': [{'path': ['my_asset']}]}}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
    assert response.status_code in (200, 502)
    data = response.get_json()
    assert 'data' in data or 'result' in data.get('data', {})


def test_variable_object_argument(client):
        query = '''
        query GetUser($input: UserInput!) {
            getUser(input: $input) {
                id
                name
                details {
                    age
                    address {
                        city
                        zip
                    }
                }
            }
        }
        '''
        variables = {
                "input": {
                        "name": "Ann",
                        "details": {
                                "age": 30,
                                "address": {
                                        "city": "NYC",
                                        "zip": "10001"
                                }
                        }
                }
        }
        
        response = client.post('/graphql', json={'query': query, 'variables': variables}, headers=get_test_headers('kgmcquate@gmail.com', 'kgmcquate'))
        assert response.status_code in (200, 502)
        data = response.get_json()
        assert 'data' in data or 'result' in data.get('data', {})

