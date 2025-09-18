import pytest
from graphql_authz_proxy.flask_app import get_flask_app
from graphql_authz_proxy.models import Users, User, Groups, Group, Permissions, PolicyEffect, MutationPolicy, QueryPolicy, FieldRule
from testcontainers.compose import DockerCompose
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)

@pytest.fixture(scope="module")
def graphql_api_container():
    with DockerCompose(
        Path(__file__).parent,
        compose_file_name="docker-compose.yml",
    ) as compose:
        host = compose.get_service_host("graphql-engine", 8080)
        yield f"http://{host}:8080"


@pytest.fixture
def client_for_graphql_engine(graphql_api_container):
    flask_app = get_flask_app(
        upstream_url=graphql_api_container,
        upstream_graphql_path='/v1/graphql',
        users_config=Users(
            users=[
                User(
                    username="adminuser",
                    email="adminuser@example.com",
                    groups=["admin"]
                ),
                User(
                    username="vieweruser",
                    email="vieweruser@example.com",
                    groups=["viewer"]
                )
            ]
        ),
        groups_config=Groups(
            groups=[
                Group(
                    name="admin",
                    permissions=Permissions(
                        queries=QueryPolicy(
                            effect=PolicyEffect.ALLOW,
                            fields=[
                                FieldRule(
                                    field_name="*"
                                )
                            ]
                        ),
                        mutations=MutationPolicy(
                            effect=PolicyEffect.ALLOW,
                            fields=[
                            FieldRule(
                                field_name="*"
                            )
                        ]
                    )
                )
                ),
                Group(
                    name="viewer",
                    permissions=Permissions(
                        queries=QueryPolicy(
                            effect=PolicyEffect.ALLOW,
                            fields=[
                                FieldRule(
                                    field_name="GetUserData"
                                )
                            ]
                        ),
                    )
                )
            ]
        ),
        healthcheck_path='/health',
        version=False,
        debug=False,
    )

    with flask_app.test_client() as client:
        yield client


def test_graphql_query(graphql_api_container, client_for_graphql_engine):
    query = '{ __typename }'
    response = client_for_graphql_engine.post(
        f"{graphql_api_container}/v1/graphql",
        json={"query": query},
        headers={
            "X-Forwarded-Email": "adminuser@example.com",
            "X-Forwarded-Preferred-Username": "adminuser"
        }
    )

    assert response.status_code == 200
    data = response.get_json()
    assert "data" in data


def test_graphql_mutation(graphql_api_container, client_for_graphql_engine):
    # Hasura needs a table and permissions to allow mutations; this is a placeholder
    mutation = 'mutation { insert_test_table_one(objects: {name: "foo"}) { returning { id name } } }'
    response = client_for_graphql_engine.post(
        f"{graphql_api_container}/v1/graphql",
        json={"query": mutation},
        headers={
            "X-Forwarded-Email": "adminuser@example.com",
            "X-Forwarded-Preferred-Username": "adminuser"
        }
    )
    assert response.status_code == 200 #in (200, 400)
    data = response.get_json()
    assert "errors" in data
    assert data["errors"][0]["message"] == "no mutations exist"


def test_mutation_denied_for_viewer(graphql_api_container, client_for_graphql_engine):
    query = 'mutation { insert_test_table_one(objects: {name: "foo"}) { returning { id name } } }'
    response = client_for_graphql_engine.post(
        f"{graphql_api_container}/v1/graphql",
        json={"query": query},
        headers={
            "X-Forwarded-Email": "vieweruser@example.com",
            "X-Forwarded-Preferred-Username": "vieweruser"
        }
    )
    assert response.status_code == 403
    data = response.get_json()
    assert "errors" in data
    assert data["errors"][0]["message"].startswith("Access denied")


def test_query_denied_for_viewer(graphql_api_container, client_for_graphql_engine):
    query = 'query { test_table { id name } }'
    response = client_for_graphql_engine.post(
        f"{graphql_api_container}/v1/graphql",
        json={"query": query},
        headers={
            "X-Forwarded-Email": "vieweruser@example.com",
            "X-Forwarded-Preferred-Username": "vieweruser"
        }
    )
    assert response.status_code == 403
    data = response.get_json()
    assert "errors" in data
    assert data["errors"][0]["message"].startswith("Access denied")


# def test_query_allowed_for_viewer(graphql_api_container, client_for_graphql_engine):
#     query = 'query GetUserData { id name }'
#     response = client_for_graphql_engine.post(
#         f"{graphql_api_container}/v1/graphql",
#         json={"query": query},
#         headers={
#             "X-Forwarded-Email": "vieweruser@example.com",
#             "X-Forwarded-Preferred-Username": "vieweruser"
#         }
#     )
#     assert response.status_code == 200
    # data = response.get_json()
    # assert "errors" in data
    # assert data["errors"][0]["message"].startswith("Access denied")
