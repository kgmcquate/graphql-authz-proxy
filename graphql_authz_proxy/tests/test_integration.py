import pytest
from testcontainers.postgres import PostgresContainer
from testcontainers.core.container import DockerContainer
from testcontainers.compose import DockerCompose
import requests
import time
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


def test_graphql_query(graphql_api_container):
    query = '{ __typename }'
    response = requests.post(
        f"{graphql_api_container}/v1/graphql",
        json={"query": query},
        headers={
            "X-Forwarded-Email": "test@example.com",
            "X-Forwarded-Preferred-Username": "testuser"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "data" in data


# def test_graphql_mutation(graphql_api_container):
#     # Hasura needs a table and permissions to allow mutations; this is a placeholder
#     mutation = 'mutation { insert_test_table_one(objects: {name: "foo"}) { returning { id name } } }'
#     response = requests.post(
#         f"{graphql_api_container}/v1/graphql",
#         json={"query": mutation},
#         headers={
#             "X-Forwarded-Email": "test@example.com",
#             "X-Forwarded-Preferred-Username": "testuser"
#         }
#     )
#     # Accept 200 (success) or 400 (no table/permission)
#     assert response.status_code in (200, 400)
#     data = response.json()
#     assert "data" in data or "errors" in data
