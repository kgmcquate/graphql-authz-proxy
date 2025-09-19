from unittest.mock import Mock, patch

from .fixtures import (
    get_test_headers,
    client,
    client2,
    users_config,
    groups_config,
    mock_requests_post
)


def test_health_endpoint(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert "authorization" in data
    assert "groups_configured" in data["authorization"]

def test_query_allowed(client) -> None:
    query = "{ __typename }"
    response = client.post("/graphql", json={"query": query}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code == 200
    data = response.get_json()
    assert "data" in data or "result" in data.get("data", {})


def test_mutation_denied(client) -> None:
    mutation = "mutation { deletePipelineRun { id } }"
    response = client.post("/graphql", json={"query": mutation}, headers=get_test_headers("bob@company.com", "bob-gh"))
    assert response.status_code == 403
    data = response.get_json()
    assert "errors" in data
    assert data["errors"][0]["extensions"]["code"] == "FORBIDDEN"


def test_mutation_allowed(client) -> None:
    mutation = "mutation { launchPipelineExecution { id } }"
    response = client.post("/graphql", json={"query": mutation}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code in (200, 502)
    data = response.get_json()
    assert "data" in data or "result" in data.get("data", {})


def test_graphql_path_variation(client2) -> None:
    query = "{ __typename }"
    response = client2.post("/", json={"query": query}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code == 200

# Proxy logic
def test_proxy_arbitrary_route(client) -> None:
    response = client.get("/foo/bar", headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code in (200, 502)

def test_proxy_upstream_error(client) -> None:
    with patch("requests.request") as mock_request:
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.content = b""
        mock_response.headers = {}
        mock_request.return_value = mock_response
        response = client.get("/foo/bar", headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
        assert response.status_code == 500

# Header handling
def test_missing_headers(client) -> None:
    query = "{ __typename }"
    response = client.post("/graphql", json={"query": query})
    assert response.status_code == 403

# Edge cases
def test_empty_body(client) -> None:
    response = client.post("/graphql", data="", headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code in (400, 403, 500)

def test_malformed_query(client) -> None:
    response = client.post("/graphql", json={"query": "not a valid graphql"}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code == 500

def test_large_payload(client) -> None:
    large_query = "{" + "a" * 10000 + "}"
    response = client.post("/graphql", json={"query": large_query}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code in (200, 502, 400, 413)

