

from graphql_authz_proxy.flask_app import get_flask_app
from graphql_authz_proxy.models import (
    ArgumentRule,
    FieldRule,
    Group,
    Groups,
    MutationPolicy,
    Permissions,
    PolicyEffect,
    QueryPolicy,
    User,
    Users,
)

from .fixtures import (
    get_test_headers,
    client,
    client2,
    users_config,
    groups_config,
    mock_requests_post
)


def test_unknown_user() -> None:
    users_config = Users(
        users=[],
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
                            FieldRule(field_name="*"),
                        ],
                    ),
                    queries=QueryPolicy(
                        effect=PolicyEffect.ALLOW,
                        fields=[
                            FieldRule(field_name="getUser"),
                        ],
                    ),
                ),
            ),
        ],
    )

    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
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
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
        assert resp.status_code == 403
        data = resp.get_json()
        assert "errors" in data
        assert data["errors"][0]["extensions"]["code"] == "FORBIDDEN"


def test_restricted_field_argument() -> None:
    users_config = Users(
        users=[
            User(
                username="test_user",
                email="test_user@gmail.com",
                groups=["viewers"],
            ),
        ],
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
                                        values=["Alice", "Bob"],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ),
            ),
        ],
    )

    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
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
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("test_user@gmail.com", "test_user"))

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
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("test_user@gmail.com", "test_user"))

        assert resp.status_code == 403
        data = resp.get_json()
        assert "errors" in data
        assert data["errors"][0]["extensions"]["code"] == "FORBIDDEN"


def test_user_with_multiple_groups() -> None:
    users_config = Users(
        users=[
            User(
                username="multi_group_user",
                email="multi@company.com",
                groups=["admin", "viewers"],
            ),
        ],
    )

    groups_config = Groups.parse_config_string(
        """
        groups:
          - name: admin
            description: Full administrative access
            permissions:
              mutations:
                effect: allow
                fields:
                  - field_name: "*"
              queries:
                effect: allow
                fields:
                  - field_name: "*"
          - name: viewers
            description: Read-only access
            permissions:
              mutations:
                effect: deny
                fields:
                  - field_name: "*"
              queries:
                effect: allow
                fields:
                  - field_name: "*"
        """,
    )

    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        # Should be allowed due to admin group
        mutation = "mutation { launchPipelineExecution { id } }"
        resp = client.post("/graphql", json={"query": mutation}, headers=get_test_headers("multi@company.com", "multi_group_user"))
        assert resp.status_code in (200, 502)
        # Should be allowed due to viewers group
        query = '{ getUser(name: "Ann") { id name } }'
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("multi@company.com", "multi_group_user"))
        assert resp.status_code in (200, 502)


def test_multi_group_nested_query() -> None:
    users_config = Users(
        users=[
            User(
                username="nested_user",
                email="nested@company.com",
                groups=["engineering", "viewers"],
            ),
        ],
    )

    groups_config = Groups.parse_config_string(
        """
groups:
  - name: engineering
    description: Dev team
    permissions:
      queries:
        effect: allow
        fields:
          - field_name: user
            arguments:
              - argument_name: name
                values:
                - Ann Berry
                fields:
                - field_name: profile
                  fields:
                  - field_name: address
                    fields:
                    - field_name: city
  - name: viewers
    description: Read-only
    permissions:
        queries:
          effect: allow
          fields:
            - field_name: user
          arguments:
            - argument_name: name
          values:
            - Ann
        """,
    )

    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        # Allowed: matches engineering group, 3-layer nested
        query = """
        query {
            user(name: "Ann Berry") {
            profile {
                address {
                city
                }
            }
            }
        }
        """
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("nested@company.com", "nested_user"))
        assert resp.status_code in (200, 502)

        # Denied: argument not allowed in either group
        query = """
        query {
            user(name: "Eve") {
            profile {
                address {
                city
                }
            }
            }
        }
        """
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("nested@company.com", "nested_user"))
        assert resp.status_code == 403
        data = resp.get_json()
        assert "errors" in data
        assert data["errors"][0]["extensions"]["code"] == "FORBIDDEN"


def test_dagster_request(client2) -> None:
    query = """query AssetsFreshnessInfoQuery($assetKeys: [AssetKeyInput!]!) {\n  assetNodes(assetKeys: $assetKeys) {\n    id\n    assetKey {\n      path\n      __typename\n    }\n    freshnessInfo {\n      ...AssetNodeLiveFreshnessInfoFragment\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment AssetNodeLiveFreshnessInfoFragment on AssetFreshnessInfo {\n  currentMinutesLate\n  __typename\n}"""

    response = client2.post("/", json={"query": query, "variables": {"assetKeys": [{"path": ["my_asset"]}]}}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
    assert response.status_code in (200, 502)
    data = response.get_json()
    assert "data" in data or "result" in data.get("data", {})


def test_variable_object_argument(client) -> None:
        query = """
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
        """
        variables = {
                "input": {
                        "name": "Ann",
                        "details": {
                                "age": 30,
                                "address": {
                                        "city": "NYC",
                                        "zip": "10001",
                                },
                        },
                },
        }

        response = client.post("/graphql", json={"query": query, "variables": variables}, headers=get_test_headers("kgmcquate@gmail.com", "kgmcquate"))
        assert response.status_code in (200, 502)
        data = response.get_json()
        assert "data" in data or "result" in data.get("data", {})


def test_restricted_field_argument() -> None:
    users_config = Users(
        users=[
            User(
                username="test_user",
                email="test_user@gmail.com",
                groups=["viewers"],
            ),
        ],
    )

    groups_config = Groups.parse_config_string(
        """
        groups:
          - name: viewers
            description: Read-only access
            permissions:
              queries:
                effect: allow
                fields:
                  - field_name: getUser
                    arguments:
                      - argument_name: name
                        values:
                          - Alice
                          - Bob
        """,
    )

    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
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
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("test_user@gmail.com", "test_user"))

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
        resp = client.post("/graphql", json={"query": query}, headers=get_test_headers("test_user@gmail.com", "test_user"))

        assert resp.status_code == 403
        data = resp.get_json()
        assert "errors" in data
        assert data["errors"][0]["extensions"]["code"] == "FORBIDDEN"


def test_allowed_object_argument(client) -> None:
    users_config = Users(
        users=[
            User(
                username="test_user",
                email="test_user@gmail.com",
                groups=["engineers"],
            ),
        ],
    )

    groups_yaml = """
    groups:
    - name: engineers
      permissions:
          mutations:
              effect: allow
              fields:
              - field_name: launchPipelineExecution
                arguments:
                  - argument_name: executionParams
                    values:
                    - selector:
                        repositoryLocationName: k8s-example-user-code-1
    """
    groups_config = Groups.parse_config_string(groups_yaml)

    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        variables = {
            "executionParams": {
                "mode": "default",
                "executionMetadata": {
                "tags": [
                    {
                    "key": "dagster/from_ui",
                    "value": "true",
                    },
                ],
                },
                "runConfigData": "{}",
                "selector": {
                    "repositoryLocationName": "k8s-example-user-code-1",
                    "repositoryName": "__repository__",
                    "pipelineName": "__ASSET_JOB",
                    "assetSelection": [
                        {
                        "path": [
                            "iris_dataset_size",
                        ],
                        },
                    ],
                    "assetCheckSelection": [],
                },
            },
        }

        query = """
        mutation LaunchPipelineExecution($executionParams: ExecutionParams!) {
            launchPipelineExecution(executionParams: $executionParams)
        }"""

        response = client.post("/graphql", json={"query": query, "variables": variables}, headers=get_test_headers("test_user@gmail.com", "test_user"))
        assert response.status_code in (200, 502)
        data = response.get_json()
        assert "data" in data or "result" in data.get("data", {})


def test_allow_for_denied_object_argument(client) -> None:
    users_config = Users(
        users=[
            User(
                username="test_user",
                email="test_user@gmail.com",
                groups=["engineers"],
            ),
        ],
    )

    groups_config = Groups.parse_config_string(
        """
        groups:
          - name: engineers
            permissions:
              mutations:
                effect: allow
                fields:
                  - field_name: launchPipelineExecution
                    arguments:
                      - argument_name: executionParams
                        values:
                          - selector:
                              repositoryName: not_real_repo
        """,
    )


    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        variables = {
            "executionParams": {
                "mode": "default",
                "executionMetadata": {
                "tags": [
                    {
                    "key": "dagster/from_ui",
                    "value": "true",
                    },
                ],
                },
                "runConfigData": "{}",
                "selector": {
                    "repositoryLocationName": "k8s-example-user-code-1",
                    "repositoryName": "__repository__",
                    "pipelineName": "__ASSET_JOB",
                    "assetSelection": [
                        {
                        "path": [
                            "iris_dataset_size",
                        ],
                        },
                    ],
                    "assetCheckSelection": [],
                },
            },
        }

        query = """
        mutation LaunchPipelineExecution($executionParams: ExecutionParams!) {
            launchPipelineExecution(executionParams: $executionParams)
        }"""

        response = client.post("/graphql", json={"query": query, "variables": variables}, headers=get_test_headers("test_user@gmail.com", "test_user"))
        assert response.status_code == 403



def test_deny_for_denied_object_argument(client) -> None:
    users_config = Users(
        users=[
            User(
                username="test_user",
                email="test_user@gmail.com",
                groups=["engineers"],
            ),
        ],
    )

    groups_config = Groups.parse_config_string(
        """
        groups:
          - name: engineers
            permissions:
              mutations:
                effect: deny
                fields:
                  - field_name: launchPipelineExecution
                    arguments:
                      - argument_name: executionParams
                        values:
                          - selector:
                              repositoryName: __repository__
                              repositoryLocationName: not_real_location
        """,
    )


    flask_app = get_flask_app(
        upstream_url="http://localhost:4000/",
        upstream_graphql_path="/graphql",
        users_config=users_config,
        groups_config=groups_config,
    )
    with flask_app.test_client() as client:
        variables = {
            "executionParams": {
                "mode": "default",
                "executionMetadata": {
                "tags": [
                    {
                    "key": "dagster/from_ui",
                    "value": "true",
                    },
                ],
                },
                "runConfigData": "{}",
                "selector": {
                    "repositoryLocationName": "k8s-example-user-code-1",
                    "repositoryName": "__repository__",
                    "pipelineName": "__ASSET_JOB",
                    "assetSelection": [
                        {
                        "path": [
                            "iris_dataset_size",
                        ],
                        },
                    ],
                    "assetCheckSelection": [],
                },
            },
        }

        query = """
        mutation LaunchPipelineExecution($executionParams: ExecutionParams!) {
            launchPipelineExecution(executionParams: $executionParams)
        }"""

        response = client.post("/graphql", json={"query": query, "variables": variables}, headers=get_test_headers("test_user@gmail.com", "test_user"))
        assert response.status_code == 403