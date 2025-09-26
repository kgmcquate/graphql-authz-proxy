from graphql import parse
from graphql_authz_proxy.flask_app import get_flask_app
from pathlib import Path
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

recent_asset_events_variables = {
  "assetKey": {
    "path": [
      "monthly_revenue_report"
    ]
  },
  "limit": 100,
  "partitions": [],
  "eventTypeSelectors": [
    "MATERIALIZATION",
    "OBSERVATION",
    "FAILED_TO_MATERIALIZE"
  ]
}

def test_recent_asset_events_query_parsing() -> None:
    with open(Path(__file__).parent / "graphql_queries" / "RecentAssetsEventsQuery.gql", "r") as f:
        recent_asset_events_query = f.read()

    document = parse(recent_asset_events_query)
    assert document is not None

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
        resp = client.post(
            "/graphql",
            json={"query": recent_asset_events_query, "variables": recent_asset_events_variables},
            headers=get_test_headers("test_user@gmail.com", "test_user")
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert "errors" in data
        assert data["errors"][0]["extensions"]["code"] == "FORBIDDEN"