import os

from graphql_authz_proxy.models import Groups, Users

USERS_CONFIG = os.path.join(os.path.dirname(__file__), "authz_configs", "users.yaml")
GROUPS_CONFIG = os.path.join(os.path.dirname(__file__), "authz_configs", "groups.yaml")

def test_parse_users_config() -> None:
    users = Users.parse_config(USERS_CONFIG)
    assert isinstance(users, Users)
    assert len(users.users) == 2
    usernames = [u.username for u in users.users]
    assert "kgmcquate" in usernames
    assert "bob" in usernames


def test_parse_groups_config() -> None:
    groups = Groups.parse_config(GROUPS_CONFIG)
    assert isinstance(groups, Groups)
    assert len(groups.groups) == 2
    group_names = [g.name for g in groups.groups]
    assert "admin" in group_names
    assert "viewers" in group_names


def test_users_config_string_parsing() -> None:
    users_yaml = """
users:
  - username: "alice"
    email: "alice@example.com"
    groups: ["admin", "viewer"]
  - username: "bob"
    email: "bob@example.com"
    groups: ["admin"]  

"""
    users = Users.parse_config_string(users_yaml)
    assert isinstance(users, Users)
    assert len(users.users) == 2


def test_groups_config_string_parsing() -> None:
    groups_yaml = """
groups:
  - name: "admin"
    permissions:
      mutations:
        effect: "allow"
      queries:
        effect: "allow"
  - name: "viewers"
    permissions:
      mutations:
        effect: "deny"
      queries:
        effect: "allow"
"""
    groups = Groups.parse_config_string(groups_yaml)
    assert isinstance(groups, Groups)
    assert len(groups.groups) == 2


def test_groups_config_string_parsing_with_anchors() -> None:
    groups_yaml = """
groups:
  - name: "admin"
    permissions:
      mutations:
        effect: "allow"
      queries: &admin_query_policy
        effect: "allow"
  - name: "viewers"
    permissions:
      mutations:
        effect: "deny"
      queries:
        <<: *admin_query_policy
        fields:
          - field_name: "GetUserData"
"""
    groups = Groups.parse_config_string(groups_yaml)
    assert isinstance(groups, Groups)
    assert len(groups.groups) == 2


def test_groups_config_string_parsing_with_external_anchors() -> None:
    groups_yaml = """

allow_policy: &admin_query_policy
  effect: "allow"

  
groups:
  - name: "admin"
    permissions:
      mutations:
        effect: "allow"
      queries:
      <<: *admin_query_policy
  - name: "viewers"
    permissions:
      mutations:
        effect: "deny"
      queries:
        <<: *admin_query_policy
        fields:
          - field_name: "GetUserData"
"""
    groups = Groups.parse_config_string(groups_yaml)
    assert isinstance(groups, Groups)
    assert len(groups.groups) == 2
