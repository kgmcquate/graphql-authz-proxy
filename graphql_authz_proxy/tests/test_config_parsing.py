import pytest
from graphql_authz_proxy.models import Users, Groups
import os

USERS_CONFIG = os.path.join(os.path.dirname(__file__), "authz_configs", "users.yaml")
GROUPS_CONFIG = os.path.join(os.path.dirname(__file__), "authz_configs", "groups.yaml")

def test_parse_users_config():
    users = Users.parse_config(USERS_CONFIG)
    assert isinstance(users, Users)
    assert len(users.users) == 2
    usernames = [u.username for u in users.users]
    assert "kgmcquate" in usernames
    assert "bob" in usernames


def test_parse_groups_config():
    groups = Groups.parse_config(GROUPS_CONFIG)
    assert isinstance(groups, Groups)
    assert len(groups.groups) == 2
    group_names = [g.name for g in groups.groups]
    assert "admin" in group_names
    assert "viewers" in group_names

