from graphql import parse

from graphql_authz_proxy.authz.utils import convert_fields_to_dict, render_fields

SIMPLE_QUERY = """
query HeroQuery($heroName: String!) {
  hero(name: $heroName) {
    first_name
    friends {
      first_name
    }
  }
}
"""

ARG_QUERY = """
query GetUser($name: String!) {
  getUser(name: $name) {
    id
    name
  }
}
"""

def test_render_fields_simple() -> None:
    document = parse(SIMPLE_QUERY)
    operation = document.definitions[0]
    fragments = {}
    variable_values = {"heroName": "Ann"}
    fields = render_fields(fragments, variable_values, operation.selection_set)
    assert "hero" in fields
    hero_nested = fields["hero"]["_nested"]
    assert "first_name" in hero_nested
    assert "friends" in hero_nested
    friends_nested = hero_nested["friends"]["_nested"]
    assert "first_name" in friends_nested

def test_render_fields_with_arguments() -> None:
    document = parse("""
    query GetUser($name: String!) {
    getUser(name: $name) {
        id
        name
    }
    }""")


    variable_values = {"name": "Ann"}

    desired_output = {
        "getUser": {
            "arguments": {"name": "Ann"},
            "selection_set": {
                "id": {
                    "arguments": {},
                    "selection_set": None,
                },
                "name": {
                    "arguments": {},
                    "selection_set": None,
                },
            },
        },
    }
    operation = document.definitions[0]
    fragments = {}
    fields = render_fields(fragments, variable_values, operation.selection_set)
    fields_dict = convert_fields_to_dict(fields)
    assert fields_dict == desired_output


def test_render_fields_with_sub_field_arguments() -> None:
    document = parse("""
    query GetUser($first_name: String!) {
        getUser {
            name(first_name: $first_name)
        }
    }
    """)
    desired_output = {
        "getUser": {
            "arguments": {},
            "selection_set": {
                "name": {
                    "arguments": {"first_name": "Ann"},
                    "selection_set": None,
                },
            },
        },
    }
    operation = document.definitions[0]
    fragments = {}
    variable_values = {"first_name": "Ann"}
    fields = render_fields(fragments, variable_values, operation.selection_set)
    fields_dict = convert_fields_to_dict(fields)
    assert fields_dict == desired_output


def test_convert_fields_to_dict_with_arguments() -> None:
    document = parse(ARG_QUERY)
    operation = document.definitions[0]
    fragments = {}
    variable_values = {"name": "Ann"}
    fields = render_fields(fragments, variable_values, operation.selection_set)
    field_dict = convert_fields_to_dict(fields)
    assert "getUser" in field_dict
    assert "arguments" in field_dict["getUser"]
    assert field_dict["getUser"]["arguments"]["name"] == "Ann"
    assert field_dict["getUser"]["selection_set"] is not None
    assert "id" in field_dict["getUser"]["selection_set"]
    assert "name" in field_dict["getUser"]["selection_set"]
