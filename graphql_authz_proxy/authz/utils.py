import logging
from typing import Any

from graphql import (
    ConstValueNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    ObjectValueNode,
    SelectionSetNode,
    VariableNode,
    ast_to_dict,
)
from jsonpath_ng import parse as jsonpath_parse

from graphql_authz_proxy.models import FieldNodeDict, RenderedFields


def get_value_of_jsonpath(data: dict, path: str) -> Any:  # noqa: ANN401
    """Get nested value from data using JSONPath notation.

    Args:
        data (dict): The data to search.
        path (str): JSONPath string (without leading $).

    Returns:
        Any: The value(s) found, or None if not found.

    """
    if not data or not path:
        return None
    try:
        jsonpath_expr = f"$.{path}"
        jsonpath_expression = jsonpath_parse(jsonpath_expr)
        matches = [match.value for match in jsonpath_expression.find(data)]
        if not matches:
            return None
        elif len(matches) == 1:
            return matches[0]
        else:
            return matches
    except Exception as e:
        logging.debug(f"JSONPath error for path '{path}': {e!s}")
        return None


def extract_user_from_headers(headers: dict) -> tuple[str, str, str]:
    """Extract user email, username, and access token from HTTP headers.

    Args:
        headers (dict): HTTP request headers.

    Returns:
        tuple: (user_email, username, access_token)

    """
    user_email = headers.get("X-Forwarded-Email", "")
    assert isinstance(user_email, str), f"X-Forwarded-Email header is not a string: {user_email} ({type(user_email)})"

    headers.get("X-Forwarded-Preferred-Username", "")
    user = headers.get("X-Forwarded-User", "")
    assert isinstance(user, str), f"X-Forwarded-User header is not a string: {user} ({type(user)})"
    access_token = headers.get("X-Forwarded-Access-Token", "")
    assert isinstance(access_token, str), f"X-Forwarded-Access-Token header is not a string: ({type(access_token)})"
    return user_email, user, access_token


def convert_fields_to_dict(fields: RenderedFields) -> FieldNodeDict:  # noqa: C901, PLR0912
    """Convert RenderedFields to a nested dict of field arguments and selection sets.

    Args:
        fields (RenderedFields): Parsed GraphQL fields.

    Returns:
        FieldNodeDict: Nested dict of field arguments and selection sets.

    """
    result = {}
    for field_name, selection in fields.items():
        if isinstance(selection, list):
            field_dicts = []
            for field in selection:
                if isinstance(field, FieldNode):
                    try:
                        field_dict = ast_to_dict(field)
                    except TypeError:
                        # If argument value is a list, convert to tuple for hashing
                        for arg in getattr(field, "arguments", []):
                            if hasattr(arg.value, "values") and isinstance(arg.value.values, list):
                                arg.value.values = tuple(arg.value.values)
                        field_dict = ast_to_dict(field)
                    field_dicts.append(field_dict)
            if len(field_dicts) == 1:
                field_dict = field_dicts[0]
                result[field_name] = {
                    "arguments": {arg["name"]["value"]: arg["value"] for arg in field_dict.get("arguments", [])},
                    "selection_set": None,
                }
            else:
                result[field_name] = []
                for field_dict in field_dicts:
                    result[field_name].append({
                        "arguments": {arg["name"]["value"]: arg["value"] for arg in field_dict.get("arguments", [])},
                        "selection_set": None,
                    })
        elif isinstance(selection, dict):
            field_node = selection.get("_field_node")
            nested = selection.get("_nested")
            if field_node:
                try:
                    field_dict = ast_to_dict(field_node)
                except TypeError:
                    for arg in getattr(field_node, "arguments", []):
                        if hasattr(arg.value, "values") and isinstance(arg.value.values, list):
                            arg.value.values = tuple(arg.value.values)
                    field_dict = ast_to_dict(field_node)
                arguments = {arg["name"]["value"]: arg["value"] for arg in field_dict.get("arguments", [])}
            else:
                arguments = {}
            result[field_name] = {
                "arguments": arguments,
                "selection_set": convert_fields_to_dict(nested) if nested else None,
            }
    return result


def render_fields(  # noqa: C901, PLR0912
    fragments: dict[str, FragmentDefinitionNode],
    variable_values: dict[str, Any],
    selection_set: SelectionSetNode,
) -> RenderedFields:
    """Recursively collect fields from a GraphQL selection set, resolving fragments and variables.

    Args:
        fragments (dict): Fragment definitions by name.
        variable_values (dict): Variable values for the query.
        selection_set (SelectionSetNode): Selection set to process.

    Returns:
        RenderedFields: Nested dict of fields and subfields.

    """
    fields: RenderedFields = {}

    for selection in selection_set.selections:
        if isinstance(selection, FragmentSpreadNode):
            name = selection.name.value
            fragment = fragments.get(selection.name.value)
            if fragment is not None:
                fields.update(
                    render_fields(
                        fragments,
                        variable_values,
                        fragment.selection_set,
                    ),
                )
        elif isinstance(selection, InlineFragmentNode):
            if selection.selection_set:
                fields.update(
                    render_fields(
                        fragments,
                        variable_values,
                        selection.selection_set,
                    ),
                )
        elif isinstance(selection, FieldNode):
            name = selection.alias.value if selection.alias else selection.name.value
            # Insert variable values into arguments
            if selection.arguments:
                for arg in selection.arguments:
                    if isinstance(arg.value, VariableNode):
                        variable_value = variable_values.get(arg.value.name.value)
                        arg.value = variable_value
                    elif isinstance(arg.value, ConstValueNode):
                        arg.value = arg.value.value
                    elif isinstance(arg.value, ObjectValueNode):
                        arg.value = arg.value
                    else:
                        raise TypeError(f"Unsupported argument value type: {type(arg.value)}: {arg.value.to_dict()}")
            if selection.selection_set:
                fields[name] = {
                    "_field_node": selection,
                    "_nested": render_fields(
                        fragments,
                        variable_values,
                        selection.selection_set,
                    ),
                }
            else:
                fields.setdefault(name, []).append(selection)
        else:
            raise TypeError(f"Unexpected selection node type: {type(selection)}")
    return fields
