from typing import Any
from jsonpath_ng import parse as jsonpath_parse
import logging
from graphql_authz_proxy.models import RenderedFields, FieldNodeDict
from graphql import ConstValueNode, FieldNode, FragmentDefinitionNode, FragmentSpreadNode, InlineFragmentNode, ObjectValueNode, SelectionSetNode, VariableNode, ast_to_dict

def get_value_of_jsonpath(data, path: str):
    """Get nested value from data using JSONPath notation"""
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
        logging.debug(f"JSONPath error for path '{path}': {str(e)}")
        return None


def extract_user_from_headers(headers: dict) -> tuple[str, str, str]:
    user_email = headers.get('X-Forwarded-Email', '')
    user_preferred_username = headers.get('X-Forwarded-Preferred-Username', '')
    user = headers.get('X-Forwarded-User', '')
    access_token = headers.get('X-Forwarded-Access-Token', '')
    return user_email, user, access_token


def convert_fields_to_dict(fields: RenderedFields) -> FieldNodeDict:
    """
    {'hero': {'first_name': [FieldNode at 29:39],
          'friends': {'first_name': [FieldNode at 60:70]}}}
    ->
    {'hero': {
        'first_name': {"arguments": {}, "selection_set": None},
        'friends': {
            'arguments': {},
            'selection_set': {
                'first_name': {"arguments": {}, "selection_set": None}
            }
        }
    }}
    """
    result = {}
    for field_name, selection in fields.items():
        if isinstance(selection, list):
            field_dicts = [ast_to_dict(field) for field in selection if isinstance(field, FieldNode)]
            if len(field_dicts) == 1:
                field_dict = field_dicts[0]
                result[field_name] = {
                    'arguments': {arg['name']['value']: arg['value'] for arg in field_dict.get('arguments', [])},
                    'selection_set': None
                }
            else:
                result[field_name] = []
                for field_dict in field_dicts:
                    result[field_name].append({
                        'arguments': {arg['name']['value']: arg['value'] for arg in field_dict.get('arguments', [])},
                        'selection_set': None
                    })
        elif isinstance(selection, dict):
            field_node = selection.get('_field_node')
            nested = selection.get('_nested')
            if field_node:
                field_dict = ast_to_dict(field_node)
                arguments = {arg['name']['value']: arg['value'] for arg in field_dict.get('arguments', [])}
            else:
                arguments = {}
            result[field_name] = {
                'arguments': arguments,
                'selection_set': convert_fields_to_dict(nested) if nested else None
            }
    return result


def render_fields(
    fragments: dict[str, FragmentDefinitionNode],
    variable_values: dict[str, Any],
    selection_set: SelectionSetNode
) -> RenderedFields:
    """Collect fields (internal implementation)."""

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
                    )
                )
        elif isinstance(selection, InlineFragmentNode):
            if selection.selection_set:
                fields.update(
                    render_fields(
                        fragments,
                        variable_values,
                        selection.selection_set,
                    )
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
                        # ObjectValueNode
                    else:
                        raise ValueError(f"Unsupported argument value type: {type(arg.value)}: {arg.value.to_dict()}")
            if selection.selection_set:
                fields[name] = {
                    '_field_node': selection,
                    '_nested': render_fields(
                        fragments,
                        variable_values,
                        selection.selection_set,
                    )
                }
            else:
                fields.setdefault(name, []).append(selection)
        else:
            raise TypeError(f"Unexpected selection node type: {type(selection)}")
    return fields
