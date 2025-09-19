from typing import Any

from graphql_authz_proxy.authz.utils import get_value_of_jsonpath
from graphql_authz_proxy.models import FieldNodeDict, FieldRule


def check_field_denials(  # noqa: C901, PLR0911, PLR0912
        field_nodes: FieldNodeDict,
        field_denials: list[FieldRule],
        parent_fields: list[str] | None = None,
    ) -> tuple[bool, str, list[str]]:
    """Check if any field or argument matches a restriction (deny rule).

    Args:
        field_nodes (FieldNodeDict): Parsed fields from query.
        field_denials (list[FieldRule]): List of deny rules.
        parent_fields (list[str] | None): Parent field path for nested checks.

    Returns:
        tuple: (is_allowed, reason, parent_fields)

    """
    if not field_denials:
        return True, "No field restrictions to check", parent_fields
    
    if parent_fields is None:
        parent_fields = []

    for field_restriction in field_denials:
        if field_restriction.field_name == "*":
            return False, "Wildcard '*' found in field restrictions, all fields are denied", parent_fields

        if field_restriction.field_name in field_nodes:
            if field_restriction.arguments:
                for arg_restriction in field_restriction.arguments:
                    field_node_args = field_nodes[field_restriction.field_name].get("arguments", {})
                    if arg_restriction.argument_name in field_node_args:
                        arg_value = field_node_args[arg_restriction.argument_name]
                        if arg_restriction.values:
                            for denied_value in arg_restriction.values:
                                if isinstance(denied_value, dict):
                                    # Deny if ANY key/value in denied_value matches
                                    for path, val in flatten_jsonpaths(denied_value):
                                        actual = get_value_of_jsonpath(arg_value, path)
                                        if actual == val:
                                            return (
                                                False,
                                                f"Argument '{arg_restriction.argument_name}' "
                                                f"value '{arg_value}' is forbidden for field '{field_restriction.field_name}'",  # noqa: E501
                                                [*parent_fields, field_restriction.field_name]
                                            )
                                elif arg_value == denied_value:
                                    return (
                                        False,
                                        f"Argument '{arg_restriction.argument_name}' "
                                        f"value '{arg_value}' is forbidden for field '{field_restriction.field_name}'",
                                        [*parent_fields, field_restriction.field_name]
                                    )

            # Field is allowed, check sub-fields if any
            sub_field_nodes = field_nodes[field_restriction.field_name].get("selection_set")
            if sub_field_nodes and field_restriction.field_rules:
                parent_fields.append(field_restriction.field_name)
                all_subfields_allowed = True
                for sub_field_name, sub_field_node in sub_field_nodes.items():
                    is_allowed, reason, parent_fields = check_field_denials(
                        {sub_field_name: sub_field_node},
                        field_restriction.field_rules,
                        parent_fields,
                    )
                    if not is_allowed:
                        all_subfields_allowed = False
                        return False, reason, parent_fields
                if all_subfields_allowed:
                    parent_fields.pop()
                    continue
            elif sub_field_nodes and not field_restriction.field_rules:
                return (
                    False,
                    f"Field '{field_restriction.field_name}' has sub-fields but no sub-field restrictions defined", 
                    parent_fields
                )
            else:
                continue
        else:
            continue

    return True, "All field permissions are satisfied.", parent_fields


def check_field_allowances(  # noqa: C901, PLR0912
        field_nodes: FieldNodeDict,
        field_rules: list[FieldRule],
        parent_fields: list[str] | None = None,
    ) -> tuple[bool, str, list[str]]:
    """Check if any field or argument matches an allowance (allow rule).

    Args:
        field_nodes (FieldNodeDict): Parsed fields from query.
        field_rules (list[FieldRule]): List of allow rules.
        parent_fields (list[str] | None): Parent field path for nested checks.

    Returns:
        tuple: (is_allowed, reason, parent_fields)

    """
    if not field_rules:
        return False, "No field allowances defined, all fields are denied", parent_fields
    
    if parent_fields is None:
        parent_fields = []

    for field_rule in field_rules:
        if field_rule.field_name == "*":
            return True, "Wildcard '*' found in field allowances, all fields are allowed", parent_fields

        if field_rule.field_name not in field_nodes:
            continue

        # Check arguments if any
        if field_rule.arguments:
            field_node_args = field_nodes[field_rule.field_name].get("arguments", {})
            for arg_rule in field_rule.arguments:
                if arg_rule.argument_name in field_node_args:
                    arg_value = field_node_args[arg_rule.argument_name]
                    # If values are dicts, use JSONPath for deep matching
                    if arg_rule.values:
                        allowed = False
                        for allowed_value in arg_rule.values:
                            if isinstance(allowed_value, dict):
                                # All keys/values in allowed_value must match
                                all_match = True
                                for path, val in flatten_jsonpaths(allowed_value):
                                    actual = get_value_of_jsonpath(arg_value, path)
                                    if actual != val:
                                        all_match = False
                                        break
                                if all_match:
                                    allowed = True
                                    break
                            elif arg_value == allowed_value:
                                allowed = True
                                break
                        if not allowed:
                            return (
                                False,
                                f"Argument '{arg_rule.argument_name}'" 
                                    f"value '{arg_value}' is not allowed for field '{field_rule.field_name}'",
                                [*parent_fields, field_rule.field_name]
                            )

        # Field is allowed, check sub-fields if any
        sub_field_nodes = field_nodes[field_rule.field_name].get("selection_set")
        if sub_field_nodes and field_rule.field_rules:
            parent_fields.append(field_rule.field_name)
            all_subfields_allowed = True
            for sub_field_name, sub_field_node in sub_field_nodes.items():
                is_allowed, reason, parent_fields = check_field_allowances(
                    {sub_field_name: sub_field_node},
                    field_rule.field_rules,
                    parent_fields,
                )
                if not is_allowed:
                    all_subfields_allowed = False
                    return False, reason, parent_fields
            if all_subfields_allowed:
                parent_fields.pop()
                continue
        else:
            return True, f"Field '{field_rule.field_name}' is allowed", [*parent_fields, field_rule.field_name]

    return False, "No matching field allowances found, access denied", parent_fields


def flatten_jsonpaths(d: dict, parent_key: str = "") -> list[tuple[str, Any]]:
    """Yield (jsonpath, value) pairs for all leaf nodes in a nested dict.

    Args:
        d (dict): Nested dictionary to flatten.
        parent_key (str): Prefix for keys (used for recursion).

    Returns:
        list: List of (jsonpath, value) pairs for all leaf nodes.

    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_jsonpaths(v, new_key))
        else:
            items.append((new_key, v))
    return items
