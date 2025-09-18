import logging
from graphql_authz_proxy.authz.utils import get_value_of_jsonpath
from graphql_authz_proxy.models import FieldRule, PolicyEffect, User, Groups, Group, FieldNodeDict, FieldRule
from graphql import OperationType


def check_field_restrictions(
        field_nodes: FieldNodeDict,
        field_restrictions: list[FieldRule],
        parent_fields: list[str] = None
    ) -> tuple[bool, str, list[str]]:
    if not field_restrictions:
        return True, "No field restrictions to check", parent_fields
    
    if parent_fields is None:
        parent_fields = []

    for field_restriction in field_restrictions:
        if field_restriction.field_name == "*":
            return False, "Wildcard '*' found in field restrictions, all fields are denied", parent_fields

        if field_restriction.field_name in field_nodes:
            if field_restriction.arguments:
                for arg_restriction in field_restriction.arguments:
                    field_node_args = field_nodes[field_restriction.field_name].get('arguments', {})
                    if arg_restriction.argument_name in field_node_args:
                        arg_value = field_node_args[arg_restriction.argument_name]
                        if arg_value in arg_restriction.values:
                            return False, f"Argument '{arg_restriction.argument_name}' value '{arg_value}' is forbidden for field '{field_restriction.field_name}'", parent_fields + [field_restriction.field_name]

            # Field is allowed, check sub-fields if any
            sub_field_nodes = field_nodes[field_restriction.field_name].get('selection_set')
            if sub_field_nodes and field_restriction.field_rules:
                parent_fields.append(field_restriction.field_name)
                all_subfields_allowed = True
                for sub_field_name, sub_field_node in sub_field_nodes.items():
                    is_allowed, reason, parent_fields = check_field_restrictions(
                        {sub_field_name: sub_field_node},
                        field_restriction.field_rules,
                        parent_fields
                    )
                    if not is_allowed:
                        all_subfields_allowed = False
                        return False, reason, parent_fields
                if all_subfields_allowed:
                    parent_fields.pop()
                    continue
            elif sub_field_nodes and not field_restriction.field_rules:
                return False, f"Field '{field_restriction.field_name}' has sub-fields but no sub-field restrictions defined", parent_fields
            else:
                continue
        else:
            continue

    return True, "All field permissions are satisfied.", parent_fields


def check_field_allowances(
        field_nodes: FieldNodeDict,
        field_rules: list[FieldRule],
        parent_fields: list[str] = None
    ) -> tuple[bool, str, list[str]]:
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
            field_node_args = field_nodes[field_rule.field_name].get('arguments', {})
            for arg_rule in field_rule.arguments:
                if arg_rule.argument_name in field_node_args:
                    arg_value = field_node_args[arg_rule.argument_name]
                    if arg_rule.values and arg_value not in arg_rule.values:
                        return False, f"Argument '{arg_rule.argument_name}' value '{arg_value}' is not allowed for field '{field_rule.field_name}'", parent_fields + [field_rule.field_name]

        # Field is allowed, check sub-fields if any
        sub_field_nodes = field_nodes[field_rule.field_name].get('selection_set')
        if sub_field_nodes and field_rule.field_rules:
            parent_fields.append(field_rule.field_name)
            all_subfields_allowed = True
            for sub_field_name, sub_field_node in sub_field_nodes.items():
                is_allowed, reason, parent_fields = check_field_allowances(
                    {sub_field_name: sub_field_node},
                    field_rule.field_rules,
                    parent_fields
                )
                if not is_allowed:
                    all_subfields_allowed = False
                    return False, reason, parent_fields
            if all_subfields_allowed:
                parent_fields.pop()
                continue
        else:
            return True, f"Field '{field_rule.field_name}' is allowed", parent_fields + [field_rule.field_name]
    
    return False, "No matching field allowances found, access denied", parent_fields
