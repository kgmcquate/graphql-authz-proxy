import logging
from graphql_authz_proxy.authz.utils import get_value_of_jsonpath
from graphql_authz_proxy.models import FieldAllowance, User, Groups, Group, FieldNodeDict, FieldRestriction
from graphql import OperationType


def check_field_restrictions(
        field_nodes: FieldNodeDict,
        field_restrictions: list[FieldRestriction],
        parent_fields: list[str] = None
    ) -> tuple[bool, str, list[str]]:
    if not field_restrictions:
        return True, "No field restrictions to check", parent_fields
    
    if parent_fields is None:
        parent_fields = []

    for field_restriction in field_restrictions:
        if field_restriction.name == "*":
            return False, "Wildcard '*' found in field restrictions, all fields are denied", parent_fields
        
        if field_restriction.name in field_nodes:
            if field_restriction.argument_restrictions:
                for arg_restriction in field_restriction.argument_restrictions:
                    arg_restriction.allowed_values

                    field_node_args = field_nodes[field_restriction.name].get('arguments', {})
                    if arg_restriction.name in field_node_args:
                        arg_value = field_node_args[arg_restriction.name]
                        if arg_restriction.allowed_values is not None and \
                            arg_value not in arg_restriction.allowed_values:
                            return False, f"Argument '{arg_restriction.name}' value '{arg_value}' not allowed for field '{field_restriction.name}'", parent_fields + [field_restriction.name]
                        elif arg_restriction.forbidden_values is not None and \
                            arg_value in arg_restriction.forbidden_values:
                            return False, f"Argument '{arg_restriction.name}' value '{arg_value}' is forbidden for field '{field_restriction.name}'", parent_fields + [field_restriction.name]

            # Field is allowed, check sub-fields if any
            sub_field_nodes = field_nodes[field_restriction.name].get('selection_set')
            if sub_field_nodes and field_restriction.field_restrictions:
                parent_fields.append(field_restriction.name)
                all_subfields_allowed = True
                for sub_field_name, sub_field_node in sub_field_nodes.items():
                    is_allowed, reason, parent_fields = check_field_restrictions(
                        {sub_field_name: sub_field_node},
                        field_restriction.field_restrictions,
                        parent_fields
                    )
                    if not is_allowed:
                        all_subfields_allowed = False
                        return False, reason, parent_fields
                if all_subfields_allowed:
                    parent_fields.pop()
                    continue
            elif sub_field_nodes and not field_restriction.field_restrictions:
                return False, f"Field '{field_restriction.name}' has sub-fields but no sub-field restrictions defined", parent_fields
            else:
                continue
        else:
            continue

    return True, "All field permissions are satisfied.", parent_fields


def check_field_allowances(
        field_nodes: FieldNodeDict,
        field_allowances: list[FieldAllowance],
        parent_fields: list[str] = None
    ) -> tuple[bool, str, list[str]]:
    if not field_allowances:
        return False, "No field allowances defined, all fields are denied", parent_fields
    
    if parent_fields is None:
        parent_fields = []

    for field_allowance in field_allowances:
        if field_allowance.name == "*":
            return True, "Wildcard '*' found in field allowances, all fields are allowed", parent_fields
        
        if field_allowance.name not in field_nodes:
            continue

        # Field is allowed, check sub-fields if any
        sub_field_nodes = field_nodes[field_allowance.name].get('selection_set')
        if sub_field_nodes and field_allowance.field_allowances:
            parent_fields.append(field_allowance.name)
            all_subfields_allowed = True
            for sub_field_name, sub_field_node in sub_field_nodes.items():
                is_allowed, reason, parent_fields = check_field_allowances(
                    {sub_field_name: sub_field_node},
                    field_allowance.field_allowances,
                    parent_fields
                )
                if not is_allowed:
                    all_subfields_allowed = False
                    return False, reason, parent_fields
            if all_subfields_allowed:
                parent_fields.pop()
                continue
    
    return False, "No matching field allowances found, access denied", parent_fields
