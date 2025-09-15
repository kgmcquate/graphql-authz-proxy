import logging
from graphql_authz_proxy.authz.utils import get_value_of_jsonpath
from graphql_authz_proxy.models import UsersConfig, GroupsConfig, GroupConfig, Rule
from graphql import OperationType

def check_parameter_restrictions(group_rules: list[Rule], operation_name: str, variables: dict):
    if not variables:
        return True, "No variables to check"
    
    for rule in group_rules:
        if not rule.parameter_restrictions:
            continue

        for param_restriction in rule.parameter_restrictions:
            param_path = param_restriction.jsonpath
            param_value = get_value_of_jsonpath(variables, param_path)
            if param_restriction.allowed_values is not None and \
                param_value not in param_restriction.allowed_values:
                logging.warning(f"Parameter {param_path} value {param_value} not allowed")
                return False, f"Parameter {param_path} value '{param_value}' not allowed"
            elif param_restriction.forbidden_values is not None and \
                param_value in param_restriction.forbidden_values:
                logging.warning(f"Parameter {param_path} value {param_value} is forbidden")
                return False, f"Parameter {param_path} value '{param_value}' is forbidden"

    logging.debug(f"All parameter restrictions passed for {operation_name}")
    return True, "Parameter restrictions satisfied"


def check_operation_permission(
        user_groups: list[GroupConfig],
        operation_type: OperationType,
        operation_name: str, 
        variables: dict
    ):

    for group in user_groups:
        if operation_type == OperationType.QUERY:
            group_rules = group.permissions.queries if group.permissions else []
        elif operation_type == OperationType.MUTATION:
            group_rules = group.permissions.mutations if group.permissions else []

        if variables is not None:
            param_allowed, param_reason = check_parameter_restrictions(group_rules, operation_name, variables)

        if any(operation_name == rule.operation_name or rule.operation_name == "*" for rule in group_rules):
            operation_allowed = True

        if operation_allowed and param_allowed:
            return True, f"Group {group.name} allows {operation_name}"
        elif operation_allowed and not param_allowed:
            logging.warning(f"Group {group.name} allows {operation_name} but parameter restrictions failed: {param_reason}")
        elif not operation_allowed and param_allowed:
            logging.warning(f"Group {group.name} denies {operation_name}")

        return True, f"Group {group.name} allows {operation_name}"

    return False, f"No permission for mutation {operation_name}"
