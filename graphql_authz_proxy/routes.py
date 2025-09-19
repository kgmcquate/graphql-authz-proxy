from urllib.parse import urljoin

import requests
from flask import Flask, Response, current_app, jsonify, request
from graphql import (
    DocumentNode,
    FragmentDefinitionNode,
    OperationDefinitionNode,
    OperationType,
    parse,
)

from graphql_authz_proxy.authz.permissions import check_field_allowances, check_field_denials
from graphql_authz_proxy.authz.utils import (
    convert_fields_to_dict,
    extract_user_from_headers,
    render_fields,
)
from graphql_authz_proxy.identity_providers.main import get_identity_provider
from graphql_authz_proxy.models import FieldNodeDict, Group, Groups, PolicyEffect, User, UserRules, Users


def proxy_all(path: str) -> Response:
    """Proxy all non-GraphQL requests to the upstream Dagster webserver.
    Forwards the incoming request, preserving method, headers, and body.

    Args:
        path (str): The path to proxy to the upstream server.

    Returns:
        Response: Flask response with upstream content and status.

    """
    try:
        # Forward the request to Dagster webserver
        headers = dict(request.headers)
        headers.pop("Host", None)
        headers.pop("Content-Length", None)

        url = current_app.config["upstream_url"] + f"/{path}"
        if request.query_string:
            url += f"?{request.query_string.decode()}"

        response = requests.request(
            method=request.method,
            url=url,
            data=request.get_data(),
            headers=headers,
            timeout=30,
        )

        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers),
        )
    except Exception as e:
        current_app.logger.exception(f"Error proxying request: {e!s}")
        return jsonify({
            "errors": [{
                "message": "Proxy error",
                "extensions": {"code": "PROXY_ERROR"},
            }],
        }), 502
        

def health_check() -> Response:
    """Health check endpoint for the proxy service.
    Returns service status, enabled features, and config status.

    Returns:
        Response: JSON response with health and config info.

    """
    groups: Groups = current_app.config.get("groups_config")
    config_status = {
        "groups_configured": len(groups.groups),
    }
    
    return jsonify({
        "status": "healthy", 
        "service": "graphql-authz-proxy",
        "features": {
            "graphql_parsing": True,
            "mutation_detection": True,
            "github_integration": True,
            "config_driven_auth": True,
            "parameter_validation": True,
            "jsonpath_support": True,
        },
        "authorization": config_status,
    })



def _parse_graphql_request() -> tuple[str, dict, str]:
    """Parse GraphQL query, variables, and operation name from request."""
    if request.is_json:
        data = request.get_json()
        query = data.get("query", "") if data else ""
        variables = data.get("variables", {}) if data else {}
        operation_name = data.get("operationName", "") if data else ""
    else:
        query = request.form.get("query", "")
        variables = {}
        operation_name = ""
    return query, variables, operation_name


def _get_user(
    users_config: Users,
    username: str,
    user_email: str
) -> tuple[User | None, Response | None]:
    """Get user object by username/email and validate token if required."""
    user = users_config.get_user(username)
    if user is None:
        user = users_config.get_user_by_email(user_email)
    if user is None:
        return None, (jsonify({
            "errors": [{
                "message": "User not configured.",
                "extensions": {
                    "code": "FORBIDDEN",
                    "user": username,
                    "user_email": user_email,
                },
            }],
        }), 403)

    return user, None


def _validate_user(
    user: User,
    access_token: str,
    idp_name: str,
    validate_token: bool,
) -> tuple[bool, Response | None]:
    if validate_token and access_token:
        identity_provider = get_identity_provider(idp_name)
        valid, reason = identity_provider.validate_token(access_token, user.username, user.email)
        if not valid:
            return None, (jsonify({
                "errors": [{
                    "message": f"Authentication failed: {reason}",
                    "extensions": {
                        "code": "UNAUTHORIZED",
                        "user": user.username,
                        "user_email": user.email,
                    },
                }],
            }), 401)
    return True, None


def _collect_field_rules(
    user_groups: list[Group],
) -> UserRules:
    """Collect field denials and allowances from user groups."""
    query_field_denials = []
    mutation_field_denials = []
    query_field_allowances = []
    mutation_field_allowances = []
    for group in user_groups:
        if group:
            if group.permissions.queries and group.permissions.queries.fields:
                if group.permissions.queries.effect == PolicyEffect.DENY:
                    query_field_denials.extend(group.permissions.queries.fields)
                elif group.permissions.queries.effect == PolicyEffect.ALLOW:
                    query_field_allowances.extend(group.permissions.queries.fields)
            if group.permissions.mutations and group.permissions.mutations.fields:
                if group.permissions.mutations.effect == PolicyEffect.DENY:
                    mutation_field_denials.extend(group.permissions.mutations.fields)
                elif group.permissions.mutations.effect == PolicyEffect.ALLOW:
                    mutation_field_allowances.extend(group.permissions.mutations.fields)
    return UserRules(
        query_field_allowances=query_field_allowances,
        query_field_denials=query_field_denials,
        mutation_field_allowances=mutation_field_allowances,
        mutation_field_denials=mutation_field_denials,
    )


def _check_authorization(
    document: DocumentNode,
    variables: dict,
    user_rules: UserRules
) -> tuple[bool, str, list[str]]:
    """Check authorization for each operation in the GraphQL document."""
    fragments = {}
    for definition in document.definitions:
        if isinstance(definition, FragmentDefinitionNode):
            fragments[definition.name.value] = definition
    for definition in document.definitions:
        if isinstance(definition, OperationDefinitionNode):
            fields = render_fields(
                fragments=fragments,
                variable_values=variables,
                selection_set=definition.selection_set,
            )
            field_dict: FieldNodeDict = convert_fields_to_dict(fields)
            if definition.operation == OperationType.MUTATION:
                field_denials = user_rules.mutation_field_denials
                field_allowances = user_rules.mutation_field_allowances
            elif definition.operation == OperationType.QUERY:
                field_denials = user_rules.query_field_denials
                field_allowances = user_rules.query_field_allowances
            else:
                continue
            # Explicit allowances override denials
            if field_allowances:
                is_allowed, reason, parent_fields = check_field_allowances(
                    field_nodes=field_dict,
                    field_rules=field_allowances,
                )
            elif field_denials:
                is_allowed, reason, parent_fields = check_field_denials(
                    field_nodes=field_dict,
                    field_denials=field_denials,
                )
            else:
                raise ValueError("No field restrictions or allowances configured.")
            
            return is_allowed, reason, parent_fields

    return True, "No operations to authorize.", []


def _forward_to_upstream(upstream_graphql_url: str) -> Response:
    """Forward the request to the upstream Dagster webserver."""
    headers = dict(request.headers)
    response = requests.post(
        upstream_graphql_url,
        data=request.get_data(),
        headers=headers,
        timeout=30,
    )
    return Response(
        response.content,
        status=response.status_code,
        headers=dict(response.headers),
    )

def proxy_graphql() -> Response:
    """Proxy and authorize GraphQL requests to the upstream Dagster server.
    Parses the GraphQL query, extracts user info, checks authorization,
    and forwards the request if allowed.

    Returns:
        Response: Flask response with upstream content or error JSON.

    """
    try:
        query, variables, operation_name = _parse_graphql_request()
        document: DocumentNode = parse(query)
        current_app.logger.info(f"Extracting user information from headers: {request.headers}")
        user_email, username, access_token = extract_user_from_headers(request.headers)
        users_config: Users = current_app.config.get("users_config")
        groups_config: Groups = current_app.config.get("groups_config")
        enable_jinja: bool = current_app.config.get("enable_config_jinja", False)
        idp_name: str = current_app.config.get("idp", "github")
        validate_token: bool = current_app.config.get("validate_token", False)
        upstream_graphql_url: str = urljoin(
            current_app.config["upstream_url"], 
            current_app.config["upstream_graphql_path"],
        )
        user, error_response = _get_user(
            users_config,
            username,
            user_email
        )
        if error_response:
            return error_response

        is_valid, validation_response = _validate_user(
            user,
            access_token,
            idp_name,
            validate_token,
        )

        if not is_valid:
            return validation_response

        user_groups = [groups_config.get_group(group_name) for group_name in user.groups]
        user_rules: UserRules = _collect_field_rules(user_groups)
        if enable_jinja:
            user_rules.render_argument_values(
                {"username": username, "user_email": user_email, **request.headers}
            )
        is_allowed, reason, _ = _check_authorization(
            document, variables,
            user_rules,
        )
        if not is_allowed:
            current_app.logger.warning(f"❌ Query '{operation_name}' denied for user {username} ({user_email})")
            current_app.logger.warning(f"❌ Reason: {reason}")
            return jsonify({
                "errors": [{
                    "message": f"Access denied: {reason}",
                    "extensions": {
                        "code": "FORBIDDEN",
                        "user": username,
                        "user_email": user_email,
                        "query": operation_name,
                        "reason": reason
                    },
                }],
            }), 403
            

        return _forward_to_upstream(upstream_graphql_url)
    except Exception as e:
        current_app.logger.exception(f"Error processing request: {e!s}")
        return jsonify({
            "errors": [{
                "message": "Internal server error",
                "extensions": {"code": "INTERNAL_ERROR"},
            }],
        }), 500


def register_routes(
        flask_app: Flask,
        graphql_path: str = "/graphql",
        healthcheck_path: str = "/gqlproxy/health",
    ) -> None:
    """Register all Flask routes for the proxy service.

    Args:
        flask_app (Flask): The Flask app instance.
        graphql_path (str): Path for GraphQL endpoint.
        healthcheck_path (str): Path for health check endpoint.

    """
    flask_app.route("/", defaults={"path": ""})(proxy_all)
    flask_app.route("/<path:path>")(proxy_all)
    flask_app.route(healthcheck_path, methods=["GET"])(health_check)
    flask_app.route(graphql_path, methods=["POST"])(proxy_graphql)
