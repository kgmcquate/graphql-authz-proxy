from graphql import FragmentDefinitionNode, parse, OperationDefinitionNode, OperationType, DocumentNode, FieldDefinitionNode, InputValueDefinitionNode
import requests
from flask import Flask, request, jsonify, Response, current_app
# from gql_parsing import render_fields
from graphql_authz_proxy.authz.utils import extract_user_from_headers, convert_fields_to_dict, render_fields
from graphql_authz_proxy.authz.permissions import check_field_restrictions, check_field_allowances
from graphql_authz_proxy.models import FieldRule, FieldNodeDict, PolicyEffect, User, User, Groups
from urllib.parse import urljoin


def proxy_all(path):
    """Proxy all other requests to Dagster webserver"""
    try:
        # Forward the request to Dagster webserver
        headers = dict(request.headers)
        headers.pop('Host', None)
        headers.pop('Content-Length', None)

        url = current_app.config['upstream_url'] + f'/{path}'
        if request.query_string:
            url += f'?{request.query_string.decode()}'

        response = requests.request(
            method=request.method,
            url=url,
            data=request.get_data(),
            headers=headers,
            timeout=30
        )

        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )
    except Exception as e:
        current_app.logger.error(f"Error proxying request: {str(e)}")
        return jsonify({
            'errors': [{
                'message': 'Proxy error',
                'extensions': {'code': 'PROXY_ERROR'}
            }]
        }), 502
        

def health_check():
    groups: Groups = current_app.config.get('groups_config')
    config_status = {
        'groups_configured': len(groups.groups)
    }
    
    return jsonify({
        'status': 'healthy', 
        'service': 'graphql-authz-proxy',
        'features': {
            'graphql_parsing': True,
            'mutation_detection': True,
            'github_integration': True,
            'config_driven_auth': True,
            'parameter_validation': True,
            'jsonpath_support': True
        },
        'authorization': config_status
    })


def proxy_graphql():
    try:
        # Extract user information
        current_app.logger.info(f"Extracting user information from headers: {request.headers}")
        user_email, username, access_token = extract_user_from_headers(request.headers)

        users_config: User = current_app.config.get('users_config')
        groups_config: Groups = current_app.config.get('groups_config')

        user: User = users_config.get_user(username)

        upstream_graphql_url: str = urljoin(current_app.config['upstream_url'], current_app.config['upstream_graphql_path'])

        if user is None:
            user = users_config.get_user_by_email(user_email)

        if user is None:
            return jsonify({
                'errors': [{
                    'message': 'User not configured.',
                    'extensions': {
                        'code': 'FORBIDDEN',
                        'user': username,
                        'user_email': user_email
                    }
                }]
            }), 403

        user_groups = [groups_config.get_group(group_name) for group_name in user.groups]

        query_field_restrictions: list[FieldRule] = []
        mutation_field_restrictions: list[FieldRule] = []
        query_field_allowances: list[FieldRule] = []
        mutation_field_allowances: list[FieldRule] = []
        for group in user_groups:
            if group:
                if group.permissions.queries and group.permissions.queries.fields:
                    if group.permissions.queries.effect == PolicyEffect.DENY:
                        query_field_restrictions.extend(group.permissions.queries.fields)
                    elif group.permissions.queries.effect == PolicyEffect.ALLOW:
                        query_field_allowances.extend(group.permissions.queries.fields)
                if group.permissions.mutations and group.permissions.mutations.fields:
                    if group.permissions.mutations.effect == PolicyEffect.DENY:
                        mutation_field_restrictions.extend(group.permissions.mutations.fields)
                    elif group.permissions.mutations.effect == PolicyEffect.ALLOW:
                        mutation_field_allowances.extend(group.permissions.mutations.fields)

        # Get the GraphQL query
        if request.is_json:
            data = request.get_json()
            query = data.get('query', '') if data else ''
            variables = data.get('variables', {}) if data else {}
            operation_name = data.get('operationName', '') if data else ''
        else:
            query = request.form.get('query', '')
            variables = {}
            operation_name = ''

        document: DocumentNode = parse(query)

        fragments = {}
        for definition in document.definitions:
            if isinstance(definition, FragmentDefinitionNode):
                fragments[definition.name.value] = definition

        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                fields = render_fields(
                    fragments=fragments,
                    variable_values=variables,
                    selection_set=definition.selection_set
                )

                field_dict: FieldNodeDict = convert_fields_to_dict(fields)

                # pprint.pprint(field_dict)

                if definition.operation == OperationType.MUTATION:
                    field_restrictions = mutation_field_restrictions
                    field_allowances = mutation_field_allowances
                elif definition.operation == OperationType.QUERY:
                    field_restrictions = query_field_restrictions
                    field_allowances = query_field_allowances
                else:
                    continue
                

                if field_restrictions:
                    is_allowed, reason, parent_fields = check_field_restrictions(
                        field_nodes=field_dict,
                        field_restrictions=field_restrictions
                    )
                elif field_allowances:
                    is_allowed, reason, parent_fields = check_field_allowances(
                        field_nodes=field_dict,
                        field_rules=field_allowances
                    )
                else:
                    raise Exception(f"No field restrictions or allowances configured for user groups {user_groups}")

                if not is_allowed:
                    current_app.logger.warning(f"❌ Query '{operation_name}' denied for user {username} ({user_email})")
                    current_app.logger.warning(f"❌ Reason: {reason}")
                    return jsonify({
                        'errors': [{
                            'message': f'Access denied: {reason}',
                            'extensions': {
                                'code': 'FORBIDDEN',
                                'user': username,
                                'user_email': user_email,
                                # 'user_groups': user_groups,
                                'query': operation_name,
                                'reason': reason,
                                'fields': parent_fields
                            }
                        }]
                    }), 403

        # Forward the request to Dagster webserver
        headers = dict(request.headers)
        # headers.pop('Host', None)
        # headers.pop('Content-Length', None)
        response = requests.post(
            upstream_graphql_url,
            data=request.get_data(),
            headers=headers,
            timeout=30
        )
        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )
    except Exception as e:
        current_app.logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            'errors': [{
                'message': 'Internal server error',
                'extensions': {'code': 'INTERNAL_ERROR'}
            }]
        }), 500


def register_routes(flask_app: Flask, graphql_path: str = "/graphql", healthcheck_path: str = "/gqlproxy/health"):

    flask_app.route('/', defaults={'path': ''})(proxy_all)
    flask_app.route('/<path:path>')(proxy_all)

    flask_app.route(healthcheck_path, methods=['GET'])(health_check)
    flask_app.route(graphql_path, methods=['POST'])(proxy_graphql)
