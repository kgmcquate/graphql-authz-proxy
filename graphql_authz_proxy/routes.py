from graphql import parse, OperationDefinitionNode, OperationType
import requests
from flask import Flask, request, jsonify, Response, current_app
from graphql_authz_proxy.authz.utils import extract_user_from_headers
from graphql_authz_proxy.authz.permissions import check_operation_permission
from graphql_authz_proxy.models import UserConfig, UsersConfig, GroupsConfig
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
    groups: GroupsConfig = current_app.config.get('groups_config')
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

        users_config: UsersConfig = current_app.config.get('users_config')
        groups_config: GroupsConfig = current_app.config.get('groups_config')

        user: UserConfig = users_config.get_user(username)

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


        document = parse(query)

        for definition in document.definitions:
            if not isinstance(definition, OperationDefinitionNode):
                continue

            if definition.operation == OperationType.MUTATION:
                mutation_allowed, mutation_allowed_reason = check_operation_permission(
                    user_groups,
                    OperationType.MUTATION,
                    definition.name,
                    variables
                )


                if not mutation_allowed:
                    current_app.logger.warning(f"❌ Mutation '{operation_name}' denied for user {username} ({user_email})")
                    current_app.logger.warning(f"❌ Reason: {mutation_allowed_reason}")
                    return jsonify({
                        'errors': [{
                            'message': f'Access denied: {mutation_allowed_reason}',
                            'extensions': {
                                'code': 'FORBIDDEN',
                                'user': username,
                                'user_email': user_email,
                                # 'user_groups': user_groups,
                                'mutation': operation_name,
                                'reason': mutation_allowed_reason
                            }
                        }]
                    }), 403
            
            elif definition.operation == OperationType.QUERY:
                query_allowed, query_allowed_reason = check_operation_permission(
                    user_groups,
                    OperationType.QUERY,
                    definition.name,
                    variables
                )

                if not query_allowed:
                    current_app.logger.warning(f"❌ Query '{operation_name}' denied for user {username} ({user_email})")
                    current_app.logger.warning(f"❌ Reason: {query_allowed_reason}")
                    return jsonify({
                        'errors': [{
                            'message': f'Access denied: {query_allowed_reason}',
                            'extensions': {
                                'code': 'FORBIDDEN',
                                'user': username,
                                'user_email': user_email,
                                # 'user_groups': user_groups,
                                'query': operation_name,
                                'reason': query_allowed_reason
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
