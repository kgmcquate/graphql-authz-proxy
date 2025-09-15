from jsonpath_ng import parse as jsonpath_parse
import logging

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
    access_token = headers.get('X-Forwarded-Access-Token', '')
    return user_email, user_preferred_username, access_token
