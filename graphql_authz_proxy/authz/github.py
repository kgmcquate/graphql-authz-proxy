import requests
import logging
from functools import lru_cache

def get_github_user_info(access_token):
    """Cached function to get GitHub user information"""
    github_api_headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'dagster-api-gateway'
    }
    try:
        user_response = requests.get(
            'https://api.github.com/user',
            headers=github_api_headers,
            timeout=10
        )
        user_info = None
        if user_response.status_code == 200:
            user_info = user_response.json()
        else:
            return None, []
        orgs_response = requests.get(
            'https://api.github.com/user/orgs',
            headers=github_api_headers,
            timeout=10
        )
        user_orgs = []
        if orgs_response.status_code == 200:
            orgs = orgs_response.json()
            user_orgs = [org['login'] for org in orgs]
        return user_info, user_orgs
    except Exception:
        return None, []
