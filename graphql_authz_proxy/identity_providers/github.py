
import requests

from graphql_authz_proxy.identity_providers.base import IdentityProvider


class GitHubIdentityProvider(IdentityProvider):
    """GitHub identity provider implementation."""
    
    def validate_token(self, token: str, claimed_username: str | None, claimed_email: str | None) -> tuple[bool, str | None]:
        """Validate a GitHub access token and check claimed identity.

        Args:
            token (str): GitHub access token.
            claimed_username (str | None): Username claimed by the user.
            claimed_email (str | None): Email claimed by the user.

        Returns:
            tuple: (is_valid, error_reason_if_any)

        """
        user_info, _ = self._get_github_user_info(token)
        if not user_info:
            return False, "GitHub token invalid"
        gh_username = user_info.get("login")
        gh_email = user_info.get("email")
        if claimed_username and claimed_username != gh_username:
            return False, f"Username mismatch: header={claimed_username} github={gh_username}"
        if claimed_email and gh_email and claimed_email != gh_email:
            return False, f"Email mismatch: header={claimed_email} github={gh_email}"
        return True, None

    def _get_github_user_info(self, access_token):
        """Get GitHub user information and organizations for a given access token.

        Args:
            access_token (str): GitHub access token.

        Returns:
            tuple: (user_info dict, user_orgs list)

        """
        github_api_headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "dagster-api-gateway",
        }
        try:
            user_response = requests.get(
                "https://api.github.com/user",
                headers=github_api_headers,
                timeout=10,
            )
            user_info = None
            if user_response.status_code == 200:
                user_info = user_response.json()
            else:
                return None, []
            orgs_response = requests.get(
                "https://api.github.com/user/orgs",
                headers=github_api_headers,
                timeout=10,
            )
            user_orgs = []
            if orgs_response.status_code == 200:
                orgs = orgs_response.json()
                user_orgs = [org["login"] for org in orgs]
            return user_info, user_orgs
        except Exception:
            return None, []
