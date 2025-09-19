
from graphql_authz_proxy.identity_providers.base import IdentityProvider


class CustomIdentityProvider(IdentityProvider):
    def validate_token(self, token: str, claimed_username: str | None, claimed_email: str | None) -> tuple[bool, str | None]:
        """Validate a custom access token and check claimed identity.

        Args:
            token (str): Custom access token.
            claimed_username (str | None): Username claimed by the user.
            claimed_email (str | None): Email claimed by the user.

        Returns:
            tuple: (is_valid, error_reason_if_any)

        """
        # Implement custom IdP logic here
        return True, None
