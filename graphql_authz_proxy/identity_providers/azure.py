
from graphql_authz_proxy.identity_providers.base import IdentityProvider


class AzureIdentityProvider(IdentityProvider):
    def validate_token(self, token: str, claimed_username: str | None, claimed_email: str | None) -> tuple[bool, str | None]:
        """Validate an Azure access token and check claimed identity.

        Args:
            token (str): Azure access token (JWT).
            claimed_username (str | None): Username claimed by the user.
            claimed_email (str | None): Email claimed by the user.

        Returns:
            tuple: (is_valid, error_reason_if_any)

        """
        try:
            import jwt
            decoded = jwt.decode(token, options={"verify_signature": False})
            az_username = decoded.get("preferred_username") or decoded.get("upn")
            az_email = decoded.get("email")
            if claimed_username and az_username and claimed_username != az_username:
                return False, f"Username mismatch: header={claimed_username} azure={az_username}"
            if claimed_email and az_email and claimed_email != az_email:
                return False, f"Email mismatch: header={claimed_email} azure={az_email}"
            return True, None
        except Exception as e:
            return False, f"Azure token invalid: {e!s}"
