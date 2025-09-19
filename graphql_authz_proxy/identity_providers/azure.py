from typing import Optional, Tuple
from graphql_authz_proxy.identity_providers.base import IdentityProvider

class AzureIdentityProvider(IdentityProvider):
    def validate_token(self, token: str, claimed_username: Optional[str], claimed_email: Optional[str]) -> Tuple[bool, Optional[str]]:
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
            return False, f"Azure token invalid: {str(e)}"
