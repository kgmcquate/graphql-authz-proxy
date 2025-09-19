from typing import Optional, Tuple
from graphql_authz_proxy.identity_providers.base import IdentityProvider

class CustomIdentityProvider(IdentityProvider):
    def validate_token(self, token: str, claimed_username: Optional[str], claimed_email: Optional[str]) -> Tuple[bool, Optional[str]]:
        # Implement custom IdP logic here
        return True, None
