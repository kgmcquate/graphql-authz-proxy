from typing import Optional, Tuple

class IdentityProvider:
    def validate_token(self, token: str, claimed_username: Optional[str], claimed_email: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate the token and check if the claimed identity matches.
        Returns (is_valid, error_reason_if_any)
        """
        raise NotImplementedError()
