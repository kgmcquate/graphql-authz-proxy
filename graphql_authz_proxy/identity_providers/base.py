

class IdentityProvider:
    def validate_token(self, token: str, claimed_username: str | None, claimed_email: str | None) -> tuple[bool, str | None]:
        """Validate the token and check if the claimed identity matches.

        Args:
            token (str): The access token to validate.
            claimed_username (str | None): Username claimed by the user.
            claimed_email (str | None): Email claimed by the user.

        Returns:
            tuple: (is_valid, error_reason_if_any)

        """
        raise NotImplementedError
