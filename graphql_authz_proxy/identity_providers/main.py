"""Module to get identity provider instances by name."""
from graphql_authz_proxy.identity_providers.azure import AzureIdentityProvider
from graphql_authz_proxy.identity_providers.base import IdentityProvider
from graphql_authz_proxy.identity_providers.custom import CustomIdentityProvider
from graphql_authz_proxy.identity_providers.github import GitHubIdentityProvider


def get_identity_provider(idp_name: str) -> IdentityProvider:
    """Get an identity provider instance by name.

    Args:
        idp_name (str): Name of the identity provider (github, azure, custom).

    Returns:
        IdentityProvider: Instance of the requested provider.

    """
    if idp_name == "github":
        return GitHubIdentityProvider()
    elif idp_name == "azure":
        return AzureIdentityProvider()
    else:
        return CustomIdentityProvider()