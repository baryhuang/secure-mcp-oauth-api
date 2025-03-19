"""
OAuth service factory module.
"""
from fastapi import HTTPException, status

from app.config.providers import PROVIDER_SERVICES, is_provider_supported
from app.services.oauth_base import BaseOAuthService


def create_oauth_service(provider: str) -> BaseOAuthService:
    """
    Create an OAuth service instance for the specified provider.
    
    Args:
        provider: The OAuth provider name.
        
    Returns:
        BaseOAuthService: An OAuth service instance.
        
    Raises:
        HTTPException: If the provider is not supported.
    """
    if not is_provider_supported(provider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}"
        )
    
    service_class = PROVIDER_SERVICES[provider]
    return service_class() 