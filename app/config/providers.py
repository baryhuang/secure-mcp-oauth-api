"""
Provider configuration module for the OAuth API service.
"""
from enum import Enum
from typing import Dict, List, Set, Type

# Import provider service classes once created
from app.services.providers.sketchfab import SketchfabOAuthService
from app.services.providers.google import GoogleOAuthService


class OAuthProvider(str, Enum):
    """
    Enum for supported OAuth providers.
    """
    SKETCHFAB = "sketchfab"
    GOOGLE = "google"
    # Add more providers here as needed


# Register provider service classes
PROVIDER_SERVICES: Dict[str, Type] = {
    OAuthProvider.SKETCHFAB: SketchfabOAuthService,
    OAuthProvider.GOOGLE: GoogleOAuthService,
    # Add more providers here as needed
}


def get_supported_providers() -> List[str]:
    """
    Get list of supported OAuth providers.
    
    Returns:
        List[str]: List of supported provider names.
    """
    return [provider.value for provider in OAuthProvider]


def is_provider_supported(provider: str) -> bool:
    """
    Check if a provider is supported.
    
    Args:
        provider: Provider name to check.
        
    Returns:
        bool: True if the provider is supported, False otherwise.
    """
    return provider in get_supported_providers() 