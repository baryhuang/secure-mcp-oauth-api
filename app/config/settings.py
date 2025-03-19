"""
Settings module for loading and validating environment variables.
"""
import os
from functools import lru_cache
from typing import Dict, Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load environment variables from .env file if it exists
load_dotenv()


class Settings(BaseSettings):
    """
    Settings class for the OAuth API service.
    """
    # AWS Configuration
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    dynamodb_table: str = os.getenv("DYNAMODB_TABLE", "oauth-tokens-dev")
    stage: str = os.getenv("STAGE", "dev")

    # Sketchfab OAuth configuration
    sketchfab_client_id: str = os.getenv("SKETCHFAB_CLIENT_ID", "")
    sketchfab_client_secret: str = os.getenv("SKETCHFAB_CLIENT_SECRET", "")
    sketchfab_redirect_uri: str = os.getenv("SKETCHFAB_REDIRECT_URI", "")
    
    # Base URLs for API endpoints
    api_base_path: str = "/api/oauth"

    class Config:
        """
        Pydantic configuration.
        """
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """
    Get settings singleton instance.
    
    Returns:
        Settings: Settings instance.
    """
    return Settings()


def get_oauth_config(provider: str) -> Dict[str, str]:
    """
    Get OAuth configuration for a specific provider.
    
    Args:
        provider: The OAuth provider name.
        
    Returns:
        Dict[str, str]: OAuth configuration for the provider.
    """
    settings = get_settings()
    
    if provider == "sketchfab":
        return {
            "client_id": settings.sketchfab_client_id,
            "client_secret": settings.sketchfab_client_secret,
            "redirect_uri": settings.sketchfab_redirect_uri,
            "authorize_url": "https://sketchfab.com/oauth2/authorize/",
            "token_url": "https://sketchfab.com/oauth2/token/",
            "api_base_url": "https://sketchfab.com/v2/",
        }
    
    # Add more providers here
    
    raise ValueError(f"Unsupported provider: {provider}") 