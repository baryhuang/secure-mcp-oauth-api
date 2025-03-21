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
    stage: str = os.getenv("STAGE", "dev")
    
    # Development mode flag - set to True to skip database operations
    dev_mode: bool = os.getenv("DEV_MODE", "false").lower() == "true"

    # Sketchfab OAuth configuration
    sketchfab_client_id: str = os.getenv("SKETCHFAB_CLIENT_ID", "")
    sketchfab_client_secret: str = os.getenv("SKETCHFAB_CLIENT_SECRET", "")
    sketchfab_redirect_uri: str = os.getenv("SKETCHFAB_REDIRECT_URI", "")
    
    # Google OAuth configuration
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    google_redirect_uri: str = os.getenv("GOOGLE_REDIRECT_URI", "")
    
    # Twitter OAuth configuration
    twitter_client_id: str = os.getenv("TWITTER_CLIENT_ID", "")
    twitter_client_secret: str = os.getenv("TWITTER_CLIENT_SECRET", "")
    twitter_redirect_uri: str = os.getenv("TWITTER_REDIRECT_URI", "")
    
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
    elif provider == "google":
        return {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": settings.google_redirect_uri,
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "api_base_url": "https://www.googleapis.com/oauth2/v1/",
        }
    elif provider == "twitter":
        return {
            "client_id": settings.twitter_client_id,
            "client_secret": settings.twitter_client_secret,
            "redirect_uri": settings.twitter_redirect_uri,
            "authorize_url": "https://twitter.com/i/oauth2/authorize",
            "token_url": "https://api.twitter.com/2/oauth2/token",
            "api_base_url": "https://api.twitter.com/2/users/me",
            "scopes": "tweet.read users.read offline.access",
        }
    
    raise ValueError(f"Unsupported provider: {provider}") 