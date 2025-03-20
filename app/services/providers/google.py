"""
Google OAuth service implementation.
"""
import json
import time
from typing import Dict, Optional
from urllib.parse import urlencode

import requests
from fastapi import HTTPException, status

from app.config.settings import get_oauth_config, get_settings
from app.models.oauth import OAuthTokenResponse, UserInfo
from app.services.oauth_base import BaseOAuthService


class GoogleOAuthService(BaseOAuthService):
    """
    Google OAuth service implementation.
    """
    
    def __init__(self):
        """
        Initialize the Google OAuth service.
        """
        super().__init__("google")
        self.config = get_oauth_config("google")
        self.settings = get_settings()
    
    def get_authorization_url(self) -> str:
        """
        Get the authorization URL for Google.
        
        Returns:
            str: The authorization URL.
        """
        params = {
            "response_type": "code",
            "client_id": self.config["client_id"],
            "redirect_uri": self.config["redirect_uri"],
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent"
        }
        
        return f"{self.config['authorize_url']}?{urlencode(params)}"
    
    def exchange_code_for_token(self, code: str) -> OAuthTokenResponse:
        """
        Exchange an authorization code for an access token.
        
        Args:
            code: The authorization code.
            
        Returns:
            OAuthTokenResponse: The OAuth token.
        """
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_google_client_id_here" or not self.config["client_id"]:
            return self._get_mock_token()
            
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "redirect_uri": self.config["redirect_uri"]
        }
        
        response = requests.post(self.config["token_url"], data=data)
        
        if response.status_code != 200:
            error_data = response.json() if response.content else {"error": "Unknown error"}
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_data
            )
        
        token_data = response.json()
        return OAuthTokenResponse(
            access_token=token_data["access_token"],
            token_type=token_data["token_type"],
            expires_in=token_data.get("expires_in", 3600),
            refresh_token=token_data.get("refresh_token"),
            scope=token_data.get("scope")
        )
    
    def refresh_token(self, refresh_token: str) -> OAuthTokenResponse:
        """
        Refresh an access token.
        
        Args:
            refresh_token: The refresh token.
            
        Returns:
            OAuthTokenResponse: The new OAuth token.
        """
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_google_client_id_here" or not self.config["client_id"]:
            return self._get_mock_token()
            
        data = {
            "grant_type": "refresh_token",
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "refresh_token": refresh_token
        }
        
        response = requests.post(self.config["token_url"], data=data)
        
        if response.status_code != 200:
            error_data = response.json() if response.content else {"error": "Unknown error"}
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_data
            )
        
        token_data = response.json()
        # Google doesn't return a refresh token in the refresh flow
        return OAuthTokenResponse(
            access_token=token_data["access_token"],
            token_type=token_data["token_type"],
            expires_in=token_data.get("expires_in", 3600),
            refresh_token=refresh_token,  # Reuse the original refresh token
            scope=token_data.get("scope")
        )
    
    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Get user information from Google.
        
        Args:
            access_token: The OAuth access token.
            
        Returns:
            UserInfo: The user information.
        """
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_google_client_id_here" or not self.config["client_id"]:
            return self._get_mock_user_info()
            
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        response = requests.get(f"{self.config['api_base_url']}userinfo", headers=headers)
        
        if response.status_code != 200:
            error_data = response.json() if response.content else {"error": "Unknown error"}
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_data
            )
        
        user_data = response.json()
        
        return UserInfo(
            id=user_data["id"],
            username=user_data.get("name"),
            email=user_data.get("email"),
            profile_url=user_data.get("profile"),
            avatar_url=user_data.get("picture"),
            raw_data=user_data
        )
    
    def _get_mock_token(self) -> OAuthTokenResponse:
        """
        Generate a mock token for testing purposes.
        
        Returns:
            OAuthTokenResponse: A mock OAuth token.
        """
        return OAuthTokenResponse(
            access_token=f"mock_google_access_token_{int(time.time())}",
            token_type="Bearer",
            expires_in=3600,
            refresh_token=f"mock_google_refresh_token_{int(time.time())}",
            scope="openid email profile"
        )
    
    def _get_mock_user_info(self) -> UserInfo:
        """
        Generate mock user information for testing purposes.
        
        Returns:
            UserInfo: Mock user information.
        """
        return UserInfo(
            id="12345678901234567890",
            username="Mock Google User",
            email="mock.google.user@example.com",
            profile_url="https://profiles.google.com/mock.user",
            avatar_url="https://lh3.googleusercontent.com/a-/mock-google-avatar",
            raw_data={
                "id": "12345678901234567890",
                "name": "Mock Google User",
                "given_name": "Mock",
                "family_name": "User",
                "email": "mock.google.user@example.com",
                "verified_email": True,
                "picture": "https://lh3.googleusercontent.com/a-/mock-google-avatar",
                "locale": "en"
            }
        ) 