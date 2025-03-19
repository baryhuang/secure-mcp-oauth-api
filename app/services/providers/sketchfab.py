"""
Sketchfab OAuth service implementation.
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


class SketchfabOAuthService(BaseOAuthService):
    """
    Sketchfab OAuth service implementation.
    """
    
    def __init__(self):
        """
        Initialize the Sketchfab OAuth service.
        """
        super().__init__("sketchfab")
        self.config = get_oauth_config("sketchfab")
        self.settings = get_settings()
    
    def get_authorization_url(self) -> str:
        """
        Get the authorization URL for Sketchfab.
        
        Returns:
            str: The authorization URL.
        """
        params = {
            "response_type": "code",
            "client_id": self.config["client_id"],
            "redirect_uri": self.config["redirect_uri"]
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
        if self.config["client_id"] == "your_sketchfab_client_id" or not self.config["client_id"]:
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
            status_code, error_data = self.handle_request_error(response)
            raise HTTPException(
                status_code=status_code,
                detail=error_data
            )
        
        token_data = response.json()
        return OAuthTokenResponse(
            access_token=token_data["access_token"],
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"],
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
        if self.config["client_id"] == "your_sketchfab_client_id" or not self.config["client_id"]:
            return self._get_mock_token()
            
        data = {
            "grant_type": "refresh_token",
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "refresh_token": refresh_token
        }
        
        response = requests.post(self.config["token_url"], data=data)
        
        if response.status_code != 200:
            status_code, error_data = self.handle_request_error(response)
            raise HTTPException(
                status_code=status_code,
                detail=error_data
            )
        
        token_data = response.json()
        return OAuthTokenResponse(
            access_token=token_data["access_token"],
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"],
            refresh_token=token_data.get("refresh_token"),
            scope=token_data.get("scope")
        )
    
    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Get user information from Sketchfab.
        
        Args:
            access_token: The OAuth access token.
            
        Returns:
            UserInfo: The user information.
        """
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_sketchfab_client_id" or not self.config["client_id"]:
            return self._get_mock_user_info()
            
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        response = requests.get(f"{self.config['api_base_url']}users/me", headers=headers)
        
        if response.status_code != 200:
            status_code, error_data = self.handle_request_error(response)
            raise HTTPException(
                status_code=status_code,
                detail=error_data
            )
        
        user_data = response.json()
        
        return UserInfo(
            id=user_data["uid"],
            username=user_data["username"],
            email=user_data.get("email"),
            profile_url=user_data.get("profileUrl"),
            avatar_url=user_data.get("avatar", {}).get("url"),
            raw_data=user_data
        )
    
    def _get_mock_token(self) -> OAuthTokenResponse:
        """
        Generate a mock token for testing purposes.
        
        Returns:
            OAuthTokenResponse: A mock OAuth token.
        """
        return OAuthTokenResponse(
            access_token=f"mock_access_token_{int(time.time())}",
            token_type="Bearer",
            expires_in=3600,
            refresh_token=f"mock_refresh_token_{int(time.time())}",
            scope="read write"
        )
    
    def _get_mock_user_info(self) -> UserInfo:
        """
        Generate mock user information for testing purposes.
        
        Returns:
            UserInfo: Mock user information.
        """
        return UserInfo(
            id="mock_user_123",
            username="mock_sketchfab_user",
            email="mock_user@example.com",
            profile_url="https://sketchfab.com/mock_user",
            avatar_url="https://sketchfab.com/avatars/mock_user.jpg",
            raw_data={
                "uid": "mock_user_123",
                "username": "mock_sketchfab_user",
                "email": "mock_user@example.com",
                "profileUrl": "https://sketchfab.com/mock_user",
                "avatar": {
                    "url": "https://sketchfab.com/avatars/mock_user.jpg"
                }
            }
        ) 