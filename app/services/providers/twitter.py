"""
Twitter OAuth service implementation.
"""
import base64
import hashlib
import json
import os
import re
import time
from typing import Dict, Optional
from urllib.parse import urlencode

import requests
from fastapi import HTTPException, Request, status
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError

from app.config.settings import get_oauth_config, get_settings
from app.models.oauth import OAuthTokenResponse, UserInfo
from app.services.oauth_base import BaseOAuthService


class TwitterOAuthService(BaseOAuthService):
    """
    Twitter OAuth service implementation.
    """
    
    def __init__(self):
        """
        Initialize the Twitter OAuth service.
        """
        super().__init__("twitter")
        self.config = get_oauth_config("twitter")
        self.settings = get_settings()
        
        # Store code verifiers in memory (keyed by state)
        self._code_verifiers = {}
    
    def generate_code_verifier(self) -> str:
        """Generate a code verifier for PKCE."""
        code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode('utf-8')
        return re.sub('[^a-zA-Z0-9]+', '', code_verifier)
    
    def generate_code_challenge(self, code_verifier: str) -> str:
        """Generate a code challenge from the code verifier."""
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')
    
    def get_authorization_url(self) -> str:
        """
        Get the authorization URL for Twitter.
        
        Returns:
            str: The authorization URL.
        """
        # Generate PKCE code verifier
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)
        
        # Create OAuth2Session
        twitter = OAuth2Session(
            self.config["client_id"],
            redirect_uri=self.config["redirect_uri"],
            scope=self.config["scopes"].split()
        )
        
        # Get authorization URL
        authorization_url, state = twitter.authorization_url(
            self.config["authorize_url"],
            code_challenge=code_challenge,
            code_challenge_method="S256"
        )
        
        # Store code verifier for later use
        self._code_verifiers[state] = code_verifier
        
        return authorization_url
    
    def exchange_code_for_token(self, code: str, code_verifier: Optional[str] = None, state: Optional[str] = None) -> OAuthTokenResponse:
        """
        Exchange an authorization code for an access token.
        
        Args:
            code: The authorization code.
            code_verifier: Optional PKCE code verifier.
            state: Optional state parameter from the callback.
            
        Returns:
            OAuthTokenResponse: The OAuth token.
        """
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_twitter_client_id" or not self.config["client_id"]:
            return self._get_mock_token()
        
        # Get code verifier from storage if not provided
        if not code_verifier and state and state in self._code_verifiers:
            code_verifier = self._code_verifiers.pop(state)
        
        if not code_verifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_request", "error_description": "Missing code_verifier"}
            )
        
        try:
            # Create OAuth2Session
            twitter = OAuth2Session(
                self.config["client_id"],
                redirect_uri=self.config["redirect_uri"]
            )
            
            # Exchange code for token
            token = twitter.fetch_token(
                self.config["token_url"],
                client_secret=self.config["client_secret"],
                code=code,
                code_verifier=code_verifier
            )
            
            # Convert to OAuthTokenResponse
            # Handle scope being a list by joining it with spaces if needed
            scope = token.get("scope")
            if isinstance(scope, list):
                scope = " ".join(scope)
                
            return OAuthTokenResponse(
                access_token=token["access_token"],
                token_type=token["token_type"],
                expires_in=token.get("expires_in", 7200),
                refresh_token=token.get("refresh_token"),
                scope=scope
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
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
        if self.config["client_id"] == "your_twitter_client_id" or not self.config["client_id"]:
            return self._get_mock_token()
        
        try:
            # Create OAuth2Session with current token
            twitter = OAuth2Session(
                self.config["client_id"],
                token={"refresh_token": refresh_token}
            )
            
            # Refresh the token
            token = twitter.refresh_token(
                self.config["token_url"],
                refresh_token=refresh_token,
                client_id=self.config["client_id"],
                client_secret=self.config["client_secret"]
            )
            
            # Convert to OAuthTokenResponse
            # Handle scope being a list by joining it with spaces if needed
            scope = token.get("scope")
            if isinstance(scope, list):
                scope = " ".join(scope)
                
            return OAuthTokenResponse(
                access_token=token["access_token"],
                token_type=token["token_type"],
                expires_in=token.get("expires_in", 7200),
                refresh_token=token.get("refresh_token", refresh_token),  # Reuse if not returned
                scope=scope
            )
        except (InvalidGrantError, TokenExpiredError, Exception) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    def get_oauth_session(self, token_dict: Dict) -> OAuth2Session:
        """
        Get an OAuth2Session with the provided token.
        
        Args:
            token_dict: The token dictionary.
            
        Returns:
            OAuth2Session: The OAuth2Session.
        """
        return OAuth2Session(
            self.config["client_id"],
            token=token_dict
        )
    
    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Get user information from Twitter.
        
        Args:
            access_token: The OAuth access token.
            
        Returns:
            UserInfo: The user information.
        """
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_twitter_client_id" or not self.config["client_id"]:
            return self._get_mock_user_info()
        
        try:
            # Create OAuth2Session with access token
            token = {"access_token": access_token, "token_type": "Bearer"}
            twitter = self.get_oauth_session(token)
            
            # Get user info
            response = twitter.get(
                self.config["api_base_url"],
                params={"user.fields": "id,name,username,profile_image_url"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=response.json() if response.content else {"error": "Unknown error"}
                )
            
            user_data = response.json().get("data", {})
            
            return UserInfo(
                id=user_data["id"],
                username=user_data["username"],
                email=None,  # Twitter API v2 requires additional scope for email
                profile_url=f"https://twitter.com/{user_data['username']}",
                avatar_url=user_data.get("profile_image_url"),
                raw_data=user_data
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    def _get_mock_token(self) -> OAuthTokenResponse:
        """
        Generate a mock token for testing purposes.
        
        Returns:
            OAuthTokenResponse: A mock OAuth token.
        """
        return OAuthTokenResponse(
            access_token=f"mock_twitter_access_token_{int(time.time())}",
            token_type="Bearer",
            expires_in=7200,
            refresh_token=f"mock_twitter_refresh_token_{int(time.time())}",
            scope="tweet.read users.read offline.access"
        )
    
    def _get_mock_user_info(self) -> UserInfo:
        """
        Generate mock user information for testing purposes.
        
        Returns:
            UserInfo: Mock user information.
        """
        return UserInfo(
            id="1234567890",
            username="mock_twitter_user",
            email=None,
            profile_url="https://twitter.com/mock_twitter_user",
            avatar_url="https://pbs.twimg.com/profile_images/mock_image.jpg",
            raw_data={
                "id": "1234567890",
                "name": "Mock Twitter User",
                "username": "mock_twitter_user",
                "profile_image_url": "https://pbs.twimg.com/profile_images/mock_image.jpg"
            }
        ) 