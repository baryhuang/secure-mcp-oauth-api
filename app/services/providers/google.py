"""
Google OAuth service implementation.

This service implements OAuth 2.0 authentication for Google. It handles:
1. Generating the authorization URL
2. Exchanging the authorization code for access and refresh tokens
3. Refreshing expired access tokens

Note: User info retrieval is skipped for Google OAuth to avoid potential issues with the userinfo endpoint.
Instead, the service returns only the tokens which can be used directly by the client application.
"""
import json
import logging
import time
from typing import Dict, Optional
from urllib.parse import urlencode

import requests
from fastapi import HTTPException, status

from app.config.settings import get_oauth_config, get_settings
from app.models.oauth import OAuthTokenResponse, UserInfo
from app.services.oauth_base import BaseOAuthService

# Configure logger
logger = logging.getLogger(__name__)

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
        logger.info(f"Initialized GoogleOAuthService with client_id: {self.config['client_id'][:5]}*** and redirect_uri: {self.config['redirect_uri']}")
    
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
        
        authorization_url = f"{self.config['authorize_url']}?{urlencode(params)}"
        logger.info(f"Generated Google authorization URL with params: {params}")
        logger.debug(f"Full authorization URL: {authorization_url}")
        return authorization_url
    
    def exchange_code_for_token(self, code: str, code_verifier: Optional[str] = None, state: Optional[str] = None) -> OAuthTokenResponse:
        """
        Exchange an authorization code for an access token.
        
        Args:
            code: The authorization code.
            code_verifier: Optional PKCE code verifier (not used for Google).
            state: Optional state parameter from the callback (not used for Google).
            
        Returns:
            OAuthTokenResponse: The OAuth token.
        """
        logger.info("Exchanging code for token")
        logger.debug(f"Authorization code: {code[:5]}*** (partial)")
        
        # Note: Google doesn't require PKCE, so we ignore code_verifier and state
        if code_verifier:
            logger.warning("Code verifier provided but Google doesn't use PKCE - ignoring this parameter")
        if state:
            logger.debug(f"State parameter provided: {state} - Google doesn't use this for token exchange")
        
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_google_client_id_here" or not self.config["client_id"]:
            logger.warning("Using placeholder credentials, returning mock token")
            return self._get_mock_token()
            
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "redirect_uri": self.config["redirect_uri"]
        }
        
        logger.debug(f"Token request data: {json.dumps({k: v if k != 'client_secret' else '***' for k, v in data.items()})}")
        logger.debug(f"Token URL: {self.config['token_url']}")
        logger.debug(f"Request method: POST")
        
        try:
            response = requests.post(self.config["token_url"], data=data)
            logger.debug(f"Token response status: {response.status_code}")
            logger.debug(f"Token response headers: {dict(response.headers)}")
            
            if response.content:
                logger.debug(f"Token response content: {response.text[:1000]}")
            
            if response.status_code != 200:
                error_data = response.json() if response.content else {"error": "Unknown error"}
                logger.error(f"Failed to exchange code for token: {error_data}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_data
                )
            
            token_data = response.json()
            
            # Validate token structure
            if "access_token" not in token_data:
                logger.error("Invalid token response: missing access_token")
                logger.debug(f"Full token data: {token_data}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Invalid token response from Google: missing access_token"
                )
                
            # Log token structure (safely)
            token_info = {
                "access_token_length": len(token_data.get("access_token", "")),
                "token_type": token_data.get("token_type"),
                "expires_in": token_data.get("expires_in"),
                "has_refresh_token": "refresh_token" in token_data,
                "scope": token_data.get("scope")
            }
            logger.debug(f"Token structure: {token_info}")
            
            # Handle scope being a list by joining it with spaces if needed
            scope = token_data.get("scope")
            if isinstance(scope, list):
                scope = " ".join(scope)
                
            logger.info(f"Successfully exchanged code for token, expires in: {token_data.get('expires_in')} seconds")
            
            # Create token response
            token_response = OAuthTokenResponse(
                access_token=token_data["access_token"],
                token_type=token_data["token_type"],
                expires_in=token_data.get("expires_in", 3600),
                refresh_token=token_data.get("refresh_token"),
                scope=scope
            )
            
            # Verify token response
            if not token_response.access_token:
                logger.error("Empty access token in token response")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Empty access token in response"
                )
            
            logger.debug(f"Created OAuthTokenResponse with token_type: {token_response.token_type}, access_token length: {len(token_response.access_token)}")
            
            return token_response
        except requests.RequestException as e:
            logger.error(f"Request exception during token exchange: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error during token exchange: {str(e)}"
            )
    
    def refresh_token(self, refresh_token: str) -> OAuthTokenResponse:
        """
        Refresh an access token.
        
        Args:
            refresh_token: The refresh token.
            
        Returns:
            OAuthTokenResponse: The new OAuth token.
        """
        logger.info("Refreshing Google access token")
        
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_google_client_id_here" or not self.config["client_id"]:
            logger.warning("Using placeholder credentials, returning mock token")
            return self._get_mock_token()
            
        data = {
            "grant_type": "refresh_token",
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "refresh_token": refresh_token
        }
        
        logger.debug(f"Refresh token request data: {json.dumps({k: v if k not in ['client_secret', 'refresh_token'] else '***' for k, v in data.items()})}")
        
        try:
            response = requests.post(self.config["token_url"], data=data)
            logger.debug(f"Refresh token response status: {response.status_code}")
            
            if response.status_code != 200:
                error_data = response.json() if response.content else {"error": "Unknown error"}
                logger.error(f"Failed to refresh token: {error_data}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_data
                )
            
            token_data = response.json()
            # Handle scope being a list by joining it with spaces if needed
            scope = token_data.get("scope")
            if isinstance(scope, list):
                scope = " ".join(scope)
                
            logger.info(f"Successfully refreshed token, expires in: {token_data.get('expires_in')} seconds")
            
            # Google doesn't return a refresh token in the refresh flow
            return OAuthTokenResponse(
                access_token=token_data["access_token"],
                token_type=token_data["token_type"],
                expires_in=token_data.get("expires_in", 3600),
                refresh_token=refresh_token,  # Reuse the original refresh token
                scope=scope
            )
        except requests.RequestException as e:
            logger.error(f"Request exception during token refresh: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error during token refresh: {str(e)}"
            )
    
    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Get user information from Google.
        
        Args:
            access_token: The OAuth access token.
            
        Returns:
            UserInfo: The user information.
        """
        logger.info("Getting user info from Google")
        logger.debug(f"Using access token: {access_token[:5]}*** (partial)")
        
        # If using placeholder credentials, return mock data
        if self.config["client_id"] == "your_google_client_id_here" or not self.config["client_id"]:
            logger.warning("Using placeholder credentials, returning mock user info")
            return self._get_mock_user_info()
            
        # Make sure to use the correct authorization header format
        # The header should be in the format "Bearer <token>"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        logger.debug(f"User info request headers: {json.dumps({k: v[:10] + '...' if k == 'Authorization' else v for k, v in headers.items()})}")
        
        # Use the correct URL for Google's userinfo endpoint
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        logger.debug(f"User info request URL: {userinfo_url}")
        
        try:
            # Log the full request for debugging
            logger.debug(f"Making GET request to {userinfo_url} with Authorization: Bearer {access_token[:5]}***")
            
            # Make request to Google's userinfo endpoint
            response = requests.get(userinfo_url, headers=headers)
            logger.debug(f"User info response status: {response.status_code}")
            logger.debug(f"User info response headers: {dict(response.headers)}")
            
            if response.content:
                logger.debug(f"User info response content: {response.text[:1000]}")
            
            if response.status_code != 200:
                error_data = response.json() if response.content else {"error": "Unknown error"}
                logger.error(f"Failed to get user info: {error_data}")
                
                # Add some additional debugging info
                if response.status_code == 401:
                    logger.error("Authentication failed: Token may be invalid, expired, or malformed")
                    logger.debug(f"Original access token: {access_token[:10]}...")
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_data
                )
            
            user_data = response.json()
            logger.info(f"Successfully retrieved user info for user ID: {user_data.get('id')}")
            
            return UserInfo(
                id=user_data["id"],
                username=user_data.get("name"),
                email=user_data.get("email"),
                profile_url=user_data.get("profile"),
                avatar_url=user_data.get("picture"),
                raw_data=user_data
            )
        except requests.RequestException as e:
            logger.error(f"Request exception during user info retrieval: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error retrieving user info: {str(e)}"
            )
    
    def _get_mock_token(self) -> OAuthTokenResponse:
        """
        Generate a mock token for testing purposes.
        
        Returns:
            OAuthTokenResponse: A mock OAuth token.
        """
        logger.debug("Generating mock Google token")
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
        logger.debug("Generating mock Google user info")
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