"""
Base OAuth service for provider-specific implementations.
"""
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Union

import requests
from fastapi import HTTPException, status

from app.config.settings import get_settings
from app.models.oauth import OAuthToken, OAuthTokenResponse, UserInfo


class BaseOAuthService(ABC):
    """
    Base OAuth service with common functionality.
    """
    
    def __init__(self, provider: str):
        """
        Initialize the OAuth service.
        
        Args:
            provider: The OAuth provider name.
        """
        self.provider = provider
        self.settings = get_settings()
        
        # In-memory token storage (for development/testing)
        self._tokens = {}
    
    @abstractmethod
    def get_authorization_url(self) -> str:
        """
        Get the authorization URL for the OAuth provider.
        
        Returns:
            str: The authorization URL.
        """
        pass
    
    @abstractmethod
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
        pass
    
    @abstractmethod
    def refresh_token(self, refresh_token: str) -> OAuthTokenResponse:
        """
        Refresh an access token.
        
        Args:
            refresh_token: The refresh token.
            
        Returns:
            OAuthTokenResponse: The new OAuth token.
        """
        pass
    
    @abstractmethod
    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Get user information from the OAuth provider.
        
        Args:
            access_token: The OAuth access token.
            
        Returns:
            UserInfo: The user information.
        """
        pass
    
    def store_token(self, user_id: str, token: OAuthTokenResponse) -> None:
        """
        Store an OAuth token in memory (for development/testing).
        
        Args:
            user_id: The user ID.
            token: The OAuth token.
        """
        # Calculate TTL for token expiration
        expires_at = int(time.time()) + token.expires_in
        
        oauth_token = OAuthToken(
            user_id=user_id,
            provider=self.provider,
            access_token=token.access_token,
            token_type=token.token_type,
            expires_in=token.expires_in,
            refresh_token=token.refresh_token,
            scope=token.scope,
            expires_at=expires_at
        )
        
        # Store in memory
        key = f"{user_id}:{self.provider}"
        self._tokens[key] = oauth_token
    
    def get_token(self, user_id: str) -> Optional[OAuthToken]:
        """
        Get an OAuth token from memory. If token is expired, return None.
        
        Args:
            user_id: The user ID.
            
        Returns:
            Optional[OAuthToken]: The OAuth token if found and valid, None otherwise.
        """
        key = f"{user_id}:{self.provider}"
        token = self._tokens.get(key)
        
        # Check if token exists and is not expired or about to expire (within 60 seconds)
        if token and token.expires_at:
            now = time.time()
            if token.expires_at - now < 60:
                # Token is expired or about to expire, try to refresh
                if token.refresh_token:
                    try:
                        new_token = self.refresh_token(token.refresh_token)
                        # Store the new token
                        self.store_token(user_id, new_token)
                        # Return the newly stored token
                        return self._tokens.get(key)
                    except Exception:
                        # If refresh fails, delete the token
                        self.delete_token(user_id)
                        return None
                else:
                    # No refresh token, delete the token
                    self.delete_token(user_id)
                    return None
        
        return token
    
    def delete_token(self, user_id: str) -> None:
        """
        Delete an OAuth token from memory.
        
        Args:
            user_id: The user ID.
        """
        key = f"{user_id}:{self.provider}"
        if key in self._tokens:
            del self._tokens[key]
    
    def handle_request_error(
        self, 
        response: requests.Response
    ) -> Tuple[int, Dict]:
        """
        Handle an error response from the OAuth provider.
        
        Args:
            response: The response from the OAuth provider.
            
        Returns:
            Tuple[int, Dict]: The error status code and response.
        """
        status_code = response.status_code
        
        try:
            error_data = response.json()
        except ValueError:
            error_data = {"error": "unknown_error", "error_description": response.text}
        
        return status_code, error_data 