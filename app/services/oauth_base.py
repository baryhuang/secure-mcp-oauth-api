"""
Base OAuth service for provider-specific implementations.
"""
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Union

import boto3
import requests
from botocore.exceptions import ClientError
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
        self.dynamodb = boto3.resource(
            'dynamodb', 
            region_name=self.settings.aws_region
        )
        self.table = self.dynamodb.Table(self.settings.dynamodb_table)
    
    @abstractmethod
    def get_authorization_url(self) -> str:
        """
        Get the authorization URL for the OAuth provider.
        
        Returns:
            str: The authorization URL.
        """
        pass
    
    @abstractmethod
    def exchange_code_for_token(self, code: str) -> OAuthTokenResponse:
        """
        Exchange an authorization code for an access token.
        
        Args:
            code: The authorization code.
            
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
        Store an OAuth token in DynamoDB.
        
        Args:
            user_id: The user ID.
            token: The OAuth token.
        """
        # Calculate TTL for automatic token expiration
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
        
        try:
            self.table.put_item(Item=oauth_token.model_dump())
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to store token: {str(e)}"
            )
    
    def get_token(self, user_id: str) -> Optional[OAuthToken]:
        """
        Get an OAuth token from DynamoDB.
        
        Args:
            user_id: The user ID.
            
        Returns:
            Optional[OAuthToken]: The OAuth token if found, None otherwise.
        """
        try:
            response = self.table.get_item(
                Key={
                    'user_id': user_id,
                    'provider': self.provider
                }
            )
            
            if 'Item' in response:
                return OAuthToken(**response['Item'])
            
            return None
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve token: {str(e)}"
            )
    
    def delete_token(self, user_id: str) -> None:
        """
        Delete an OAuth token from DynamoDB.
        
        Args:
            user_id: The user ID.
        """
        try:
            self.table.delete_item(
                Key={
                    'user_id': user_id,
                    'provider': self.provider
                }
            )
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete token: {str(e)}"
            )
    
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