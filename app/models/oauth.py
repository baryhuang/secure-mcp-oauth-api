"""
OAuth models for the API service.
"""
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, Field


class OAuthToken(BaseModel):
    """
    OAuth token model for storing in DynamoDB.
    """
    user_id: str
    provider: str
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    expires_at: Optional[int] = None  # Unix timestamp for TTL

    def model_dump(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Convert model to dictionary for DynamoDB.
        
        Returns:
            Dict: Dictionary representation of the model.
        """
        # Filter out None values
        return {k: v for k, v in super().model_dump(**kwargs).items() if v is not None}


class OAuthTokenResponse(BaseModel):
    """
    OAuth token response model for API responses.
    """
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class OAuthRefreshRequest(BaseModel):
    """
    OAuth refresh token request model.
    """
    user_id: str
    refresh_token: str


class OAuthError(BaseModel):
    """
    OAuth error response model.
    """
    error: str
    error_description: Optional[str] = None


class UserInfo(BaseModel):
    """
    User information model returned by the provider.
    """
    id: str
    username: str
    email: Optional[str] = None
    profile_url: Optional[str] = None
    avatar_url: Optional[str] = None
    raw_data: Dict = Field(default_factory=dict) 