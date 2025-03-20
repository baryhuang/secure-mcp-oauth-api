"""
OAuth router module for the API service.
"""
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from app.config.providers import get_supported_providers
from app.config.settings import get_settings
from app.models.oauth import OAuthRefreshRequest, OAuthTokenResponse, UserInfo
from app.services.oauth_factory import create_oauth_service


router = APIRouter(prefix="/api/oauth")


@router.get("/authorize/{provider}")
async def authorize(provider: str):
    """
    Initiate the OAuth flow by redirecting to the provider's authorization page.
    
    Args:
        provider: The OAuth provider.
        
    Returns:
        RedirectResponse: Redirect to the provider's authorization page.
    """
    if provider not in get_supported_providers():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}"
        )
    
    service = create_oauth_service(provider)
    authorization_url = service.get_authorization_url()
    
    return RedirectResponse(authorization_url)


@router.get("/callback/{provider}")
async def callback(
    provider: str,
    code: str = Query(...),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None)
):
    """
    Handle the OAuth callback from the provider.
    
    Args:
        provider: The OAuth provider.
        code: The authorization code.
        state: Optional state parameter for CSRF protection.
        error: Optional error parameter from the provider.
        error_description: Optional error description from the provider.
        
    Returns:
        Dict: The OAuth token response.
    """
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": error,
                "error_description": error_description
            }
        )
    
    service = create_oauth_service(provider)
    token = service.exchange_code_for_token(code)
    
    # In a real application, you would identify the user here
    # and store the token associated with the user.
    # For simplicity, we're using a fixed user ID in this example.
    user_id = "user123"
    service.store_token(user_id, token)
    
    # For testing purposes, return more information
    return {
        "message": f"Successfully authenticated with {provider}",
        "provider": provider,
        "user_id": user_id,
        "token_info": {
            "access_token": token.access_token,
            "token_type": token.token_type,
            "expires_in": token.expires_in,
            "refresh_token": token.refresh_token,
            "scope": token.scope
        }
    }


@router.post("/refresh/{provider}")
async def refresh_token(
    provider: str,
    refresh_request: OAuthRefreshRequest
):
    """
    Refresh an OAuth access token.
    
    Args:
        provider: The OAuth provider.
        refresh_request: The refresh token request.
        
    Returns:
        Dict: The new OAuth token response.
    """
    service = create_oauth_service(provider)
    
    # Check if the user has a token for this provider
    existing_token = service.get_token(refresh_request.user_id)
    if not existing_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No token found for user {refresh_request.user_id} and provider {provider}"
        )
    
    # Refresh the token
    token = service.refresh_token(refresh_request.refresh_token)
    
    # Store the new token
    service.store_token(refresh_request.user_id, token)
    
    return {
        "message": "Token refreshed successfully",
        "access_token": token.access_token,
        "token_type": token.token_type,
        "expires_in": token.expires_in,
        "provider": provider,
        "user_id": refresh_request.user_id
    }


@router.get("/me/{provider}")
async def get_user_info(
    provider: str,
    user_id: str
):
    """
    Get user information from the OAuth provider.
    
    Args:
        provider: The OAuth provider.
        user_id: The user ID.
        
    Returns:
        UserInfo: The user information.
    """
    service = create_oauth_service(provider)
    
    # Get the user's token
    token = service.get_token(user_id)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No token found for user {user_id} and provider {provider}"
        )
    
    # Get the user information
    user_info = service.get_user_info(token.access_token)
    
    return user_info


@router.get("/providers")
async def get_providers():
    """
    Get the list of supported OAuth providers.
    
    Returns:
        Dict: The list of supported providers.
    """
    return {
        "providers": get_supported_providers()
    } 