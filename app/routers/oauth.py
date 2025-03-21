"""
OAuth router module for the API service.
"""
import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from fastapi.responses import RedirectResponse

from app.config.providers import get_supported_providers
from app.config.settings import get_settings
from app.models.oauth import OAuthRefreshRequest, OAuthTokenResponse, UserInfo
from app.services.oauth_factory import create_oauth_service

# Configure logger
logger = logging.getLogger(__name__)

# Define which providers require PKCE
PKCE_PROVIDERS = ["twitter"]

router = APIRouter(prefix="/api/oauth")


@router.get("/authorize/{provider}")
async def authorize(provider: str, request: Request):
    """
    Initiate the OAuth flow by redirecting to the provider's authorization page.
    
    Args:
        provider: The OAuth provider.
        request: The FastAPI request object.
        
    Returns:
        RedirectResponse: Redirect to the provider's authorization page.
    """
    logger.info(f"Initiating OAuth flow for provider: {provider}")
    
    if provider not in get_supported_providers():
        logger.warning(f"Unsupported provider requested: {provider}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}"
        )
    
    service = create_oauth_service(provider)
    authorization_url = service.get_authorization_url()
    
    logger.info(f"Redirecting to {provider} authorization URL")
    return RedirectResponse(authorization_url)


@router.get("/callback/{provider}")
async def callback(
    provider: str,
    request: Request,
    code: str = Query(...),
    state: Optional[str] = Query(None),
    code_verifier: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None)
):
    """
    Handle the OAuth callback from the provider.
    
    Args:
        provider: The OAuth provider.
        request: The FastAPI request object.
        code: The authorization code.
        state: Optional state parameter from the provider.
        code_verifier: Optional PKCE code verifier.
        error: Optional error parameter from the provider.
        error_description: Optional error description from the provider.
        
    Returns:
        Dict: The OAuth token response.
    """
    logger.info(f"Handling OAuth callback for provider: {provider}")
    logger.debug(f"Callback query params: code={code[:5]}***")
    logger.debug(f"Request headers: {dict(request.headers)}")
    
    # Log optional parameters if they exist
    if state:
        logger.debug(f"State parameter present: {state[:5]}***")
    if code_verifier:
        logger.debug(f"Code verifier present: {code_verifier[:5]}***")
    
    if error:
        logger.error(f"OAuth error from provider: {error}, description: {error_description}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": error,
                "error_description": error_description
            }
        )
    
    if provider not in get_supported_providers():
        logger.warning(f"Unsupported provider in callback: {provider}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}"
        )
    
    logger.info(f"Creating OAuth service for provider: {provider}")
    service = create_oauth_service(provider)
    
    try:
        # Exchange the authorization code for an access token
        token = service.exchange_code_for_token(code, code_verifier, state)
        logger.info(f"Successfully obtained token for provider: {provider}")
        
        # For Google, skip user info retrieval and just return the tokens
        if provider == "google":
            return {
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "refresh_token": token.refresh_token,
                "scope": token.scope
            }
        
        # Get user information using the access token
        user_info = service.get_user_info(token.access_token)
        logger.info(f"Successfully retrieved user info for provider: {provider}")
        
        # Store the token with the user's provider ID
        logger.info(f"Storing token for user ID: {user_info.id}")
        service.store_token(user_info.id, token)
        
        logger.info(f"OAuth flow successfully completed for user: {user_info.username}")
        
        # Prepare sanitized response data for logging (without full tokens)
        log_response = {
            "success": True,
            "user_info": {
                "id": user_info.id,
                "username": user_info.username,
                "email": user_info.email,
                "profile_url": user_info.profile_url,
                "avatar_url": user_info.avatar_url
            },
            "token_info": {
                "access_token": f"{token.access_token[:10]}..." if token.access_token else None,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "refresh_token": f"{token.refresh_token[:10]}..." if token.refresh_token else None,
                "scope": token.scope
            }
        }
        logger.debug(f"Callback response data: {log_response}")
        
        # Return the actual data without truncated tokens
        return {
            "success": True,
            "user_info": {
                "id": user_info.id,
                "username": user_info.username,
                "email": user_info.email,
                "profile_url": user_info.profile_url,
                "avatar_url": user_info.avatar_url
            },
            "token_info": {
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "refresh_token": token.refresh_token,
                "scope": token.scope
            }
        }
        
    except Exception as e:
        logger.error(f"Exception during OAuth callback: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


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
        "success": True,
        "access_token": token.access_token,
        "token_type": token.token_type,
        "expires_in": token.expires_in,
        "refresh_token": token.refresh_token,
        "scope": token.scope
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