"""
Main application module for the OAuth API service.
"""
import logging
from typing import Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mangum import Mangum

from app.config.settings import get_settings
from app.routers import oauth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Secure MCP OAuth API",
    description="OAuth API service for multiple providers",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add routers
app.include_router(oauth.router)


@app.get("/")
async def root():
    """
    Root endpoint.
    
    Returns:
        Dict: Service information.
    """
    settings = get_settings()
    return {
        "name": "Secure MCP OAuth API",
        "version": "0.1.0",
        "description": "OAuth API service for multiple providers",
        "docs_url": "/docs",
        "environment": settings.stage
    }


@app.get("/health")
async def health():
    """
    Health check endpoint.
    
    Returns:
        Dict: Health status.
    """
    return {
        "status": "healthy"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler.
    
    Args:
        request: The request that caused the exception.
        exc: The exception.
        
    Returns:
        JSONResponse: Error response.
    """
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc)
        }
    )


# Create Mangum handler for AWS Lambda
handler = Mangum(app) 