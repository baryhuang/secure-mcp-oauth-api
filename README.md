# Secure MCP OAuth API

An extensible OAuth API service that supports multiple OAuth providers, starting with Sketchfab.

## Setup

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - On Windows: `venv\Scripts\activate`
   - On macOS/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and fill in the required values
6. Run locally: `uvicorn app.main:app --reload`

## Deployment

Deploy to AWS using the Serverless Application Model (SAM):

```bash
sam build
sam deploy --guided
```

## Adding a New OAuth Provider

1. Add provider credentials to `.env`
2. Create a new provider service in `app/services/providers/`
3. Register the provider in `app/config/providers.py`

## API Endpoints

- `GET /api/oauth/authorize/{provider}` - Initiate OAuth flow
- `GET /api/oauth/callback/{provider}` - OAuth callback endpoint
- `POST /api/oauth/refresh/{provider}` - Refresh access token
- `GET /api/oauth/me/{provider}` - Get authenticated user information