"""
Repository API Routes
"""

from fastapi import APIRouter, Depends, HTTPException
from app.auth.jwt_handler import get_current_user
from app.auth.oauth_github import fetch_github_repos
from app.models.user import User
from app.core.logging import get_logger

logger = get_logger("api_repos")
router = APIRouter(prefix="/repos", tags=["Repositories"])


@router.get("")
async def list_repos(user: User = Depends(get_current_user)):
    """List user's GitHub repositories."""
    if not user.github_token_encrypted:
        raise HTTPException(status_code=400, detail="No GitHub account connected")
    try:
        repos = await fetch_github_repos(user)
        return {"repos": repos}
    except Exception as e:
        logger.error("repo_list_error", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to fetch repositories")
