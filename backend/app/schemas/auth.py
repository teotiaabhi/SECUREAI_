from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from uuid import UUID
from datetime import datetime


class GoogleAuthRequest(BaseModel):
    token: str = Field(..., description="Google OAuth ID token")


class GitHubAuthRequest(BaseModel):
    code: str = Field(..., description="GitHub OAuth authorization code")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: UUID
    email: str
    name: str
    provider: str
    avatar_url: Optional[str] = None
    created_at: datetime
    role: str = "user"
    status: str = "active"
    tier: str = "free"
    is_paid: bool = False
    github_connected: bool = False

    model_config = {"from_attributes": True}


class RefreshTokenRequest(BaseModel):
    refresh_token: str
