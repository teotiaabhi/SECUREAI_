import httpx
from typing import List
from urllib.parse import urlencode
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import get_settings
from app.core.security import encrypt_token, decrypt_token
from app.core.logging import get_logger
from app.models.user import User

logger = get_logger("oauth_github")

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"


def build_github_auth_url() -> str:
    """Build the GitHub OAuth authorization URL that initiates the consent screen."""
    settings = get_settings()
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "read:user user:email repo",
    }
    return f"{GITHUB_AUTH_URL}?{urlencode(params)}"


async def exchange_github_code(code: str) -> dict:
    """Exchange authorization code for GitHub access token."""
    settings = get_settings()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        data = resp.json()
        if "access_token" not in data:
            raise ValueError(f"GitHub OAuth error: {data.get('error_description', 'unknown')}")
        return data


async def get_github_user_info(access_token: str) -> dict:
    """Fetch GitHub user profile."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        # Fetch primary email if not public
        email = data.get("email")
        if not email:
            email_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=10,
            )
            emails = email_resp.json()
            primary = next((e for e in emails if e.get("primary")), None)
            email = primary["email"] if primary else f"{data['login']}@github.com"

        return {
            "email": email,
            "name": data.get("name") or data["login"],
            "avatar_url": data.get("avatar_url"),
            "login": data["login"],
        }


async def get_or_create_github_user(db: AsyncSession, user_info: dict, access_token: str) -> User:
    """Find existing user or create, and store encrypted GitHub token."""
    result = await db.execute(select(User).where(User.email == user_info["email"]))
    user = result.scalar_one_or_none()

    encrypted = encrypt_token(access_token)

    if user:
        user.name = user_info["name"]
        user.avatar_url = user_info.get("avatar_url")
        user.github_token_encrypted = encrypted
        logger.info("github_login_existing", email=user_info["email"])
    else:
        user = User(
            email=user_info["email"],
            name=user_info["name"],
            provider="github",
            avatar_url=user_info.get("avatar_url"),
            github_token_encrypted=encrypted,
        )
        db.add(user)
        logger.info("github_login_new", email=user_info["email"])

    await db.flush()
    return user


async def fetch_github_repos(user: User) -> List[dict]:
    """Fetch user's GitHub repositories."""
    if not user.github_token_encrypted:
        return []
    token = decrypt_token(user.github_token_encrypted)
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user/repos?per_page=50&sort=updated",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        repos = resp.json()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "full_name": r["full_name"],
                "language": r.get("language"),
                "stargazers_count": r.get("stargazers_count", 0),
                "updated_at": r.get("updated_at"),
                "private": r.get("private", False),
                "default_branch": r.get("default_branch", "main"),
            }
            for r in repos
        ]


async def fetch_repo_tree(user: User, repo_full_name: str, branch: str = "main") -> List[dict]:
    """Fetch repository file tree from GitHub API."""
    if not user.github_token_encrypted:
        raise ValueError("No GitHub token")
    token = decrypt_token(user.github_token_encrypted)
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo_full_name}/git/trees/{branch}?recursive=1",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        tree = resp.json().get("tree", [])
        return [
            {"path": item["path"], "type": item["type"], "size": item.get("size", 0)}
            for item in tree
            if item["type"] == "blob"
        ]


async def fetch_file_content(user: User, repo_full_name: str, file_path: str, branch: str = "main") -> str:
    """Download a single file from GitHub."""
    if not user.github_token_encrypted:
        raise ValueError("No GitHub token")
    token = decrypt_token(user.github_token_encrypted)
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}?ref={branch}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3.raw",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.text
