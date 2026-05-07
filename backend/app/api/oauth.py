"""
OAuth 2.0 compatible endpoints for MCP clients.
"""
from datetime import timedelta
import base64
import hashlib
import hmac
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.settings import get_mcp_config_dict
from app.utils.security import create_access_token

router = APIRouter()

MCP_CLIENT_ID = "litemark-mcp"
MCP_SCOPE = "bookmarks:read bookmarks:write"
MCP_TOKEN_EXPIRE_SECONDS = 3600


def token_hash(token: str) -> str:
    """Hash MCP token for OAuth access-token binding."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_external_base_url(request: Request) -> str:
    """Build external origin URL from forwarded headers."""
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def get_mcp_resource_url(request: Request) -> str:
    """Return the canonical MCP resource URL."""
    return f"{get_external_base_url(request)}/mcp/"


def _basic_credentials(request: Request) -> tuple[Optional[str], Optional[str]]:
    value = request.headers.get("authorization", "")
    scheme, _, encoded = value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None, None
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return None, None
    username, _, password = decoded.partition(":")
    return username or None, password or None


def _normalize_resource(value: str) -> str:
    return value.rstrip("/") + "/"


def _resource_allowed(request: Request, resource: Optional[str]) -> bool:
    if not resource:
        return True
    requested = _normalize_resource(resource)
    base = get_external_base_url(request)
    allowed = {
        _normalize_resource(base),
        _normalize_resource(f"{base}/mcp"),
    }
    return requested in allowed


def _scope_allowed(scope: str) -> bool:
    requested = set(scope.split())
    supported = set(MCP_SCOPE.split())
    return requested == supported


async def _require_mcp_config(session: AsyncSession) -> dict:
    config = await get_mcp_config_dict(session)
    if not config["mcp_enabled"] or not config["mcp_token"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MCP 未启用",
        )
    return config


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata(request: Request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)."""
    base = get_external_base_url(request)
    return {
        "resource": get_mcp_resource_url(request),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": MCP_SCOPE.split(),
        "resource_documentation": f"{base}/api.md",
    }


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata(request: Request):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    base = get_external_base_url(request)
    return {
        "issuer": base,
        "token_endpoint": f"{base}/oauth/token",
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "scopes_supported": MCP_SCOPE.split(),
        "response_types_supported": [],
    }


@router.post("/oauth/token")
async def issue_token(
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """Issue a short-lived OAuth 2.0 access token for MCP clients."""
    form = await request.form()
    basic_client_id, basic_client_secret = _basic_credentials(request)

    grant_type = str(form.get("grant_type") or "")
    client_id = str(form.get("client_id") or basic_client_id or "")
    client_secret = str(form.get("client_secret") or basic_client_secret or "")
    resource = str(form.get("resource") or "")
    scope = str(form.get("scope") or MCP_SCOPE)

    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="仅支持 client_credentials",
        )
    if not _scope_allowed(scope):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scope 无效",
        )
    if client_id != MCP_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client_id 无效",
            headers={"WWW-Authenticate": "Basic"},
        )

    config = await _require_mcp_config(session)
    if not client_secret or not hmac.compare_digest(client_secret, config["mcp_token"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client_secret 无效",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not _resource_allowed(request, resource):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="resource 无效",
        )

    token = create_access_token(
        {
            "sub": MCP_CLIENT_ID,
            "typ": "mcp_oauth",
            "scope": scope or MCP_SCOPE,
            "resource": resource or get_mcp_resource_url(request),
            "mcp_token_hash": token_hash(config["mcp_token"]),
        },
        expires_delta=timedelta(seconds=MCP_TOKEN_EXPIRE_SECONDS),
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": MCP_TOKEN_EXPIRE_SECONDS,
        "scope": scope or MCP_SCOPE,
    }
