import time
from collections import defaultdict
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request, status

from .config import settings

_ph = PasswordHasher()
_attempts: dict[str, list[float]] = defaultdict(list)
_MAX_ATTEMPTS = 5
_WINDOW_SECS = 60


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_ok(ip: str) -> bool:
    now = time.time()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < _WINDOW_SECS]
    return len(_attempts[ip]) < _MAX_ATTEMPTS


def record_attempt(ip: str) -> None:
    _attempts[ip].append(time.time())


def verify_password(plain: str) -> bool:
    if not settings.password_hash:
        return False
    try:
        return _ph.verify(settings.password_hash, plain)
    except (VerifyMismatchError, VerificationError):
        return False


def hash_password(plain: str) -> str:
    return _ph.hash(plain)


def login(request: Request) -> None:
    request.session["authenticated"] = True
    request.session["logged_in_at"] = int(time.time())


def logout(request: Request) -> None:
    request.session.clear()


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


async def require_auth(request: Request) -> None:
    """Dependency for page routes — raises 302 redirect if not authenticated."""
    if not is_authenticated(request):
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )


async def require_api_auth(request: Request) -> None:
    """Dependency for API routes — raises 401 if not authenticated."""
    if not is_authenticated(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
