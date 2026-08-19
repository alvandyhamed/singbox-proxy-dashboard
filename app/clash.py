"""Clash API REST client."""
import asyncio
from typing import Any, AsyncIterator, Optional

import httpx

from .config import settings


def _headers() -> dict[str, str]:
    h = {}
    if settings.clash_api_secret:
        h["Authorization"] = f"Bearer {settings.clash_api_secret}"
    return h


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.clash_api_url,
        headers=_headers(),
        timeout=10.0,
    )


async def get_version() -> Optional[dict]:
    try:
        async with _client() as c:
            r = await c.get("/version")
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


async def get_connections() -> Optional[dict]:
    try:
        async with _client() as c:
            r = await c.get("/connections")
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


async def delete_connection(conn_id: str) -> bool:
    try:
        async with _client() as c:
            r = await c.delete(f"/connections/{conn_id}")
            return r.status_code in (200, 204)
    except Exception:
        return False


async def get_proxies() -> Optional[dict]:
    try:
        async with _client() as c:
            r = await c.get("/proxies")
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


async def select_proxy(group: str, name: str) -> bool:
    try:
        async with _client() as c:
            r = await c.put(f"/proxies/{group}", json={"name": name})
            return r.status_code in (200, 204)
    except Exception:
        return False


async def delay_proxy(name: str, timeout_ms: int = 3000) -> Optional[int]:
    url = "https://www.gstatic.com/generate_204"
    try:
        async with _client() as c:
            r = await c.get(
                f"/proxies/{name}/delay",
                params={"timeout": timeout_ms, "url": url},
                timeout=timeout_ms / 1000 + 2,
            )
            if r.status_code == 200:
                return r.json().get("delay")
    except Exception:
        pass
    return None


async def delay_group(group: str, timeout_ms: int = 3000) -> dict:
    url = "https://www.gstatic.com/generate_204"
    try:
        async with _client() as c:
            r = await c.get(
                f"/group/{group}/delay",
                params={"timeout": timeout_ms, "url": url},
                timeout=timeout_ms / 1000 + 5,
            )
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return {}


async def ws_url(path: str) -> str:
    base = settings.clash_api_url.replace("http://", "ws://").replace("https://", "wss://")
    secret = settings.clash_api_secret
    sep = "&" if "?" in path else "?"
    return f"{base}{path}{sep}token={secret}" if secret else f"{base}{path}"
