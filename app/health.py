"""Periodic SOCKS health probe."""
import asyncio
import time
from typing import Optional

import httpx

from .config import settings
from .db import get_write_db


class HealthState:
    def __init__(self) -> None:
        self.last_ok: Optional[bool] = None
        self.last_ts: Optional[int] = None
        self.last_latency_ms: Optional[int] = None
        self.last_target: Optional[str] = None
        self.last_error: Optional[str] = None


health_state = HealthState()


async def probe_once() -> dict:
    target = settings.health_targets[0] if settings.health_targets else "https://api.telegram.org"
    proxy_url = f"socks5://127.0.0.1:{settings.proxy_port}"
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=15.0) as client:
            r = await client.get(target)
            latency_ms = int((time.monotonic() - t0) * 1000)
            ok = r.status_code < 500
            error = None if ok else f"HTTP {r.status_code}"
    except Exception as exc:
        latency_ms = int((time.monotonic() - t0) * 1000)
        ok = False
        error = str(exc)[:200]

    ts = int(time.time())
    health_state.last_ok = ok
    health_state.last_ts = ts
    health_state.last_latency_ms = latency_ms if ok else None
    health_state.last_target = target
    health_state.last_error = error

    try:
        with get_write_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO health_checks (ts, ok, latency_ms, target, error) VALUES (?,?,?,?,?)",
                (ts, int(ok), latency_ms if ok else None, target, error),
            )
    except Exception:
        pass

    return {"ok": ok, "latency_ms": latency_ms, "target": target, "error": error, "ts": ts}


async def run_health_checker() -> None:
    await asyncio.sleep(5)  # let sing-box stabilise first
    while True:
        try:
            await probe_once()
        except asyncio.CancelledError:
            return
        except Exception:
            pass
        await asyncio.sleep(120)
