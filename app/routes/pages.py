"""Server-rendered HTML pages."""
import time
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import _client_ip, is_authenticated, login, logout, rate_ok, record_attempt, verify_password
from ..audit import log as audit_log
from ..clash import get_proxies, get_version
from ..collector import collector_state
from ..config import settings
from ..db import get_db
from ..health import health_state
from ..profiles import get_subscriptions, get_servers, get_active_servers
from ..rules import get_rules, pending_diff
from ..singbox import unit_active

router = APIRouter(include_in_schema=False)

_TMPL_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TMPL_DIR))

import datetime as _dt
templates.env.filters["strftime"] = lambda ts: _dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d")

# ─── Helpers ───────────────────────────────────────────────────────────────────


def _ctx(request: Request, **kwargs) -> dict:
    return {"request": request, **kwargs}


def _require(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    return None


# ─── Auth ──────────────────────────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", _ctx(request, error=None))


@router.post("/login")
async def login_submit(request: Request, password: str = Form(...)):
    ip = _client_ip(request)
    if not rate_ok(ip):
        audit_log("auth.login", {"ip": ip, "result": "rate_limited"}, ok=False, src_ip=ip)
        return templates.TemplateResponse(
            request, "login.html", _ctx(request, error="Too many attempts. Wait a minute."), status_code=429
        )
    record_attempt(ip)
    if verify_password(password):
        login(request)
        audit_log("auth.login", {"ip": ip, "result": "success"}, ok=True, src_ip=ip)
        return RedirectResponse("/", status_code=302)
    audit_log("auth.login", {"ip": ip, "result": "wrong_password"}, ok=False, src_ip=ip)
    return templates.TemplateResponse(request, "login.html", _ctx(request, error="Wrong password"), status_code=401)


@router.post("/logout")
async def do_logout(request: Request):
    logout(request)
    return RedirectResponse("/login", status_code=302)


# ─── Status ────────────────────────────────────────────────────────────────────


@router.get("/", response_class=HTMLResponse)
async def status_page(request: Request):
    if redir := _require(request):
        return redir

    sb_version = await get_version()
    sb_active = await unit_active()

    subs = get_subscriptions()
    active_sub = next((s for s in subs if s["is_active"]), None)

    with get_db() as conn:
        conn_count = conn.execute(
            "SELECT COUNT(*) FROM connections WHERE ended_at IS NULL"
        ).fetchone()[0]
        db_size = Path(settings.db_path).stat().st_size if Path(settings.db_path).exists() else 0

    pending = pending_diff()
    now = int(time.time())

    expiry_warning = None
    quota_warning = None
    if active_sub:
        if active_sub.get("expires_at") and active_sub["expires_at"] - now < 7 * 86400:
            days = (active_sub["expires_at"] - now) // 86400
            expiry_warning = f"Subscription expires in {days} day(s)"
        if active_sub.get("quota_total") and active_sub["quota_total"] > 0:
            used = (active_sub.get("quota_upload") or 0) + (active_sub.get("quota_download") or 0)
            pct = used / active_sub["quota_total"] * 100
            if pct >= 80:
                quota_warning = f"Quota at {pct:.0f}% ({_fmt_bytes(used)} / {_fmt_bytes(active_sub['quota_total'])})"

    return templates.TemplateResponse(
        request,
        "status.html",
        _ctx(
            request,
            sb_active=sb_active,
            sb_version=sb_version,
            active_sub=active_sub,
            health=health_state,
            conn_count=len(collector_state.live_connections),
            pending_rules=pending,
            expiry_warning=expiry_warning,
            quota_warning=quota_warning,
            stale_warning=_stale_warning(active_sub),
            db_size=_fmt_bytes(db_size),
            collector_ok=collector_state.last_error is None,
            collector_error=collector_state.last_error,
            now=now,
        ),
    )


# ─── Traffic ───────────────────────────────────────────────────────────────────


@router.get("/traffic", response_class=HTMLResponse)
async def traffic_page(request: Request):
    if redir := _require(request):
        return redir
    return templates.TemplateResponse(request, "traffic.html", _ctx(request))


# ─── Rules ─────────────────────────────────────────────────────────────────────


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    if redir := _require(request):
        return redir
    rules = get_rules()
    pending = pending_diff()
    return templates.TemplateResponse(
        request,
        "rules.html",
        _ctx(request, rules=rules, pending=pending, proxy_port=settings.proxy_port),
    )


# ─── Subscriptions ─────────────────────────────────────────────────────────────


@router.get("/subscriptions", response_class=HTMLResponse)
async def subs_page(request: Request):
    if redir := _require(request):
        return redir
    subs = get_subscriptions()
    now = int(time.time())
    return templates.TemplateResponse(
        request,
        "subscriptions.html",
        _ctx(request, subs=subs, now=now, fmt_bytes=_fmt_bytes),
    )


# ─── Servers ───────────────────────────────────────────────────────────────────


@router.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request):
    if redir := _require(request):
        return redir
    subs = get_subscriptions()
    active_sub = next((s for s in subs if s["is_active"]), None)
    servers = get_active_servers() if active_sub else []

    proxies_data = await get_proxies()
    current_pick = None
    if proxies_data:
        proxy_group = proxies_data.get("proxies", {}).get("proxy", {})
        current_pick = proxy_group.get("now")

    return templates.TemplateResponse(
        request,
        "servers.html",
        _ctx(request, servers=servers, active_sub=active_sub, current_pick=current_pick),
    )


# ─── Containers ────────────────────────────────────────────────────────────────


@router.get("/containers", response_class=HTMLResponse)
async def containers_page(request: Request):
    if redir := _require(request):
        return redir
    return templates.TemplateResponse(request, "containers.html", _ctx(request))


# ─── Hermes ────────────────────────────────────────────────────────────────────


@router.get("/hermes", response_class=HTMLResponse)
async def hermes_page(request: Request):
    if redir := _require(request):
        return redir
    return templates.TemplateResponse(request, "hermes.html", _ctx(request))


# ─── Public healthz ────────────────────────────────────────────────────────────


@router.get("/healthz")
async def healthz():
    from fastapi.responses import JSONResponse

    last_ts = health_state.last_ts
    last_ok = health_state.last_ok
    stale = last_ts is None or (int(time.time()) - last_ts > 600)
    return JSONResponse(
        {
            "singbox": "active" if await unit_active() else "inactive",
            "last_probe_ok": last_ok,
            "last_probe_ts": last_ts,
            "stale": stale,
        }
    )


# ─── Utilities ─────────────────────────────────────────────────────────────────


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} TB"


def _stale_warning(active_sub) -> str:
    if not active_sub:
        return ""
    last_fetch = active_sub.get("last_fetch_at")
    if not last_fetch:
        return ""
    if not active_sub.get("last_fetch_ok"):
        age_h = (int(time.time()) - last_fetch) / 3600
        return f"Last subscription refresh failed {age_h:.1f}h ago"
    return ""
