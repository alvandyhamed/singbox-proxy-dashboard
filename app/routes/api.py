"""JSON API endpoints + WebSocket live traffic."""
import asyncio
import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse

from ..audit import log as audit_log
from ..auth import _client_ip, require_api_auth
from ..clash import delete_connection, delay_group, delay_proxy, get_connections, get_proxies, select_proxy
from ..collector import collector_state, net_state
from ..config import settings
from ..db import get_db
from ..health import health_state, probe_once
from ..profiles import (
    add_subscription,
    delete_subscription,
    get_active_servers,
    get_servers,
    get_subscription,
    get_subscriptions,
    refresh_subscription,
    set_active_subscription,
    store_servers,
)
from ..rules import add_rule, apply_rules, delete_rule, get_rules, pending_diff, toggle_rule
from ..singbox import safe_apply, unit_active
from ..health import health_state

router = APIRouter()
auth = Depends(require_api_auth)


# ─── Status ────────────────────────────────────────────────────────────────────


@router.get("/status", dependencies=[auth])
async def api_status(request: Request):
    subs = get_subscriptions()
    active_sub = next((s for s in subs if s["is_active"]), None)
    return {
        "singbox_active": await unit_active(),
        "active_sub": active_sub["name"] if active_sub else None,
        "health": {
            "ok": health_state.last_ok,
            "ts": health_state.last_ts,
            "latency_ms": health_state.last_latency_ms,
            "target": health_state.last_target,
            "error": health_state.last_error,
        },
        "collector_ok": collector_state.last_error is None,
    }


# ─── Traffic WebSocket ─────────────────────────────────────────────────────────


@router.websocket("/traffic/live")
async def ws_traffic(ws: WebSocket):
    await ws.accept()
    # SessionMiddleware stores session in ws.scope["session"]
    session = ws.scope.get("session", {})
    if not session.get("authenticated"):
        await ws.close(code=4401)
        return
    collector_state.clients.add(ws)
    # Send ring buffer immediately
    try:
        await ws.send_text(json.dumps({
            "type": "init",
            "ring": list(collector_state.traffic_ring),
        }))
        while True:
            # keep alive; data pushed by collector
            await asyncio.sleep(30)
            await ws.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        collector_state.clients.discard(ws)


# ─── Server network WebSocket ─────────────────────────────────────────────────


@router.websocket("/server/net/live")
async def ws_server_net(ws: WebSocket):
    await ws.accept()
    if not ws.scope.get("session", {}).get("authenticated"):
        await ws.close(code=4401)
        return
    net_state.clients.add(ws)
    try:
        await ws.send_text(json.dumps({
            "type": "init",
            "iface": net_state.iface,
            "ring": list(net_state.ring)[-60:],
        }))
        while True:
            await asyncio.sleep(30)
            await ws.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        net_state.clients.discard(ws)


# ─── Traffic history ───────────────────────────────────────────────────────────


@router.get("/traffic/history", dependencies=[auth])
async def traffic_history(request: Request, group_by: str = "host", limit: int = 50):
    now = int(time.time())
    since = now - 86400  # last 24h default

    with get_db() as conn:
        if group_by == "day":
            rows = conn.execute(
                """SELECT day, SUM(up_bytes) up, SUM(down_bytes) down, SUM(conn_count) conns
                   FROM host_daily GROUP BY day ORDER BY day DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        elif group_by == "hour":
            rows = conn.execute(
                """SELECT strftime('%Y-%m-%dT%H:00', bucket_ts, 'unixepoch') hr,
                          SUM(up_bytes) up, SUM(down_bytes) down, SUM(conn_count) conns
                   FROM host_traffic WHERE bucket_ts >= ?
                   GROUP BY hr ORDER BY hr DESC LIMIT ?""",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT host, SUM(up_bytes) up, SUM(down_bytes) down, SUM(conn_count) conns,
                          MAX(attributed) attributed
                   FROM host_traffic WHERE bucket_ts >= ?
                   GROUP BY host ORDER BY down DESC LIMIT ?""",
                (since, limit),
            ).fetchall()

    return [dict(r) for r in rows]


# ─── Connections ───────────────────────────────────────────────────────────────


@router.get("/connections", dependencies=[auth])
async def api_connections():
    return {"connections": list(collector_state.live_connections.values())}


@router.delete("/connections/{conn_id}", dependencies=[auth])
async def api_delete_connection(conn_id: str):
    ok = await delete_connection(conn_id)
    return {"ok": ok}


# ─── Subscriptions ─────────────────────────────────────────────────────────────


@router.get("/subs", dependencies=[auth])
async def api_list_subs():
    subs = get_subscriptions()
    # Mask URL (which contains the token)
    safe = []
    for s in subs:
        s2 = dict(s)
        if s2.get("url"):
            from urllib.parse import urlparse
            u = urlparse(s2["url"])
            s2["url_host"] = u.hostname
        del s2["url"]
        safe.append(s2)
    return safe


@router.post("/subs", dependencies=[auth])
async def api_add_sub(request: Request):
    body = await request.json()
    url = (body.get("url") or "").strip()
    name = (body.get("name") or "").strip()
    if not url:
        raise HTTPException(400, "url is required")

    # Reject URLs pointing at loopback/private ranges via hostname check
    from urllib.parse import urlparse
    import ipaddress
    parsed_url = urlparse(url)
    try:
        addr = ipaddress.ip_address(parsed_url.hostname or "")
        if addr.is_loopback or addr.is_private:
            raise HTTPException(400, "URL resolves to a private/loopback address")
    except ValueError:
        pass  # hostname, not IP

    if not name:
        from urllib.parse import urlparse as up
        name = up(url).hostname or url[:30]

    sub_id = add_subscription(name, url)
    audit_log("sub.add", {"name": name, "sub_id": sub_id}, ok=True, src_ip=_client_ip(request))

    # Immediately fetch and store
    result = await refresh_subscription(sub_id)
    if result["ok"]:
        store_servers(sub_id, result["parsed"], result.get("meta"))
    return {"id": sub_id, "name": name, "refresh": result}


@router.post("/subs/{sub_id}/refresh", dependencies=[auth])
async def api_refresh_sub(sub_id: int, request: Request):
    result = await refresh_subscription(sub_id)
    return result


@router.post("/subs/{sub_id}/apply", dependencies=[auth])
async def api_apply_sub(sub_id: int, request: Request):
    result = await refresh_subscription(sub_id)
    if not result["ok"]:
        raise HTTPException(400, result["error"])

    store_servers(sub_id, result["parsed"], result.get("meta"))
    set_active_subscription(sub_id)
    servers = get_servers(sub_id)

    apply_result = await safe_apply(servers, src_ip=_client_ip(request))
    if apply_result.get("busy"):
        raise HTTPException(409, "Another apply is in progress")

    audit_log(
        "sub.apply",
        {"sub_id": sub_id, "servers": len(servers), "ok": apply_result["ok"]},
        ok=apply_result["ok"],
        src_ip=_client_ip(request),
    )
    return apply_result


@router.delete("/subs/{sub_id}", dependencies=[auth])
async def api_delete_sub(sub_id: int, request: Request):
    ok = delete_subscription(sub_id)
    if not ok:
        raise HTTPException(400, "Cannot delete active subscription or not found")
    audit_log("sub.delete", {"sub_id": sub_id}, ok=True, src_ip=_client_ip(request))
    return {"ok": True}


# ─── Servers ───────────────────────────────────────────────────────────────────


@router.get("/servers", dependencies=[auth])
async def api_servers():
    subs = get_subscriptions()
    active_sub = next((s for s in subs if s["is_active"]), None)
    if not active_sub:
        return []
    servers = get_servers(active_sub["id"])

    proxies_data = await get_proxies()
    latencies: dict = {}
    current_pick = None
    if proxies_data:
        proxy_group = proxies_data.get("proxies", {}).get("proxy", {})
        current_pick = proxy_group.get("now")
        for tag, info in proxies_data.get("proxies", {}).items():
            if isinstance(info, dict):
                hist = info.get("history", [])
                latencies[tag] = hist[-1].get("delay") if hist else None

    result = []
    for s in servers:
        safe = {
            "id": s["id"],
            "outbound_tag": s["outbound_tag"],
            "label": s["label"],
            "protocol": s["protocol"],
            "server_host": s["server_host"],
            "server_port": s["server_port"],
            "is_present": s["is_present"],
            "latency": latencies.get(s["outbound_tag"]),
            "current": s["outbound_tag"] == current_pick,
        }
        result.append(safe)
    return result


@router.post("/servers/{tag}/select", dependencies=[auth])
async def api_select_server(tag: str, request: Request):
    ok = await select_proxy("proxy", tag)
    audit_log("server.select", {"tag": tag, "ok": ok}, ok=ok, src_ip=_client_ip(request))
    return {"ok": ok}


@router.post("/servers/auto", dependencies=[auth])
async def api_auto_server(request: Request):
    ok = await select_proxy("proxy", "auto")
    audit_log("server.auto", {"ok": ok}, ok=ok, src_ip=_client_ip(request))
    return {"ok": ok}


@router.post("/servers/{tag}/delay", dependencies=[auth])
async def api_delay_server(tag: str):
    latency = await delay_proxy(tag)
    return {"tag": tag, "latency": latency}


@router.post("/servers/delay", dependencies=[auth])
async def api_delay_all():
    result = await delay_group("auto")
    return result


# ─── Rules ─────────────────────────────────────────────────────────────────────


@router.get("/rules", dependencies=[auth])
async def api_list_rules():
    return get_rules()


@router.post("/rules", dependencies=[auth])
async def api_add_rule(request: Request):
    body = await request.json()
    kind = (body.get("kind") or "").strip()
    value = (body.get("value") or "").strip()
    note = (body.get("note") or "").strip()
    result = add_rule(kind, value, note)
    if result["ok"]:
        audit_log("rule.add", {"kind": kind, "value": value}, ok=True, src_ip=_client_ip(request))
    return result


@router.patch("/rules/{rule_id}", dependencies=[auth])
async def api_toggle_rule(rule_id: int, request: Request):
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    ok = toggle_rule(rule_id, enabled)
    if ok:
        audit_log("rule.toggle", {"id": rule_id, "enabled": enabled}, ok=True, src_ip=_client_ip(request))
    return {"ok": ok}


@router.delete("/rules/{rule_id}", dependencies=[auth])
async def api_delete_rule(rule_id: int, request: Request):
    ok = delete_rule(rule_id)
    if ok:
        audit_log("rule.delete", {"id": rule_id}, ok=True, src_ip=_client_ip(request))
    return {"ok": ok}


@router.get("/rules/pending", dependencies=[auth])
async def api_pending_rules():
    return pending_diff()


@router.post("/rules/apply", dependencies=[auth])
async def api_apply_rules(request: Request):
    result = await apply_rules(src_ip=_client_ip(request))
    if result.get("busy"):
        raise HTTPException(409, "Another apply is in progress")
    return result


# ─── Audit ─────────────────────────────────────────────────────────────────────


@router.get("/audit", dependencies=[auth])
async def api_audit(page: int = 1, per_page: int = 50):
    offset = (page - 1) * per_page
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ? OFFSET ?",
            (per_page, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    return {"total": total, "page": page, "items": [dict(r) for r in rows]}


# ─── Health ────────────────────────────────────────────────────────────────────


@router.get("/health", dependencies=[auth])
async def api_health_history(limit: int = 100):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM health_checks ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/health/run", dependencies=[auth])
async def api_health_run():
    result = await probe_once()
    return result


# ─── Quick status (nav indicator) ─────────────────────────────────────────────


@router.get("/status/quick", dependencies=[auth])
async def api_quick_status():
    active = await unit_active()
    server = None
    if active:
        proxies = await get_proxies()
        if proxies:
            server = proxies.get("proxies", {}).get("proxy", {}).get("now")
    return {"active": active, "server": server}


# ─── Server network report ────────────────────────────────────────────────────


@router.get("/server/net/report", dependencies=[auth])
async def api_server_net_report(period: str = "day"):
    now = int(time.time())
    if period == "week":
        since = now - 7 * 86400
        group = "strftime('%Y-%m-%d', ts, 'unixepoch')"
    elif period == "month":
        since = now - 30 * 86400
        group = "strftime('%Y-%m-%d', ts, 'unixepoch')"
    else:  # day
        since = now - 86400
        group = "strftime('%Y-%m-%dT%H:00', ts, 'unixepoch')"

    with get_db() as conn:
        rows = conn.execute(
            f"SELECT {group} as period, SUM(rx_bytes) rx, SUM(tx_bytes) tx "
            "FROM server_net_samples WHERE ts >= ? GROUP BY period ORDER BY period",
            (since,),
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/server/net/containers", dependencies=[auth])
async def api_server_net_containers():
    return net_state.container_stats


@router.get("/server/net/ring", dependencies=[auth])
async def api_server_net_ring():
    return {
        "iface": net_state.iface,
        "ring": list(net_state.ring)[-120:],
    }


# ─── Containers ────────────────────────────────────────────────────────────────


@router.get("/containers", dependencies=[auth])
async def api_containers():
    import docker as _docker
    try:
        client = _docker.from_env()
        result = []
        for c in client.containers.list(all=True):
            env = c.attrs.get("Config", {}).get("Env") or []
            proxy_env = next((e for e in env if e.upper().startswith("HTTPS_PROXY=") or e.upper().startswith("HTTP_PROXY=")), None)
            proxy_val = proxy_env.split("=", 1)[1] if proxy_env else None
            network_mode = c.attrs.get("HostConfig", {}).get("NetworkMode", "bridge")
            try:
                image_tags = c.image.tags
                image = image_tags[0] if image_tags else c.image.short_id
            except Exception:
                image = c.attrs.get("Config", {}).get("Image", "unknown")
            result.append({
                "id": c.short_id,
                "name": c.name,
                "image": image,
                "status": c.status,
                "network_mode": network_mode,
                "proxy": proxy_val,
            })
        result.sort(key=lambda x: (x["status"] != "running", x["name"]))
        return result
    except Exception as e:
        raise HTTPException(500, f"Docker error: {e}")


# ─── Hermes ────────────────────────────────────────────────────────────────────


def _read_hermes_config() -> dict:
    import yaml
    from pathlib import Path
    path = Path(settings.hermes_config_path)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def _write_hermes_config(cfg: dict) -> None:
    import yaml
    from pathlib import Path
    path = Path(settings.hermes_config_path)
    path.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True, sort_keys=False))


@router.get("/hermes/config", dependencies=[auth])
async def api_hermes_config():
    cfg = _read_hermes_config()
    providers = [dict(p) for p in cfg.get("custom_providers", [])]
    for p in providers:
        key = p.get("api_key", "")
        p["api_key_masked"] = key[:6] + "…" + key[-4:] if len(key) > 10 else "****"
        p.pop("api_key", None)
    return {
        "model": cfg.get("model", {}),
        "custom_providers": providers,
    }


@router.post("/hermes/providers", dependencies=[auth])
async def api_hermes_add_provider(request: Request):
    body = await request.json()
    name = (body.get("name") or "").strip()
    base_url = (body.get("base_url") or "").strip()
    api_key = (body.get("api_key") or "").strip()
    model = (body.get("model") or "").strip()
    if not all([name, base_url, api_key]):
        raise HTTPException(400, "name, base_url, api_key are required")
    cfg = _read_hermes_config()
    providers = cfg.setdefault("custom_providers", [])
    if any(p.get("name") == name for p in providers):
        raise HTTPException(409, f"Provider '{name}' already exists")
    entry: dict = {"name": name, "base_url": base_url, "api_key": api_key}
    if model:
        entry["model"] = model
    providers.append(entry)
    _write_hermes_config(cfg)
    audit_log("hermes.provider.add", {"name": name}, ok=True, src_ip=_client_ip(request))
    return {"ok": True}


@router.delete("/hermes/providers/{name}", dependencies=[auth])
async def api_hermes_delete_provider(name: str, request: Request):
    cfg = _read_hermes_config()
    providers = cfg.get("custom_providers", [])
    new_list = [p for p in providers if p.get("name") != name]
    if len(new_list) == len(providers):
        raise HTTPException(404, "Provider not found")
    cfg["custom_providers"] = new_list
    _write_hermes_config(cfg)
    audit_log("hermes.provider.delete", {"name": name}, ok=True, src_ip=_client_ip(request))
    return {"ok": True}


@router.post("/hermes/providers/{name}/test", dependencies=[auth])
async def api_hermes_test_provider(name: str):
    cfg = _read_hermes_config()
    provider = next((p for p in cfg.get("custom_providers", []) if p.get("name") == name), None)
    if not provider:
        raise HTTPException(404, "Provider not found")
    import httpx
    url = provider["base_url"].rstrip("/") + "/models"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers={"Authorization": f"Bearer {provider['api_key']}"})
        if r.status_code == 200:
            data = r.json()
            models = sorted([m.get("id") for m in data.get("data", []) if m.get("id")])
            return {"ok": True, "models": models, "status": r.status_code}
        return {"ok": False, "status": r.status_code, "error": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/hermes/active", dependencies=[auth])
async def api_hermes_set_active(request: Request):
    body = await request.json()
    provider_name = (body.get("provider") or "").strip()
    model_name = (body.get("model") or "").strip()
    if not provider_name or not model_name:
        raise HTTPException(400, "provider and model are required")

    cfg = _read_hermes_config()
    existing_model = cfg.get("model", {})
    custom = {p["name"]: p for p in cfg.get("custom_providers", [])}

    if provider_name in custom:
        p = custom[provider_name]
        cfg["model"] = {
            **existing_model,
            "provider": provider_name,
            "default": model_name,
            "base_url": p.get("base_url", existing_model.get("base_url", "")),
        }
    else:
        cfg["model"] = {**existing_model, "provider": provider_name, "default": model_name}

    _write_hermes_config(cfg)
    audit_log("hermes.active.set", {"provider": provider_name, "model": model_name}, ok=True, src_ip=_client_ip(request))
    return {"ok": True}
