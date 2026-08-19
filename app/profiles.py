"""
Subscription and server management.
Fetch → decode → parse → diff → stage → apply.
"""
import base64
import hashlib
import json
import re
import time
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from .config import settings
from .db import get_db, get_write_db

USER_AGENTS = [
    "sing-box/1.12.0",
    "clash-verge/2.0",
    "v2rayNG/1.9.0",
    "Hiddify/2.0.0",
]

MAX_BODY_BYTES = 1_000_000
SUB_REFRESH_COOLDOWN = 60  # seconds between manual refreshes


# ─── URI parsing ───────────────────────────────────────────────────────────────


def identity_hash(protocol: str, host: str, port: int, secret: str) -> str:
    key = f"{protocol}:{host}:{port}:{secret}"
    return hashlib.sha256(key.encode()).hexdigest()[:20]


def _parse_vless(uri: str) -> dict:
    u = urlparse(uri)
    uuid = u.username or ""
    host = u.hostname or ""
    port = u.port or 443
    params = parse_qs(u.query)

    def p(key: str) -> str:
        vals = params.get(key, [])
        return vals[0] if vals else ""

    label = unquote(u.fragment) if u.fragment else f"vless-{host}"
    security = p("security")
    transport_type = p("type") or "tcp"
    sni = p("sni") or host
    fp = p("fp")
    pbk = p("pbk")
    sid = p("sid")
    flow = p("flow")
    path = p("path") or "/"
    host_header = p("host") or host
    service_name = p("serviceName") or ""

    ob: dict = {
        "type": "vless",
        "tag": "",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }
    if flow:
        ob["flow"] = flow

    tls: dict = {}
    if security in ("tls", "reality"):
        tls["enabled"] = True
        tls["server_name"] = sni
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid}

    if tls:
        ob["tls"] = tls

    transport: dict = {}
    if transport_type == "ws":
        transport = {"type": "ws", "path": path, "headers": {"Host": host_header}}
    elif transport_type == "grpc":
        transport = {"type": "grpc", "service_name": service_name}
    elif transport_type == "h2":
        transport = {"type": "http", "host": [host_header], "path": path}
    if transport:
        ob["transport"] = transport

    return {
        "protocol": "vless",
        "host": host,
        "port": port,
        "secret": uuid,
        "label": label,
        "outbound": ob,
    }


def _parse_vmess(uri: str) -> dict:
    encoded = uri[len("vmess://"):]
    # pad and try standard, then URL-safe
    for alt in [False, True]:
        try:
            b = encoded.replace("-", "+").replace("_", "/") if alt else encoded
            padded = b + "=" * (-len(b) % 4)
            raw = base64.b64decode(padded).decode("utf-8", errors="replace")
            data = json.loads(raw)
            break
        except Exception:
            data = None

    if not data:
        raise ValueError("Cannot decode vmess URI")

    host = data.get("add", "")
    port = int(data.get("port", 443))
    uuid = data.get("id", "")
    net = data.get("net", "tcp")
    tls_mode = data.get("tls", "")
    sni = data.get("sni", "") or host
    path = data.get("path", "/")
    host_header = data.get("host", "") or host
    label = data.get("ps", f"vmess-{host}")

    ob: dict = {
        "type": "vmess",
        "tag": "",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "alter_id": int(data.get("aid", 0)),
        "security": "auto",
    }

    if tls_mode == "tls":
        ob["tls"] = {"enabled": True, "server_name": sni}

    transport: dict = {}
    if net == "ws":
        transport = {"type": "ws", "path": path, "headers": {"Host": host_header}}
    elif net == "grpc":
        transport = {"type": "grpc", "service_name": data.get("serviceName", "")}
    elif net == "h2":
        transport = {"type": "http", "host": [host_header], "path": path}
    if transport:
        ob["transport"] = transport

    return {
        "protocol": "vmess",
        "host": host,
        "port": port,
        "secret": uuid,
        "label": label,
        "outbound": ob,
    }


def _parse_trojan(uri: str) -> dict:
    u = urlparse(uri)
    password = u.username or ""
    host = u.hostname or ""
    port = u.port or 443
    params = parse_qs(u.query)

    def p(key: str) -> str:
        vals = params.get(key, [])
        return vals[0] if vals else ""

    label = unquote(u.fragment) if u.fragment else f"trojan-{host}"
    sni = p("sni") or host
    security = p("security") or "tls"

    ob: dict = {
        "type": "trojan",
        "tag": "",
        "server": host,
        "server_port": port,
        "password": password,
        "tls": {"enabled": True, "server_name": sni},
    }

    return {
        "protocol": "trojan",
        "host": host,
        "port": port,
        "secret": password,
        "label": label,
        "outbound": ob,
    }


def parse_uri(uri: str) -> dict:
    uri = uri.strip()
    if uri.startswith("vless://"):
        return _parse_vless(uri)
    elif uri.startswith("vmess://"):
        return _parse_vmess(uri)
    elif uri.startswith("trojan://"):
        return _parse_trojan(uri)
    else:
        raise ValueError(f"Unsupported scheme: {uri[:30]!r}")


# ─── Body decoding ─────────────────────────────────────────────────────────────


def decode_body(body: str) -> list[str]:
    """Decode subscription body, return list of raw URIs."""
    body = body.strip()
    if body.startswith(("vless://", "vmess://", "trojan://")):
        lines = body.splitlines()
    else:
        # Try standard base64, then URL-safe
        decoded = None
        for alt in [False, True]:
            try:
                b = body.replace("-", "+").replace("_", "/") if alt else body
                padded = b + "=" * (-len(b) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
                break
            except Exception:
                pass
        if decoded is None:
            # Try JSON
            try:
                data = json.loads(body)
                if isinstance(data, dict) and "outbounds" in data:
                    # Native sing-box config — just return tags for display; not URI-parseable
                    return []
            except Exception:
                pass
            raise ValueError("Cannot decode subscription body")
        lines = decoded.splitlines()

    uris: list[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            # Check for inline metadata comment
            continue
        if line.startswith(("vless://", "vmess://", "trojan://")):
            uris.append(line)
    return uris


def parse_metadata_headers(headers: dict, body: str) -> dict:
    """Extract quota/expiry from response headers or leading body comment."""
    meta: dict = {}

    def parse_userinfo(val: str) -> None:
        for part in val.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            try:
                n = int(v)
                if k == "upload":
                    meta["quota_upload"] = n
                elif k == "download":
                    meta["quota_download"] = n
                elif k == "total":
                    meta["quota_total"] = n  # 0 = unlimited
                elif k == "expire":
                    if n <= 0:
                        meta["expires_at"] = None
                    elif n > 32_000_000_000:
                        meta["expires_at"] = n // 1000
                    else:
                        meta["expires_at"] = n
            except ValueError:
                pass

    # Check headers (case-insensitive)
    for k, v in headers.items():
        lk = k.lower()
        if lk == "subscription-userinfo":
            parse_userinfo(v)
        elif lk == "profile-update-interval":
            try:
                meta["update_interval_h"] = int(v)
            except ValueError:
                pass
        elif lk == "profile-title":
            meta["profile_title"] = v

    # Check leading body comment
    for line in body.splitlines()[:5]:
        line = line.strip()
        if not line.startswith("#"):
            break
        if "subscription-userinfo" in line.lower():
            _, _, val = line.partition(":")
            parse_userinfo(val)

    return meta


# ─── Fetch ─────────────────────────────────────────────────────────────────────


async def fetch_subscription(url: str, stored_ua: Optional[str] = None) -> dict:
    """
    Fetch subscription URL. Tries each User-Agent and direct → tunnel paths.
    Returns {'body': str, 'headers': dict, 'via': str, 'user_agent': str, 'http_status': int}
    """
    errors: list[str] = []

    # Preferred UA first, then the ladder
    ua_order = ([stored_ua] if stored_ua else []) + [
        ua for ua in USER_AGENTS if ua != stored_ua
    ]

    for via, proxy in [("direct", None), ("tunnel", f"socks5://127.0.0.1:{settings.proxy_port}")]:
        for ua in ua_order:
            try:
                client_kwargs: dict = {"timeout": 15.0, "follow_redirects": True, "max_redirects": 5}
                if proxy:
                    client_kwargs["proxy"] = proxy
                async with httpx.AsyncClient(**client_kwargs) as client:
                    r = await client.get(
                        url,
                        headers={"User-Agent": ua},
                        extensions={"max_body_size": MAX_BODY_BYTES},
                    )
                    r.raise_for_status()
                    body = r.text
                    if body.strip():
                        return {
                            "body": body,
                            "headers": dict(r.headers),
                            "via": via,
                            "user_agent": ua,
                            "http_status": r.status_code,
                        }
            except Exception as exc:
                errors.append(f"{via}/{ua}: {exc}")

    raise RuntimeError("All fetch attempts failed:\n" + "\n".join(errors))


# ─── DB helpers ────────────────────────────────────────────────────────────────


def get_subscriptions() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM subscriptions ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_subscription(sub_id: int) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
        return dict(row) if row else None


def get_servers(sub_id: int) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM servers WHERE subscription_id=? AND is_present=1 ORDER BY outbound_tag",
            (sub_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_active_servers() -> list[dict]:
    with get_db() as conn:
        sub = conn.execute("SELECT id FROM subscriptions WHERE is_active=1 LIMIT 1").fetchone()
        if not sub:
            return []
        return get_servers(sub["id"])


def _make_tag(sub_id: int, label: str, index: int) -> str:
    safe = re.sub(r"[^a-z0-9\-]", "-", label.lower())[:20].strip("-")
    return f"sub{sub_id}-{safe or 'node'}-{index:02d}"


def add_subscription(name: str, url: str) -> int:
    now = int(time.time())
    with get_write_db() as conn:
        cur = conn.execute(
            "INSERT INTO subscriptions (name, url, added_at) VALUES (?,?,?)",
            (name, url, now),
        )
        return cur.lastrowid


def delete_subscription(sub_id: int) -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT is_active FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
        if not row or row["is_active"]:
            return False
    with get_write_db() as conn:
        conn.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
    return True


async def refresh_subscription(sub_id: int) -> dict:
    """Fetch and parse, compute diff. Does NOT apply."""
    sub = get_subscription(sub_id)
    if not sub:
        return {"ok": False, "error": "Not found"}

    try:
        result = await fetch_subscription(sub["url"], sub.get("user_agent"))
    except Exception as exc:
        _record_fetch(sub_id, ok=False, error=str(exc))
        return {"ok": False, "error": str(exc)}

    body = result["body"]
    try:
        uris = decode_body(body)
    except Exception as exc:
        _record_fetch(sub_id, ok=False, error=str(exc), **result)
        return {"ok": False, "error": f"Decode error: {exc}"}

    if not uris:
        _record_fetch(sub_id, ok=False, error="Zero servers parsed", **result)
        return {"ok": False, "error": "Subscription returned zero servers — not applying"}

    meta = parse_metadata_headers(result["headers"], body)

    # Parse each URI
    parsed: list[dict] = []
    warnings: list[str] = []
    for uri in uris:
        try:
            info = parse_uri(uri)
            info["raw_uri"] = uri
            parsed.append(info)
        except Exception as exc:
            warnings.append(f"Parse error: {exc} — {uri[:60]}")

    if not parsed:
        return {"ok": False, "error": "All URIs failed to parse: " + "; ".join(warnings)}

    # Compute diff against stored servers
    with get_db() as conn:
        stored = {
            row["identity_hash"]: dict(row)
            for row in conn.execute(
                "SELECT * FROM servers WHERE subscription_id=?", (sub_id,)
            ).fetchall()
        }

    incoming_hashes: set[str] = set()
    for p in parsed:
        h = identity_hash(p["protocol"], p["host"], p["port"], p["secret"])
        p["hash"] = h
        incoming_hashes.add(h)

    added = [p for p in parsed if p["hash"] not in stored]
    removed_hashes = set(stored.keys()) - incoming_hashes
    removed = [stored[h]["label"] for h in removed_hashes]

    diff = {
        "added": len(added),
        "removed": len(removed),
        "unchanged": len(parsed) - len(added),
        "added_labels": [p["label"] for p in added][:10],
        "removed_labels": removed[:10],
        "warnings": warnings,
        "total": len(parsed),
    }

    _record_fetch(
        sub_id,
        ok=True,
        server_count=len(parsed),
        diff_summary=json.dumps(diff),
        **result,
    )
    _update_sub_meta(sub_id, meta, result)

    return {
        "ok": True,
        "diff": diff,
        "parsed": parsed,
        "meta": meta,
        "user_agent": result["user_agent"],
        "via": result["via"],
    }


def store_servers(sub_id: int, parsed: list[dict], meta: Optional[dict] = None) -> None:
    """Persist parsed servers to DB and mark non-present ones."""
    now = int(time.time())
    with get_write_db() as conn:
        existing = {
            row["identity_hash"]: dict(row)
            for row in conn.execute(
                "SELECT * FROM servers WHERE subscription_id=?", (sub_id,)
            ).fetchall()
        }
        incoming_hashes: set[str] = set()

        for i, p in enumerate(parsed):
            h = p.get("hash") or identity_hash(p["protocol"], p["host"], p["port"], p["secret"])
            incoming_hashes.add(h)
            ob = p["outbound"].copy()

            if h in existing:
                tag = existing[h]["outbound_tag"]
                ob["tag"] = tag
                conn.execute(
                    """UPDATE servers SET label=?, outbound_json=?, raw_uri=?, last_seen_at=?, is_present=1
                       WHERE subscription_id=? AND identity_hash=?""",
                    (p["label"], json.dumps(ob), p["raw_uri"], now, sub_id, h),
                )
            else:
                tag = _make_tag(sub_id, p["label"], i + 1)
                ob["tag"] = tag
                conn.execute(
                    """INSERT OR IGNORE INTO servers
                       (subscription_id, identity_hash, outbound_tag, label, protocol,
                        server_host, server_port, outbound_json, raw_uri, first_seen_at, last_seen_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        sub_id, h, tag, p["label"], p["protocol"],
                        p["host"], p["port"], json.dumps(ob), p["raw_uri"], now, now,
                    ),
                )

        # Soft-delete gone servers
        for h, row in existing.items():
            if h not in incoming_hashes:
                conn.execute(
                    "UPDATE servers SET is_present=0 WHERE id=?", (row["id"],)
                )


def set_active_subscription(sub_id: int) -> None:
    with get_write_db() as conn:
        conn.execute("UPDATE subscriptions SET is_active=0")
        conn.execute("UPDATE subscriptions SET is_active=1 WHERE id=?", (sub_id,))


def _record_fetch(
    sub_id: int,
    ok: bool,
    via: Optional[str] = None,
    user_agent: Optional[str] = None,
    http_status: Optional[int] = None,
    server_count: Optional[int] = None,
    diff_summary: Optional[str] = None,
    error: Optional[str] = None,
    **_: object,
) -> None:
    now = int(time.time())
    with get_write_db() as conn:
        conn.execute(
            """INSERT INTO fetch_log
               (subscription_id, ts, ok, via, user_agent, http_status, server_count, diff_summary, error)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (sub_id, now, int(ok), via, user_agent, http_status, server_count, diff_summary, error),
        )
        conn.execute(
            """UPDATE subscriptions
               SET last_fetch_at=?, last_fetch_ok=?, last_fetch_via=?, last_error=?
               WHERE id=?""",
            (now, int(ok), via, error if not ok else None, sub_id),
        )
        if user_agent:
            conn.execute(
                "UPDATE subscriptions SET user_agent=? WHERE id=?", (user_agent, sub_id)
            )


def _update_sub_meta(sub_id: int, meta: dict, fetch_result: dict) -> None:
    with get_write_db() as conn:
        conn.execute(
            """UPDATE subscriptions
               SET update_interval_h=COALESCE(?,update_interval_h),
                   quota_total=COALESCE(?,quota_total),
                   quota_upload=COALESCE(?,quota_upload),
                   quota_download=COALESCE(?,quota_download),
                   expires_at=COALESCE(?,expires_at)
               WHERE id=?""",
            (
                meta.get("update_interval_h"),
                meta.get("quota_total"),
                meta.get("quota_upload"),
                meta.get("quota_download"),
                meta.get("expires_at"),
                sub_id,
            ),
        )
