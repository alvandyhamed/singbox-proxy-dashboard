"""
sing-box config management: render, validate, staging-probe, atomic apply, rollback.
Keep this module free of web concerns so it can be tested from a REPL.
"""
import asyncio
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional

from .config import settings
from .db import get_db

_apply_lock = asyncio.Lock()


# ─── Config rendering ──────────────────────────────────────────────────────────


def render_config(
    servers: list[dict],
    extra_clash_port: Optional[int] = None,
    extra_inbound_port: Optional[int] = None,
    cache_path: Optional[str] = None,
) -> dict:
    """Render a complete sing-box config dict from a list of server dicts."""
    inbound_port = extra_inbound_port or settings.proxy_port
    clash_port = extra_clash_port or 9090

    outbound_tags = [s["outbound_tag"] for s in servers]
    server_outbounds = [json.loads(s["outbound_json"]) for s in servers]

    outbounds: list[dict] = []
    if outbound_tags:
        outbounds.append(
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["auto"] + outbound_tags,
                "default": "auto",
                "interrupt_exist_connections": False,
            }
        )
        outbounds.append(
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": outbound_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m",
                "tolerance": 100,
            }
        )
    else:
        outbounds.append({"type": "direct", "tag": "proxy"})

    outbounds.extend(server_outbounds)
    outbounds.append({"type": "direct", "tag": "direct"})

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "local-in",
                "listen": "127.0.0.1",
                "listen_port": inbound_port,
            },
            {
                "type": "mixed",
                "tag": "docker-in",
                "listen": "172.17.0.1",
                "listen_port": inbound_port,
            },
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [{"rule_set": "proxied", "outbound": "proxy"}],
            "rule_set": [
                {
                    "type": "local",
                    "tag": "proxied",
                    "format": "source",
                    "path": settings.singbox_ruleset,
                }
            ],
            "final": "direct",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": cache_path or "/var/lib/sing-box/cache.db",
            },
            "clash_api": {
                "external_controller": f"127.0.0.1:{clash_port}",
                "secret": settings.clash_api_secret,
            },
        },
    }


def render_ruleset(rules: list[dict]) -> dict:
    """Render rule-set source JSON from rules rows."""
    domain_exact: list[str] = []
    domain_suffix: list[str] = []
    domain_keyword: list[str] = []
    ip_cidr: list[str] = []

    for r in rules:
        if not r["enabled"]:
            continue
        kind = r["kind"]
        val = r["value"]
        if kind == "domain":
            domain_exact.append(val)
        elif kind == "domain_suffix":
            domain_suffix.append(val)
        elif kind == "domain_keyword":
            domain_keyword.append(val)
        elif kind == "ip_cidr":
            ip_cidr.append(val)

    rule: dict = {}
    if domain_exact:
        rule["domain"] = domain_exact
    if domain_suffix:
        rule["domain_suffix"] = domain_suffix
    if domain_keyword:
        rule["domain_keyword"] = domain_keyword
    if ip_cidr:
        rule["ip_cidr"] = ip_cidr

    return {"version": 3, "rules": [rule] if rule else []}


# ─── Subprocess helpers ────────────────────────────────────────────────────────


async def _run(cmd: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode(), stderr.decode()
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", "Timed out"


async def check_config(path: str) -> tuple[bool, str]:
    """Run sing-box check. Returns (ok, message)."""
    rc, out, err = await _run([settings.singbox_bin, "check", "-c", path])
    if rc == 0:
        return True, "OK"
    return False, (err or out).strip()


async def _singbox_version() -> str:
    rc, out, _ = await _run([settings.singbox_bin, "version"])
    return out.strip() if rc == 0 else "unknown"


def _container_name() -> Optional[str]:
    return os.environ.get("SINGBOX_CONTAINER_NAME")


def _docker_action_sync(action: str, container: str) -> tuple[bool, str]:
    import docker as _docker
    try:
        client = _docker.from_env()
        c = client.containers.get(container)
        if action == "restart":
            c.restart(timeout=15)
            return True, "Restarted"
        elif action == "is-active":
            c.reload()
            return c.status == "running", c.status
    except Exception as exc:
        return False, str(exc)
    return False, "Unknown action"


async def _systemctl(cmd: str) -> tuple[bool, str]:
    container = _container_name()
    if container:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _docker_action_sync, cmd, container)
    rc, out, err = await _run(
        ["sudo", "/bin/systemctl", cmd, "sing-box"], timeout=30.0
    )
    return rc == 0, (err or out).strip()


async def unit_active() -> bool:
    container = _container_name()
    if container:
        loop = asyncio.get_event_loop()
        ok, _ = await loop.run_in_executor(None, _docker_action_sync, "is-active", container)
        return ok
    rc, out, _ = await _run(["sudo", "/bin/systemctl", "is-active", "sing-box"])
    return out.strip() == "active"


# ─── Staging validation ────────────────────────────────────────────────────────


def _kill_stale_staging() -> None:
    """Kill any sing-box process that still holds the staging ports."""
    import signal as _sig
    staging_ports = {settings.staging_port, settings.staging_api_port}
    try:
        for pid_s in os.listdir("/proc"):
            if not pid_s.isdigit():
                continue
            try:
                cmdline = open(f"/proc/{pid_s}/cmdline").read()
                if "sing-box" not in cmdline or "run" not in cmdline:
                    continue
                net = open(f"/proc/{pid_s}/net/tcp").read()
                for port in staging_ports:
                    if f"{port:04X}".upper() in net.upper():
                        os.kill(int(pid_s), _sig.SIGKILL)
                        break
            except OSError:
                pass
    except OSError:
        pass


def _pick_staging_server(servers: list[dict]) -> Optional[dict]:
    """Pick the first server that has TLS configured (skips fake info nodes)."""
    for s in servers:
        ob = json.loads(s["outbound_json"]) if isinstance(s.get("outbound_json"), str) else (s.get("outbound_json") or {})
        if ob.get("tls"):
            return s
    return servers[0] if servers else None


async def staging_validate(servers: list[dict]) -> tuple[bool, str]:
    """
    Run a minimal single-server staging config to validate connectivity,
    then return. The full production config (selector + urltest) is applied
    only after this passes.
    Returns (ok, message).
    """
    import httpx

    _kill_stale_staging()

    probe_server = _pick_staging_server(servers)
    if not probe_server:
        return False, "No servers to validate"

    ob = json.loads(probe_server["outbound_json"]) if isinstance(probe_server.get("outbound_json"), str) else (probe_server.get("outbound_json") or {})

    # Minimal single-server config — no selector/urltest overhead, instant routing.
    stg_cfg = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "local-in", "listen": "127.0.0.1", "listen_port": settings.staging_port}],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {"final": ob["tag"]},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="sb-staging-") as f:
        json.dump(stg_cfg, f, indent=2)
        cfg_path = f.name

    proc = None
    try:
        ok, msg = await check_config(cfg_path)
        if not ok:
            return False, f"sing-box check failed: {msg}"

        proc = await asyncio.create_subprocess_exec(
            settings.singbox_bin, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        await asyncio.sleep(3)

        if proc.returncode is not None:
            return False, "Staging process exited immediately"

        proxy_url = f"socks5://127.0.0.1:{settings.staging_port}"
        targets = settings.health_targets[:2] or ["https://api.telegram.org"]
        errors = []

        async with httpx.AsyncClient(proxy=proxy_url, timeout=30.0) as client:
            for target in targets:
                try:
                    r = await client.get(target)
                    if r.status_code >= 500:
                        errors.append(f"{target}: HTTP {r.status_code}")
                except Exception as exc:
                    errors.append(f"{target}: {exc}")

        if errors:
            return False, "Staging probes failed: " + "; ".join(errors)

        return True, "Staging validation passed"

    finally:
        if proc and proc.returncode is None:
            proc.kill()
            await proc.wait()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


# ─── Atomic apply and rollback ─────────────────────────────────────────────────


async def apply_config(servers: list[dict], src_ip: Optional[str] = None) -> dict:
    """
    Full apply: staging validate → backup → atomic write → restart → verify → rollback on failure.
    Returns result dict.
    Must be called under _apply_lock.
    """
    from . import audit

    config_path = Path(settings.singbox_config)
    backup_path = config_path.with_suffix(".json.bak")
    tmp_path = config_path.with_name("config.json.tmp")

    # Staging
    staging_ok, staging_msg = await staging_validate(servers)
    if not staging_ok:
        audit.log("config.apply", {"stage": "staging_failed", "error": staging_msg}, ok=False, src_ip=src_ip)
        return {"ok": False, "error": staging_msg, "rolled_back": False}

    # Render final config
    cfg = render_config(servers)
    cfg_json = json.dumps(cfg, indent=2)

    # Backup current
    last_good_ts = None
    if config_path.exists():
        shutil.copy2(config_path, backup_path)
        last_good_ts = int(config_path.stat().st_mtime)

    # Atomic write
    tmp_path.write_text(cfg_json)
    os.replace(tmp_path, config_path)

    # Restart
    restart_ok, restart_msg = await _systemctl("restart")
    if not restart_ok:
        # Rollback
        if backup_path.exists():
            os.replace(backup_path, config_path)
            await _systemctl("restart")
        audit.log("config.apply", {"stage": "restart_failed", "error": restart_msg}, ok=False, src_ip=src_ip)
        return {"ok": False, "error": f"Restart failed: {restart_msg}", "rolled_back": True}

    # Post-restart probe
    await asyncio.sleep(3)
    ok = await unit_active()
    if not ok:
        # Rollback
        rolled_back = False
        rb_msg = ""
        if backup_path.exists():
            os.replace(backup_path, config_path)
            _, rb_msg = await _systemctl("restart")
            rolled_back = True
        stale_msg = ""
        if last_good_ts:
            age_h = (time.time() - last_good_ts) / 3600
            stale_msg = f" Previous config last worked {age_h:.1f}h ago and may also be expired."
        msg = f"sing-box failed to start after restart.{stale_msg}"
        audit.log("config.apply", {"stage": "verify_failed", "rolled_back": rolled_back}, ok=False, src_ip=src_ip)
        return {"ok": False, "error": msg, "rolled_back": rolled_back}

    audit.log("config.apply", {"servers": len(servers)}, ok=True, src_ip=src_ip)
    return {"ok": True, "error": None, "rolled_back": False}


async def safe_apply(servers: list[dict], src_ip: Optional[str] = None) -> dict:
    """Acquire apply lock, return 409 if busy."""
    if _apply_lock.locked():
        return {"ok": False, "error": "Another apply is already in progress", "busy": True}
    async with _apply_lock:
        return await apply_config(servers, src_ip=src_ip)
