"""Routing rules management."""
import json
import re
import time
from typing import Optional

from .db import get_db, get_write_db
from .singbox import render_ruleset

VALID_KINDS = {"domain", "domain_suffix", "domain_keyword", "ip_cidr"}

# Rules staged in memory between edits and the next apply
_staged_changes: list[dict] = []


def validate_rule(kind: str, value: str) -> Optional[str]:
    if kind not in VALID_KINDS:
        return f"Invalid kind '{kind}'"
    value = value.strip()
    if not value:
        return "Value is empty"
    # Strip scheme prefixes users commonly paste
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0]
    if kind in ("domain", "domain_suffix"):
        if value.startswith("."):
            return "Leading dot — use domain_suffix and omit the dot"
        if " " in value or not re.match(r"^[a-zA-Z0-9.\-]+$", value):
            return "Invalid domain characters"
    elif kind == "domain_keyword" and len(value) < 4:
        return "Keyword too short — will over-match"
    elif kind == "ip_cidr":
        if not re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$|^[0-9a-fA-F:]+(/\d+)?$", value):
            return "Invalid CIDR notation"
    return None


def clean_value(kind: str, value: str) -> str:
    value = value.strip()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].strip()
    return value


def get_rules() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM rules ORDER BY sort_order, id"
        ).fetchall()
        return [dict(r) for r in rows]


def add_rule(kind: str, value: str, note: str = "") -> dict:
    value = clean_value(kind, value)
    err = validate_rule(kind, value)
    if err:
        return {"ok": False, "error": err}
    now = int(time.time())
    try:
        with get_write_db() as conn:
            cur = conn.execute(
                "INSERT INTO rules (kind, value, note, created_at) VALUES (?,?,?,?)",
                (kind, value, note or None, now),
            )
            return {"ok": True, "id": cur.lastrowid}
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return {"ok": False, "error": "Rule already exists"}
        return {"ok": False, "error": str(exc)}


def toggle_rule(rule_id: int, enabled: bool) -> bool:
    with get_write_db() as conn:
        cur = conn.execute(
            "UPDATE rules SET enabled=? WHERE id=?", (int(enabled), rule_id)
        )
        return cur.rowcount > 0


def delete_rule(rule_id: int) -> bool:
    with get_write_db() as conn:
        cur = conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        return cur.rowcount > 0


def pending_diff() -> dict:
    """Compare what's in DB against what's applied (last written ruleset)."""
    rules = get_rules()
    return {
        "count": len([r for r in rules if r["enabled"]]),
        "total": len(rules),
    }


async def apply_rules(src_ip: Optional[str] = None) -> dict:
    """Write rule-set JSON and restart sing-box."""
    from pathlib import Path
    from . import audit
    from .config import settings
    from .singbox import safe_apply
    from .profiles import get_active_servers

    rules = get_rules()
    ruleset = render_ruleset(rules)

    ruleset_path = Path(settings.singbox_ruleset)
    ruleset_path.parent.mkdir(parents=True, exist_ok=True)
    ruleset_path.write_text(json.dumps(ruleset, indent=2))

    servers = get_active_servers()
    result = await safe_apply(servers, src_ip=src_ip)
    audit.log("rules.apply", {"enabled": pending_diff()["count"]}, ok=result["ok"], src_ip=src_ip)
    return result
