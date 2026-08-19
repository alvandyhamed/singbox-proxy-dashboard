import json
import time
from typing import Any, Optional

from .db import get_write_db


def log(action: str, detail: Any = None, ok: bool = True, src_ip: Optional[str] = None) -> None:
    detail_str = json.dumps(detail, default=str) if detail is not None else None
    with get_write_db() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, action, detail, ok, src_ip) VALUES (?, ?, ?, ?, ?)",
            (int(time.time()), action, detail_str, int(ok), src_ip),
        )
