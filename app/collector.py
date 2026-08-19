"""Background traffic collector: subscribes to Clash API /connections WebSocket."""
import asyncio
import json
import time
from collections import deque
from typing import Any, Optional

import websockets

from .clash import ws_url
from .config import settings
from .db import get_write_db


class CollectorState:
    def __init__(self) -> None:
        self.traffic_ring: deque[dict] = deque(maxlen=600)  # last 10 min, 1s buckets
        self.live_connections: dict[str, dict] = {}
        self.running = False
        self.last_error: Optional[str] = None
        self.clients: set = set()  # WebSocket clients from dashboard

    def broadcast(self, msg: dict) -> None:
        dead = set()
        for ws in self.clients:
            try:
                asyncio.ensure_future(ws.send_text(json.dumps(msg)))
            except Exception:
                dead.add(ws)
        self.clients -= dead


collector_state = CollectorState()

_BUCKET_SIZE = 10  # seconds
_prev: dict[str, dict] = {}
_bucket_up: int = 0
_bucket_down: int = 0
_bucket_ts: int = 0


def _bucket_now() -> int:
    return (int(time.time()) // _BUCKET_SIZE) * _BUCKET_SIZE


def _process_snapshot(data: dict) -> None:
    global _prev, _bucket_up, _bucket_down, _bucket_ts

    now = int(time.time())
    bucket = _bucket_now()
    if bucket != _bucket_ts:
        if _bucket_ts:
            _flush_bucket(_bucket_ts, _bucket_up, _bucket_down)
        _bucket_ts = bucket
        _bucket_up = 0
        _bucket_down = 0

    conns = data.get("connections") or []
    seen: set[str] = set()

    host_deltas: dict[tuple, dict] = {}

    for c in conns:
        cid = c.get("id", "")
        seen.add(cid)
        meta = c.get("metadata", {})
        host = meta.get("host") or meta.get("destinationIP") or ""
        dest_ip = meta.get("destinationIP", "")
        dest_port = int(meta.get("destinationPort") or 0)
        network = meta.get("network", "")
        chains = c.get("chains", [])
        outbound = chains[0] if chains else ""
        node = chains[-1] if len(chains) > 1 else outbound
        rule = c.get("rule", "")
        started_str = c.get("start", "")
        up = c.get("upload", 0)
        down = c.get("download", 0)

        if cid in _prev:
            d_up = max(0, up - _prev[cid]["up"])
            d_down = max(0, down - _prev[cid]["down"])
        else:
            d_up, d_down = up, down
            _open_connection(cid, host, dest_ip, dest_port, network, outbound, rule, started_str)

        _bucket_up += d_up
        _bucket_down += d_down

        key = (host or dest_ip, outbound)
        if key not in host_deltas:
            host_deltas[key] = {"up": 0, "down": 0, "count": 0, "attributed": bool(host)}
        host_deltas[key]["up"] += d_up
        host_deltas[key]["down"] += d_down
        host_deltas[key]["count"] += 1

        _prev[cid] = {"up": up, "down": down}

        collector_state.live_connections[cid] = {
            "id": cid,
            "host": host,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "network": network,
            "outbound": outbound,
            "node": node,
            "rule": rule,
            "upload": up,
            "download": down,
            "start": started_str,
        }

    for gone in set(_prev.keys()) - seen:
        _close_connection(gone, _prev[gone]["up"], _prev[gone]["down"], now)
        del _prev[gone]
        collector_state.live_connections.pop(gone, None)

    if host_deltas:
        _flush_host_deltas(bucket, host_deltas)

    # global traffic sample every 10 s
    ts_sample = now - (now % 10)
    collector_state.traffic_ring.append(
        {"ts": ts_sample, "up": _bucket_up, "down": _bucket_down}
    )

    # broadcast to dashboard WebSocket clients
    collector_state.broadcast(
        {
            "type": "traffic",
            "up": _bucket_up,
            "down": _bucket_down,
            "ts": now,
            "connections": list(collector_state.live_connections.values())[:200],
        }
    )


def _open_connection(cid, host, dest_ip, dest_port, network, outbound, rule, started_str) -> None:
    import email.utils

    try:
        ts = int(time.fromisoformat(started_str.replace("Z", "+00:00")).timestamp()) if started_str else int(time.time())
    except Exception:
        ts = int(time.time())

    try:
        with get_write_db() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO connections
                   (id, host, dest_ip, dest_port, network, outbound, matched_rule, started_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (cid, host, dest_ip, dest_port, network, outbound, rule, ts),
            )
    except Exception:
        pass


def _close_connection(cid: str, up: int, down: int, ts: int) -> None:
    try:
        with get_write_db() as conn:
            conn.execute(
                "UPDATE connections SET ended_at=?, up_bytes=?, down_bytes=? WHERE id=?",
                (ts, up, down, cid),
            )
    except Exception:
        pass


def _flush_bucket(ts: int, up: int, down: int) -> None:
    try:
        with get_write_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO traffic_samples (ts, up_bytes, down_bytes) VALUES (?,?,?)",
                (ts, up, down),
            )
    except Exception:
        pass


def _flush_host_deltas(bucket: int, deltas: dict) -> None:
    try:
        with get_write_db() as conn:
            for (host, outbound), v in deltas.items():
                conn.execute(
                    """INSERT INTO host_traffic (bucket_ts, host, attributed, outbound, up_bytes, down_bytes, conn_count)
                       VALUES (?,?,?,?,?,?,?)
                       ON CONFLICT(bucket_ts, host, outbound)
                       DO UPDATE SET up_bytes=up_bytes+excluded.up_bytes,
                                     down_bytes=down_bytes+excluded.down_bytes,
                                     conn_count=conn_count+excluded.conn_count""",
                    (bucket, host, int(v["attributed"]), outbound, v["up"], v["down"], v["count"]),
                )
    except Exception:
        pass


# ─── Server-wide network collector ────────────────────────────────────────────


class NetState:
    def __init__(self) -> None:
        self.ring: deque[dict] = deque(maxlen=600)
        self.iface: str = ""
        self.clients: set = set()
        self.container_stats: list[dict] = []

    def broadcast(self, msg: dict) -> None:
        dead = set()
        for ws in self.clients:
            try:
                asyncio.ensure_future(ws.send_text(json.dumps(msg)))
            except Exception:
                dead.add(ws)
        self.clients -= dead


net_state = NetState()

_net_minute_ts: int = 0
_net_minute_rx: int = 0
_net_minute_tx: int = 0


def _flush_net_sample(ts: int, rx: int, tx: int) -> None:
    try:
        with get_write_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO server_net_samples (ts, rx_bytes, tx_bytes) VALUES (?,?,?)",
                (ts, rx, tx),
            )
    except Exception:
        pass


def _read_proc_net() -> dict[str, dict]:
    result: dict[str, dict] = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                fields = data.split()
                if len(fields) >= 9:
                    result[iface.strip()] = {"rx": int(fields[0]), "tx": int(fields[8])}
    except OSError:
        pass
    return result


def _main_iface(stats: dict) -> str:
    skip_prefix = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap")
    best, best_bytes = "", 0
    for iface, v in stats.items():
        if any(iface.startswith(p) for p in skip_prefix):
            continue
        total = v["rx"] + v["tx"]
        if total > best_bytes:
            best_bytes, best = total, iface
    return best


async def run_net_collector() -> None:
    global _net_minute_ts, _net_minute_rx, _net_minute_tx
    prev: dict = {}
    prev_ts: float = 0.0
    while True:
        await asyncio.sleep(1)
        try:
            stats = _read_proc_net()
            now = time.time()
            iface = _main_iface(stats)
            if not iface or iface not in stats:
                continue
            net_state.iface = iface
            if prev and iface in prev and prev_ts:
                dt = max(now - prev_ts, 0.1)
                actual_rx = max(0, stats[iface]["rx"] - prev[iface]["rx"])
                actual_tx = max(0, stats[iface]["tx"] - prev[iface]["tx"])
                rx = int(actual_rx / dt)
                tx = int(actual_tx / dt)
                sample = {"ts": int(now), "rx": rx, "tx": tx}
                net_state.ring.append(sample)
                net_state.broadcast({"type": "net", "iface": iface, "rx": rx, "tx": tx, "ts": int(now)})
                # accumulate into minute bucket
                min_ts = int(now) // 60 * 60
                if min_ts != _net_minute_ts:
                    if _net_minute_ts:
                        _flush_net_sample(_net_minute_ts, _net_minute_rx, _net_minute_tx)
                    _net_minute_ts = min_ts
                    _net_minute_rx = 0
                    _net_minute_tx = 0
                _net_minute_rx += actual_rx
                _net_minute_tx += actual_tx
            prev = stats
            prev_ts = now
        except Exception:
            pass


def _fetch_container_stats() -> list[dict]:
    try:
        import docker
        client = docker.from_env()
        result = []
        for c in client.containers.list():
            try:
                raw = c.stats(stream=False)
                networks = raw.get("networks", {})
                rx = sum(n.get("rx_bytes", 0) for n in networks.values())
                tx = sum(n.get("tx_bytes", 0) for n in networks.values())
                result.append({"id": c.id, "name": c.name, "rx": rx, "tx": tx})
            except Exception:
                pass
        return result
    except Exception:
        return []


async def run_container_collector() -> None:
    prev: dict[str, dict] = {}
    while True:
        await asyncio.sleep(60)
        try:
            loop = asyncio.get_event_loop()
            stats = await loop.run_in_executor(None, _fetch_container_stats)
            result = []
            for s in stats:
                cid = s["id"]
                p = prev.get(cid)
                delta_rx = max(0, s["rx"] - p["rx"]) if p else 0
                delta_tx = max(0, s["tx"] - p["tx"]) if p else 0
                prev[cid] = {"rx": s["rx"], "tx": s["tx"]}
                result.append({
                    "name": s["name"],
                    "rx_total": s["rx"],
                    "tx_total": s["tx"],
                    "rx_delta": delta_rx,
                    "tx_delta": delta_tx,
                })
            result.sort(key=lambda x: -(x["rx_total"] + x["tx_total"]))
            net_state.container_stats = result
        except Exception:
            pass


async def run_collector() -> None:
    collector_state.running = True
    backoff = 1.0
    while True:
        try:
            url = await ws_url("/connections")
            async with websockets.connect(url, ping_interval=30) as ws:
                # Reset state on new connection (sing-box restart resets IDs)
                _prev.clear()
                collector_state.live_connections.clear()
                backoff = 1.0
                collector_state.last_error = None
                async for msg in ws:
                    data = json.loads(msg)
                    _process_snapshot(data)
        except asyncio.CancelledError:
            collector_state.running = False
            return
        except Exception as exc:
            collector_state.last_error = str(exc)
            await asyncio.sleep(min(backoff, 60))
            backoff = min(backoff * 2, 60)
