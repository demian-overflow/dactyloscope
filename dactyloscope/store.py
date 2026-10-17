"""On-disk report and baseline storage (one JSON file per report).

Files are deliberately plain JSON so an agent can ``cat``/``jq`` them; the
index is rebuilt from the directory on start-up.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any


def new_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


class Store:
    def __init__(self, root: Path, keep: int = 500) -> None:
        self.root = root
        self.reports_dir = root / "reports"
        self.baselines_dir = root / "baselines"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        self.keep = keep
        self._lock = threading.Lock()
        self._live: dict[str, dict[str, Any]] = {}
        self._waiters: dict[str, list[asyncio.Future]] = {}

    # ---- reports -----------------------------------------------------
    def _path(self, rid: str) -> Path:
        if not rid or "/" in rid or ".." in rid:
            raise KeyError(rid)
        return self.reports_dir / f"{rid}.json"

    def put(self, report: dict[str, Any]) -> None:
        rid = report["id"]
        with self._lock:
            self._live[rid] = report
            tmp = self._path(rid).with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=1, sort_keys=False, default=str))
            os.replace(tmp, self._path(rid))
        self._notify(rid, report)

    def get(self, rid: str) -> dict[str, Any] | None:
        with self._lock:
            if rid in self._live:
                return self._live[rid]
            p = self._path(rid)
            if p.is_file():
                try:
                    r = json.loads(p.read_text())
                except json.JSONDecodeError:
                    return None
                self._live[rid] = r
                return r
        return None

    def delete(self, rid: str) -> bool:
        with self._lock:
            self._live.pop(rid, None)
            p = self._path(rid)
            if p.is_file():
                p.unlink()
                return True
        return False

    def list(self, tag: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.reports_dir.glob("*.json"), reverse=True):
            r = self.get(p.stem)
            if not r:
                continue
            if tag and r.get("tag") != tag:
                continue
            out.append(summary_of(r))
            if len(out) >= limit:
                break
        return out

    def latest(self, tag: str | None = None, done_only: bool = True) -> dict[str, Any] | None:
        for p in sorted(self.reports_dir.glob("*.json"), reverse=True):
            r = self.get(p.stem)
            if not r:
                continue
            if tag and r.get("tag") != tag:
                continue
            if done_only and not r.get("done"):
                continue
            return r
        return None

    def prune(self) -> None:
        files = sorted(self.reports_dir.glob("*.json"))
        for p in files[:-self.keep] if len(files) > self.keep else []:
            try:
                p.unlink()
                self._live.pop(p.stem, None)
            except OSError:
                pass

    # ---- waiting for completion (long poll) ---------------------------
    async def wait_done(self, rid: str, timeout: float) -> dict[str, Any] | None:
        r = self.get(rid)
        if r is None or r.get("done"):
            return r
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._waiters.setdefault(rid, []).append(fut)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return self.get(rid)
        finally:
            ws = self._waiters.get(rid)
            if ws and fut in ws:
                ws.remove(fut)

    async def wait_latest(self, tag: str | None, timeout: float, after: str | None = None) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            r = self.latest(tag)
            if r and self._is_after(r, after):
                return r
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.5)

    @staticmethod
    def _is_after(r: dict[str, Any], after: str | None) -> bool:
        """`after` is either a report id or a unix timestamp (seconds)."""
        if not after:
            return True
        if after.replace(".", "", 1).isdigit() and "-" not in after:
            return float(r.get("created_ts") or 0) >= float(after)
        return r["id"] > after

    def _notify(self, rid: str, report: dict[str, Any]) -> None:
        if not report.get("done"):
            return
        for fut in self._waiters.pop(rid, []):
            if not fut.done():
                fut.set_result(report)

    # ---- baselines ----------------------------------------------------
    def _bpath(self, name: str) -> Path:
        if not name or "/" in name or ".." in name or not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise KeyError(name)
        return self.baselines_dir / f"{name}.json"

    def put_baseline(self, name: str, report: dict[str, Any]) -> None:
        self._bpath(name).write_text(json.dumps(report, indent=1, default=str))

    def get_baseline(self, name: str) -> dict[str, Any] | None:
        p = self._bpath(name)
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            return None

    def delete_baseline(self, name: str) -> bool:
        p = self._bpath(name)
        if p.is_file():
            p.unlink()
            return True
        return False

    def list_baselines(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.baselines_dir.glob("*.json")):
            r = self.get_baseline(p.stem)
            if r:
                s = summary_of(r)
                s["name"] = p.stem
                out.append(s)
        return out


def summary_of(r: dict[str, Any]) -> dict[str, Any]:
    a = r.get("analysis") or {}
    net = r.get("network") or {}
    return {
        "id": r.get("id"),
        "created": r.get("created"),
        "created_ts": r.get("created_ts"),
        "done": bool(r.get("done")),
        "tag": r.get("tag"),
        "label": r.get("label"),
        "client_ip": (r.get("client") or {}).get("ip"),
        "user_agent": ((net.get("http") or {}).get("user_agent")),
        "ja3": ((net.get("tls") or {}).get("ja3") or {}).get("hash"),
        "ja4": ((net.get("tls") or {}).get("ja4") or {}).get("hash"),
        "akamai": ((net.get("h2") or {}).get("akamai_fingerprint")),
        "score": a.get("score"),
        "verdict": a.get("verdict"),
        "counts": a.get("counts"),
        "claimed": (a.get("identity") or {}).get("claimed"),
        "detected_engine": (a.get("identity") or {}).get("js_engine"),
    }
