"""Drive a WebDriver-speaking browser through a Dactyloscope probe run."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class WebDriver:
    def __init__(self, base: str, timeout: float = 30) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sid: str | None = None

    def _req(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read())
            except json.JSONDecodeError:
                return {"value": {"error": str(e)}}

    def wait_ready(self, timeout: float = 90) -> None:
        deadline = time.time() + timeout
        last: Any = None
        while time.time() < deadline:
            try:
                r = self._req("GET", "/status")
                if r.get("value", {}).get("ready"):
                    return
                last = r
            except Exception as e:  # noqa: BLE001
                last = str(e)
            time.sleep(1)
        raise TimeoutError(f"WebDriver at {self.base} not ready: {last}")

    def new_session(self, capabilities: dict[str, Any] | None = None) -> str:
        r = self._req("POST", "/session", {"capabilities": capabilities or {}})
        sid = r.get("value", {}).get("sessionId")
        if not sid:
            raise RuntimeError(f"session creation failed: {r}")
        self.sid = sid
        return sid

    def navigate(self, url: str) -> None:
        self._req("POST", f"/session/{self.sid}/url", {"url": url})

    def execute(self, script: str, args: list | None = None) -> Any:
        return self._req("POST", f"/session/{self.sid}/execute/sync", {"script": script, "args": args or []}).get("value")

    def quit(self) -> None:
        if self.sid:
            self._req("DELETE", f"/session/{self.sid}")
            self.sid = None


_READ_PAGE = """return {report: window.__DACTY_REPORT__ || null, seed: window.__DACTY_SEED__ || null,
               probes: window.__DACTY_RESULTS__ || null};"""


def run_probe(webdriver_url: str, server_url: str, label: str | None = None, wait: float = 120,
              capabilities: dict[str, Any] | None = None, keep_session: bool = False) -> dict[str, Any]:
    """Open the probe page in the browser behind ``webdriver_url`` and return the report the page ends up holding.

    The server keeps nothing, so the report is read out of the page itself. If the probes don't finish within
    ``wait`` seconds, the sections that did finish are analysed locally and returned with ``done: false``.
    """
    wd = WebDriver(webdriver_url)
    wd.wait_ready()
    wd.new_session(capabilities)
    started = time.time()
    try:
        wd.navigate(f"{server_url}/" + (f"?label={urllib.parse.quote(label)}" if label else ""))
        page: dict[str, Any] = {}
        while time.time() - started < wait:
            page = wd.execute(_READ_PAGE) or {}
            if isinstance(page, dict) and page.get("report"):
                break
            time.sleep(1)
        report = page.get("report") if isinstance(page, dict) else None
        if not report or not report.get("analysis"):
            seed = (page or {}).get("seed") if isinstance(page, dict) else None
            if not seed:
                raise RuntimeError(f"the probe page never loaded; did the browser reach {server_url}?")
            from .analysis import analyse
            from .known import KnownShapes
            probes = page.get("probes") or {}
            report = dict(seed, done=False, probes=probes,
                          analysis=analyse(probes, seed["network"], KnownShapes().load()))
        report["_probe_wall_s"] = round(time.time() - started, 1)
        return report
    finally:
        if not keep_session:
            wd.quit()
