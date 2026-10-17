"""Drive a WebDriver-speaking browser through a Dactyloscope probe run."""
from __future__ import annotations

import json
import ssl
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


def server_get(url: str, timeout: float = 90, text: bool = False) -> Any:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"accept": "text/plain" if text else "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        body = r.read()
        return body.decode() if text else json.loads(body)


def run_probe(webdriver_url: str, server_url: str, tag: str, wait: float = 120, capabilities: dict[str, Any] | None = None,
              keep_session: bool = False) -> dict[str, Any]:
    """Open the probe page in the browser behind ``webdriver_url`` and return the finished report."""
    wd = WebDriver(webdriver_url)
    wd.wait_ready()
    wd.new_session(capabilities)
    started = time.time()
    try:
        before = None
        try:
            before = server_get(f"{server_url}/api/report/latest?tag={urllib.parse.quote(tag)}", timeout=10).get("id")
        except Exception:  # noqa: BLE001 - no previous report is fine
            pass
        wd.navigate(f"{server_url}/?tag={urllib.parse.quote(tag)}&noredirect=1")
        q = f"tag={urllib.parse.quote(tag)}&wait={int(wait)}" + (f"&after={before}" if before else "")
        try:
            report = server_get(f"{server_url}/api/report/latest?{q}", timeout=wait + 15)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            # Nothing finished in time: return the newest (unfinished) report for
            # this tag so the caller can see which sections did arrive.
            lst = server_get(f"{server_url}/api/reports?tag={urllib.parse.quote(tag)}", timeout=10).get("reports") or []
            fresh = [x for x in lst if x.get("id") != before and x.get("created_ts", 0) >= started - 5]
            if not fresh:
                raise RuntimeError(f"no report with tag {tag!r} was created; did the browser reach {server_url}?") from e
            report = server_get(f"{server_url}/api/report/{fresh[0]['id']}", timeout=10)
        report["_probe_wall_s"] = round(time.time() - started, 1)
        return report
    finally:
        if not keep_session:
            wd.quit()
