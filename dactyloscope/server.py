"""The Dactyloscope HTTP(S) server.

One asyncio process, two listeners:

* TLS port (default 8443): every accepted socket is *peeked* for the complete
  ClientHello record before the TLS handshake starts, so we see the exact
  bytes the client sent. After the handshake the ALPN result selects HTTP/2
  (h2 state machine, plus a raw preface parser for the Akamai fingerprint) or
  HTTP/1.1 (tiny parser that preserves header order and casing).
* Plain port (default 8080): HTTP/1.1 only — convenient for agents that do
  not want to trust the local CA, and for serving ``/ca.pem``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import secrets
import socket
import ssl
import struct
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

from . import __version__, analysis, compare, h2fp, tls
from .known import KnownShapes
from .store import Store, new_id, summary_of

log = logging.getLogger("dactyloscope")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 8 * 1024 * 1024
PEEK_LIMIT = 64 * 1024

# Header values a subsequent detector could not see anyway; not stored.
STRIP_REQUEST_HEADERS: set[str] = set()


# ---------------------------------------------------------------------------
# Connection record
# ---------------------------------------------------------------------------

class ConnInfo:
    def __init__(self, peer: tuple, scheme: str) -> None:
        self.id = new_id()
        self.peer_ip, self.peer_port = (peer[0], peer[1]) if peer else ("?", 0)
        self.scheme = scheme
        self.created = time.time()
        self.tls: dict[str, Any] | None = None
        self.negotiated: dict[str, Any] | None = None
        self.h2: dict[str, Any] | None = None
        self.http_version = "1.1"
        self.request_count = 0

    def network_json(self, known: KnownShapes) -> dict[str, Any]:
        out: dict[str, Any] = {"connection_id": self.id, "scheme": self.scheme,
                               "http_version": self.http_version, "tls": None, "h2": None}
        if self.tls:
            out["tls"] = dict(self.tls)
            out["tls"]["negotiated"] = self.negotiated
            out["tls"]["match"] = known.match_tls(self.tls["shape"])
        if self.h2:
            out["h2"] = dict(self.h2)
            out["h2"]["match"] = known.match_h2(self.h2.get("akamai_fingerprint"))
        return out


class Request:
    def __init__(self, conn: ConnInfo, method: str, target: str, headers: list[tuple[str, str]],
                 body: bytes, version: str) -> None:
        self.conn = conn
        self.method = method
        self.target = target
        u = urllib.parse.urlsplit(target)
        self.path = u.path or "/"
        self.query = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        self.headers = headers  # ordered, as sent (h2: lowercase; h1: original case)
        self.body = body
        self.version = version
        self.received = time.time()

    def header(self, name: str) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def http_json(self) -> dict[str, Any]:
        return {
            "method": self.method, "path": self.path, "query": self.query, "version": self.version,
            "headers": [[k, v] for k, v in self.headers],
            "user_agent": self.header("user-agent"),
            "received": self.received,
        }


class Response:
    def __init__(self, status: int = 200, body: bytes | str = b"", content_type: str = "text/plain; charset=utf-8",
                 headers: list[tuple[str, str]] | None = None) -> None:
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.headers = [("content-type", content_type)] + (headers or [])

    @staticmethod
    def json(obj: Any, status: int = 200, pretty: bool = True) -> "Response":
        txt = json.dumps(obj, indent=1 if pretty else None, default=str)
        return Response(status, txt, "application/json; charset=utf-8")


# ---------------------------------------------------------------------------
# Application (routing)
# ---------------------------------------------------------------------------

class App:
    def __init__(self, store: Store, known: KnownShapes, ca_pem: Path, public_urls: dict[str, str],
                 public: bool = False, admin_token: str | None = None) -> None:
        # public: an Internet-facing instance. Client IPs are not stored, other people's reports can't be
        # listed or deleted, and baselines are read-only unless the request carries the admin token.
        self.public = public
        self.admin_token = admin_token
        self.store = store
        self.known = known
        self.ca_pem = ca_pem
        self.public_urls = public_urls
        self.started = time.time()
        self._static_cache: dict[str, tuple[bytes, str]] = {}

    async def handle(self, req: Request) -> Response:
        try:
            resp = await self._route(req)
        except KeyError as e:
            resp = Response.json({"error": "not found", "detail": str(e)}, 404)
        except ValueError as e:
            resp = Response.json({"error": "bad request", "detail": str(e)}, 400)
        except PermissionError as e:
            resp = Response.json({"error": "forbidden", "detail": str(e)}, 403)
        except Exception as e:  # noqa: BLE001
            log.exception("handler failed for %s %s", req.method, req.path)
            resp = Response.json({"error": "internal", "detail": f"{e.__class__.__name__}: {e}"}, 500)
        resp.headers += [("cache-control", "no-store"), ("access-control-allow-origin", "*"),
                         ("x-dactyloscope-connection", req.conn.id), ("server", f"dactyloscope/{__version__}")]
        return resp

    async def _route(self, req: Request) -> Response:  # noqa: C901 - flat dispatch table
        p, m = req.path, req.method
        if m == "OPTIONS":
            return Response(204, b"", headers=[("access-control-allow-methods", "GET,POST,DELETE,OPTIONS"),
                                                ("access-control-allow-headers", "content-type")])
        # --- UI ------------------------------------------------------------
        if p == "/" and m == "GET":
            return self.probe_page(req)
        if p.startswith("/r/") and m == "GET":
            return self.page("report.html")
        if p in ("/reports", "/reports/") and m == "GET":
            return self.page("reports.html")
        if p == "/compare" and m == "GET":
            return self.page("compare.html")
        if p == "/docs" and m == "GET":
            return self.page("docs.html")
        if p.startswith("/static/") and m == "GET":
            return self.static(p[len("/static/"):])
        if p == "/favicon.ico":
            return self.static("favicon-32.png")
        if p == "/ca.pem":
            return Response(200, self.ca_pem.read_bytes(), "application/x-pem-file",
                            [("content-disposition", 'inline; filename="dactyloscope-ca.pem"')])
        if p == "/healthz":
            return Response.json({"ok": True, "version": __version__, "uptime_s": round(time.time() - self.started)})
        # --- API -----------------------------------------------------------
        if p in ("/api", "/api/"):
            return Response.json(self.api_index())
        if p == "/api/whoami" and m == "GET":
            return self.whoami(req)
        if p == "/api/known" and m == "GET":
            return Response.json(self.known.as_json())
        if p == "/api/reports" and m == "GET":
            self._require_admin(req)
            return Response.json({"reports": self.store.list(req.query.get("tag"), int(req.query.get("limit", "50")))})
        if p == "/api/report/latest" and m == "GET":
            self._require_admin(req)
            return await self.latest(req)
        if p == "/api/report" and m == "POST":
            return self.create_report(req)
        if p.startswith("/api/report/"):
            return await self.report_routes(req, p[len("/api/report/"):])
        if p == "/api/baselines" and m == "GET":
            return Response.json({"baselines": self.store.list_baselines()})
        if p.startswith("/api/baseline/"):
            return self.baseline_routes(req, p[len("/api/baseline/"):])
        if p == "/api/compare" and m == "GET":
            return self.compare(req)
        raise KeyError(p)

    def _require_admin(self, req: Request) -> None:
        if not self.public:
            return
        auth = req.header("authorization") or ""
        if not (self.admin_token and secrets.compare_digest(auth, f"Bearer {self.admin_token}")):
            raise PermissionError("disabled on the public instance; open your own report by its id")

    # ---- UI helpers ------------------------------------------------------
    def page(self, name: str) -> Response:
        body, ctype = self._read_static(name)
        return Response(200, body, ctype)

    def static(self, name: str) -> Response:
        if ".." in name or name.startswith("/"):
            raise KeyError(name)
        body, ctype = self._read_static(name)
        return Response(200, body, ctype)

    def _read_static(self, name: str) -> tuple[bytes, str]:
        p = STATIC_DIR / name
        if not p.is_file():
            raise KeyError(name)
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        return p.read_bytes(), ctype

    def probe_page(self, req: Request) -> Response:
        """Serve the probe page; the navigation request itself becomes the network part of a new report."""
        rid = new_id()
        report = self._new_report(rid, req)
        self.store.put(report)
        self.store.prune()
        html = self._read_static("index.html")[0].decode()
        html = html.replace("__REPORT_ID__", rid).replace("__DACTY_VERSION__", __version__)
        return Response(200, html, "text/html; charset=utf-8")

    def _new_report(self, rid: str, req: Request) -> dict[str, Any]:
        net = req.conn.network_json(self.known)
        net["http"] = req.http_json()
        net["http"]["match"] = analysis.match_http(req, net)
        net["requests"] = []
        report = {
            "id": rid, "dactyloscope_version": __version__,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "created_ts": time.time(),
            "done": False,
            "tag": req.query.get("tag"), "label": req.query.get("label"),
            "client": None if self.public else {"ip": req.conn.peer_ip, "port": req.conn.peer_port},
            "network": net,
            "probes": {},
            "probe_errors": {},
            "analysis": analysis.analyse(None, net, self.known),
        }
        return report

    # ---- API ----------------------------------------------------------
    def api_index(self) -> dict[str, Any]:
        return {
            "service": "dactyloscope", "version": __version__,
            "urls": self.public_urls,
            "endpoints": {
                "GET /": "probe page; opening it in a browser creates a report and runs the JS probes",
                "GET /?tag=<tag>&label=<text>": "same, with a tag for later lookup",
                "GET /api/whoami": "network-only fingerprint of *this* connection (TLS, HTTP/2, headers) with findings",
                "GET /api/report/latest?tag=<tag>&wait=<s>": "newest finished report (optionally for a tag), long-polls up to wait seconds",
                "GET /api/report/<id>?wait=<s>": "one report as JSON (long-polls until the JS probes finished)",
                "GET /api/report/<id>/summary": "concise plain-text summary (Accept: text/plain on the JSON URL does the same)",
                "GET /api/report/<id>/findings?min=info|warn|fail": "just the findings",
                "DELETE /api/report/<id>": "remove a report",
                "GET /api/reports?tag=<tag>&limit=<n>": "list reports (summaries)",
                "GET /api/compare?a=<id|baseline:name>&b=<id|baseline:name>": "field-by-field diff of two reports",
                "GET /api/baselines": "list saved baselines",
                "POST /api/baseline/<name>?report=<id>": "save a report as a named baseline (a real browser's report, typically)",
                "DELETE /api/baseline/<name>": "delete a baseline",
                "GET /api/known": "reference TLS / HTTP/2 / header shapes the analysis compares against",
                "GET /ca.pem": "the local CA to trust for the TLS port (BoringSSL/OpenSSL clients: SSL_CERT_FILE=ca.pem)",
                "GET /healthz": "liveness",
                "GET /r/<id>": "report viewer (HTML)",
                "GET /reports": "report list (HTML)",
                "GET /compare?a=&b=": "diff viewer (HTML)",
                "GET /docs": "this documentation as HTML",
            },
            "report_schema": {
                "id": "string", "created": "ISO 8601", "done": "bool — JS probes finished", "tag": "string|null",
                "client": {"ip": "string", "port": "int"},
                "network": {"tls": "ClientHello decode, ja3, ja4, negotiated, match", "h2": "Akamai fingerprint, frames, match",
                            "http": "navigation request headers in wire order + match", "requests": "subresource requests seen for this report"},
                "probes": "JS probe sections keyed by name (navigator, screen, canvas, webgl, audio, fonts, engine, apis, automation, integrity, worker, iframe, ...)",
                "analysis": {"score": "0-100 (higher = more automated/spoofed)", "verdict": "clean|suspicious|automated",
                             "identity": "claimed vs detected browser family, OS, JS engine", "findings": "[{id, severity, category, message, evidence}]",
                             "counts": {"fail": "int", "warn": "int", "info": "int"}},
            },
        }

    def whoami(self, req: Request) -> Response:
        net = req.conn.network_json(self.known)
        net["http"] = req.http_json()
        net["http"]["match"] = analysis.match_http(req, net)
        out = {"client": {"ip": req.conn.peer_ip, "port": req.conn.peer_port}, "network": net,
               "analysis": analysis.analyse(None, net, self.known)}
        if _wants_text(req):
            return Response(200, analysis.text_summary(out))
        return Response.json(out)

    def create_report(self, req: Request) -> Response:
        """Agent-driven flow without a page load: create a report from this connection (network only)."""
        rid = new_id()
        report = self._new_report(rid, req)
        self.store.put(report)
        return Response.json({"id": rid, "report": report})

    async def latest(self, req: Request) -> Response:
        wait = float(req.query.get("wait", "0") or 0)
        tag = req.query.get("tag")
        r = await self.store.wait_latest(tag, min(wait, 600), req.query.get("after")) if wait else self.store.latest(tag)
        if not r:
            return Response.json({"error": "no report" + (f" with tag {tag!r}" if tag else "")}, 404)
        return self._report_response(req, r)

    async def report_routes(self, req: Request, rest: str) -> Response:
        parts = rest.split("/")
        rid = parts[0]
        sub = parts[1] if len(parts) > 1 else ""
        m = req.method
        if m == "GET" and not sub:
            wait = float(req.query.get("wait", "0") or 0)
            r = await self.store.wait_done(rid, min(wait, 600)) if wait else self.store.get(rid)
            if not r:
                raise KeyError(rid)
            return self._report_response(req, r)
        if m == "GET" and sub == "summary":
            r = self.store.get(rid)
            if not r:
                raise KeyError(rid)
            return Response(200, analysis.text_summary(r))
        if m == "GET" and sub == "findings":
            r = self.store.get(rid)
            if not r:
                raise KeyError(rid)
            mn = req.query.get("min", "info")
            order = {"info": 0, "warn": 1, "fail": 2}
            fs = [f for f in (r.get("analysis") or {}).get("findings", []) if order.get(f["severity"], 0) >= order.get(mn, 0)]
            return Response.json({"id": rid, "score": r["analysis"].get("score"), "verdict": r["analysis"].get("verdict"), "findings": fs})
        if m == "DELETE" and not sub:
            self._require_admin(req)
            return Response.json({"deleted": self.store.delete(rid)})
        if m == "POST" and sub == "section":
            name = parts[2] if len(parts) > 2 else ""
            if not name or not name.replace("_", "").isalnum():
                raise ValueError("bad section name")
            r = self.store.get(rid)
            if not r:
                raise KeyError(rid)
            try:
                data = json.loads(req.body.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise ValueError(f"invalid JSON: {e}") from e
            if isinstance(data, dict) and "__error__" in data:
                r.setdefault("probe_errors", {})[name] = data["__error__"]
            else:
                r.setdefault("probes", {})[name] = data
            r["network"]["requests"].append(self._subrequest(req))
            r["analysis"] = analysis.analyse(r.get("probes"), r["network"], self.known, r.get("probe_errors"))
            self.store.put(r)
            return Response.json({"ok": True, "section": name})
        if m == "POST" and sub == "done":
            r = self.store.get(rid)
            if not r:
                raise KeyError(rid)
            try:
                data = json.loads(req.body.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                data = {}
            r["probe_ms"] = data.get("elapsed_ms")
            r["probe_order"] = data.get("order")
            r["analysis"] = analysis.analyse(r.get("probes"), r["network"], self.known, r.get("probe_errors"))
            r["done"] = True
            self.store.put(r)
            return Response.json({"ok": True, "id": rid, "score": r["analysis"]["score"], "verdict": r["analysis"]["verdict"]})
        if m == "POST" and sub == "asset":
            # Subresource requests (script/style/fetch) announce themselves so their header sets are kept.
            r = self.store.get(rid)
            if r:
                r["network"]["requests"].append(self._subrequest(req))
                self.store.put(r)
            return Response.json({"ok": True})
        raise KeyError(rest)

    def _subrequest(self, req: Request) -> dict[str, Any]:
        return {"method": req.method, "path": req.path, "version": req.version,
                "connection_id": req.conn.id, "http_version": req.conn.http_version,
                "headers": [[k, v] for k, v in req.headers],
                "ja3": (req.conn.tls or {}).get("ja3", {}).get("hash") if req.conn.tls else None}

    def _report_response(self, req: Request, r: dict[str, Any]) -> Response:
        if _wants_text(req):
            return Response(200, analysis.text_summary(r))
        return Response.json(r)

    def baseline_routes(self, req: Request, name: str) -> Response:
        if req.method != "GET":
            self._require_admin(req)
        if req.method == "POST":
            rid = req.query.get("report")
            if not rid:
                raise ValueError("missing ?report=<id>")
            r = self.store.get(rid)
            if not r:
                raise KeyError(rid)
            self.store.put_baseline(name, r)
            return Response.json({"ok": True, "baseline": name, "report": rid})
        if req.method == "GET":
            b = self.store.get_baseline(name)
            if not b:
                raise KeyError(name)
            return Response.json(b)
        if req.method == "DELETE":
            return Response.json({"deleted": self.store.delete_baseline(name)})
        raise KeyError(name)

    def compare(self, req: Request) -> Response:
        a, b = req.query.get("a"), req.query.get("b")
        if not a or not b:
            raise ValueError("need ?a=<id|baseline:name>&b=<id|baseline:name>")
        ra, rb = self._resolve(a), self._resolve(b)
        return Response.json(compare.diff_reports(ra, rb, a, b))

    def _resolve(self, ref: str) -> dict[str, Any]:
        if ref.startswith("baseline:"):
            r = self.store.get_baseline(ref[len("baseline:"):])
        elif ref == "latest" and not self.public:
            r = self.store.latest(None)
        else:
            r = self.store.get(ref)
        if not r:
            raise KeyError(ref)
        return r


def _wants_text(req: Request) -> bool:
    acc = (req.header("accept") or "").lower()
    return req.query.get("format") == "text" or (acc.startswith("text/plain") and "json" not in acc)


# ---------------------------------------------------------------------------
# Protocol handling
# ---------------------------------------------------------------------------

class HttpProtocol(asyncio.Protocol):
    """Speaks HTTP/1.1 or HTTP/2 on one connection, chosen by ALPN (or h1 on plain)."""

    def __init__(self, app: App, conn: ConnInfo) -> None:
        self.app = app
        self.conn = conn
        self.transport: asyncio.Transport | None = None
        self.buf = b""
        self.h2: h2.connection.H2Connection | None = None
        self.preface = h2fp.PrefaceParser()
        self.streams: dict[int, dict[str, Any]] = {}
        self.pending_send: dict[int, bytearray] = {}
        self.tasks: set[asyncio.Task] = set()

    # ---- lifecycle -----------------------------------------------------
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sslobj = transport.get_extra_info("ssl_object")
        alpn = None
        if sslobj is not None:
            alpn = sslobj.selected_alpn_protocol()
            self.conn.negotiated = {"version": sslobj.version(), "cipher": (sslobj.cipher() or [None])[0],
                                    "alpn": alpn, "sni": getattr(sslobj, "server_hostname", None)}
            # The handshake already happened; hostname the client asked for is
            # in the ClientHello we peeked.
        if alpn == "h2":
            self.conn.http_version = "2"
            cfg = h2.config.H2Configuration(client_side=False, header_encoding=None, validate_inbound_headers=False,
                                            normalize_inbound_headers=False, validate_outbound_headers=False,
                                            normalize_outbound_headers=False)
            self.h2 = h2.connection.H2Connection(config=cfg)
            self.h2.initiate_connection()
            self._flush()

    def connection_lost(self, exc: Exception | None) -> None:
        for t in self.tasks:
            t.cancel()

    def data_received(self, data: bytes) -> None:
        if self.h2 is not None:
            self._h2_data(data)
        else:
            self._h1_data(data)

    def _flush(self) -> None:
        if self.h2 is not None and self.transport is not None:
            out = self.h2.data_to_send()
            if out:
                self.transport.write(out)

    # ---- HTTP/2 -----------------------------------------------------------
    def _h2_data(self, data: bytes) -> None:
        assert self.h2 is not None
        if not self.preface.done:
            self.preface.feed(data)
            if self.preface.done:
                self.conn.h2 = self.preface.summary()
        try:
            events = self.h2.receive_data(data)
        except h2.exceptions.ProtocolError as e:
            log.debug("h2 protocol error from %s: %s", self.conn.peer_ip, e)
            self._flush()
            if self.transport:
                self.transport.close()
            return
        for ev in events:
            if isinstance(ev, h2.events.RequestReceived):
                hdrs = [(k.decode("utf-8", "replace"), v.decode("utf-8", "replace")) for k, v in ev.headers]
                self.streams[ev.stream_id] = {"headers": hdrs, "body": bytearray()}
                if ev.stream_ended:
                    self._h2_dispatch(ev.stream_id)
            elif isinstance(ev, h2.events.DataReceived):
                st = self.streams.get(ev.stream_id)
                if st is not None:
                    st["body"] += ev.data
                    if len(st["body"]) > MAX_BODY:
                        self.h2.reset_stream(ev.stream_id, h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
                        self.streams.pop(ev.stream_id, None)
                self.h2.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                if ev.stream_id in self.streams:
                    self._h2_dispatch(ev.stream_id)
            elif isinstance(ev, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)):
                self._h2_drain_all()
            elif isinstance(ev, h2.events.StreamReset):
                self.streams.pop(ev.stream_id, None)
                self.pending_send.pop(ev.stream_id, None)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                if self.transport:
                    self.transport.close()
        self._flush()

    def _h2_dispatch(self, sid: int) -> None:
        st = self.streams.pop(sid)
        hdrs: list[tuple[str, str]] = st["headers"]
        pseudo = {k: v for k, v in hdrs if k.startswith(":")}
        regular = [(k, v) for k, v in hdrs if not k.startswith(":")]
        req = Request(self.conn, pseudo.get(":method", "GET"), pseudo.get(":path", "/"),
                      [(k, v) for k, v in hdrs], bytes(st["body"]), "2")
        req.h2_pseudo = pseudo  # type: ignore[attr-defined]
        req.regular_headers = regular  # type: ignore[attr-defined]
        self.conn.request_count += 1
        task = asyncio.get_running_loop().create_task(self._h2_respond(sid, req))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _h2_respond(self, sid: int, req: Request) -> None:
        resp = await self.app.handle(req)
        if self.h2 is None or self.transport is None or self.transport.is_closing():
            return
        headers = [(":status", str(resp.status))] + [(k.lower(), v) for k, v in resp.headers]
        headers.append(("content-length", str(len(resp.body))))
        try:
            self.h2.send_headers(sid, headers, end_stream=not resp.body)
        except h2.exceptions.ProtocolError:
            return
        if resp.body:
            self.pending_send[sid] = bytearray(resp.body)
            self._h2_drain(sid)
        self._flush()

    def _h2_drain_all(self) -> None:
        for sid in list(self.pending_send):
            self._h2_drain(sid)

    def _h2_drain(self, sid: int) -> None:
        assert self.h2 is not None
        buf = self.pending_send.get(sid)
        if buf is None:
            return
        while buf:
            try:
                window = self.h2.local_flow_control_window(sid)
            except h2.exceptions.ProtocolError:
                self.pending_send.pop(sid, None)
                return
            chunk = min(window, self.h2.max_outbound_frame_size, len(buf))
            if chunk <= 0:
                return
            data = bytes(buf[:chunk])
            del buf[:chunk]
            try:
                self.h2.send_data(sid, data, end_stream=not buf)
            except h2.exceptions.ProtocolError:
                self.pending_send.pop(sid, None)
                return
        self.pending_send.pop(sid, None)
        self._flush()

    # ---- HTTP/1.1 ---------------------------------------------------------
    def _h1_data(self, data: bytes) -> None:
        self.buf += data
        if len(self.buf) > MAX_BODY + 65536:
            self._h1_error(413, "payload too large")
            return
        while True:
            idx = self.buf.find(b"\r\n\r\n")
            if idx < 0:
                if self.buf[:4] == b"PRI ":  # h2c prior knowledge: unsupported on this listener
                    self._h1_error(505, "HTTP/2 prior knowledge not supported on the plain port")
                return
            head = self.buf[:idx].decode("iso-8859-1")
            lines = head.split("\r\n")
            try:
                method, target, version = lines[0].split(" ", 2)
            except ValueError:
                self._h1_error(400, "bad request line")
                return
            headers: list[tuple[str, str]] = []
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers.append((k.strip(), v.strip()))
            clen = 0
            for k, v in headers:
                if k.lower() == "content-length":
                    try:
                        clen = int(v)
                    except ValueError:
                        clen = 0
            if len(self.buf) < idx + 4 + clen:
                return
            body = self.buf[idx + 4: idx + 4 + clen]
            self.buf = self.buf[idx + 4 + clen:]
            req = Request(self.conn, method, target, headers, body, version.replace("HTTP/", ""))
            self.conn.request_count += 1
            keep_alive = not any(k.lower() == "connection" and v.lower() == "close" for k, v in headers)
            task = asyncio.get_running_loop().create_task(self._h1_respond(req, keep_alive))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            if not keep_alive:
                return

    async def _h1_respond(self, req: Request, keep_alive: bool) -> None:
        resp = await self.app.handle(req)
        if self.transport is None or self.transport.is_closing():
            return
        reason = {200: "OK", 204: "No Content", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}.get(resp.status, "OK")
        head = [f"HTTP/1.1 {resp.status} {reason}"]
        for k, v in resp.headers:
            head.append(f"{k}: {v}")
        head.append(f"content-length: {len(resp.body)}")
        head.append("connection: " + ("keep-alive" if keep_alive else "close"))
        self.transport.write(("\r\n".join(head) + "\r\n\r\n").encode("iso-8859-1") + resp.body)
        if not keep_alive:
            self.transport.close()

    def _h1_error(self, status: int, msg: str) -> None:
        if self.transport:
            body = msg.encode()
            self.transport.write(f"HTTP/1.1 {status} {msg}\r\ncontent-type: text/plain\r\ncontent-length: {len(body)}\r\nconnection: close\r\n\r\n".encode() + body)
            self.transport.close()


# ---------------------------------------------------------------------------
# Listeners
# ---------------------------------------------------------------------------

async def peek_client_hello(loop: asyncio.AbstractEventLoop, sock: socket.socket, timeout: float = 10.0) -> bytes:
    """Wait until the complete first TLS record is readable, without consuming it."""
    deadline = loop.time() + timeout
    while True:
        fut = loop.create_future()
        loop.add_reader(sock.fileno(), lambda: (not fut.done()) and fut.set_result(None))
        try:
            await asyncio.wait_for(fut, max(0.01, deadline - loop.time()))
        finally:
            loop.remove_reader(sock.fileno())
        data = sock.recv(PEEK_LIMIT, socket.MSG_PEEK)
        if not data:
            raise ConnectionResetError("closed before ClientHello")
        try:
            need = tls.record_length(data)
        except tls.NeedMoreData:
            continue
        if len(data) >= need or len(data) >= PEEK_LIMIT:
            return data
        if loop.time() > deadline:
            return data


async def tls_listener(app: App, host: str, port: int, ctx: ssl.SSLContext) -> None:
    loop = asyncio.get_running_loop()
    lsock = _listen(host, port)
    log.info("TLS listener on https://%s:%d", host, port)
    while True:
        try:
            sock, addr = await loop.sock_accept(lsock)
        except OSError as e:
            log.warning("accept failed: %s", e)
            await asyncio.sleep(0.1)
            continue
        loop.create_task(_serve_tls(app, loop, sock, addr, ctx))


async def _serve_tls(app: App, loop: asyncio.AbstractEventLoop, sock: socket.socket, addr: tuple, ctx: ssl.SSLContext) -> None:
    sock.setblocking(False)
    conn = ConnInfo(addr, "https")
    try:
        raw = await peek_client_hello(loop, sock)
    except (asyncio.TimeoutError, OSError, ConnectionResetError) as e:
        log.debug("no ClientHello from %s: %s", addr, e)
        sock.close()
        return
    try:
        ch = tls.parse_client_hello(raw)
        conn.tls = {"ja3": tls.ja3(ch), "ja3n": tls.ja3n(ch), "ja4": tls.ja4(ch), "shape": tls.shape(ch),
                    "decoded": tls.decoded(ch), "raw_len": len(raw)}
    except tls.NotTls:
        # Plain HTTP on the TLS port: answer helpfully.
        conn.scheme = "http"
        conn.tls = None
        try:
            await loop.connect_accepted_socket(lambda: HttpProtocol(app, conn), sock)
        except OSError:
            sock.close()
        return
    except (tls.NeedMoreData, struct.error) as e:
        log.debug("ClientHello parse problem from %s: %s", addr, e)
        conn.tls = {"error": f"unparsable ClientHello: {e.__class__.__name__}", "raw_len": len(raw)}
    try:
        await loop.connect_accepted_socket(lambda: HttpProtocol(app, conn), sock, ssl=ctx, ssl_handshake_timeout=15)
    except (ssl.SSLError, OSError, asyncio.TimeoutError) as e:
        log.debug("TLS handshake with %s failed: %s", addr, e)
        try:
            sock.close()
        except OSError:
            pass


async def plain_listener(app: App, host: str, port: int) -> None:
    loop = asyncio.get_running_loop()

    def factory() -> HttpProtocol:
        return HttpProtocol(app, ConnInfo(("?", 0), "http"))

    class _Proto(HttpProtocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            peer = transport.get_extra_info("peername") or ("?", 0)
            self.conn.peer_ip, self.conn.peer_port = peer[0], peer[1]
            super().connection_made(transport)

    server = await loop.create_server(lambda: _Proto(app, ConnInfo(("?", 0), "http")), host, port, reuse_address=True)
    log.info("plain listener on http://%s:%d", host, port)
    async with server:
        await server.serve_forever()


def _listen(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind((host, port))
    s.listen(128)
    s.setblocking(False)
    return s


def make_ssl_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    # Let clients that only offer legacy suites still get a report.
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


async def serve(app: App, host: str, tls_port: int, plain_port: int | None, ctx: ssl.SSLContext) -> None:
    tasks = [asyncio.create_task(tls_listener(app, host, tls_port, ctx))]
    if plain_port:
        tasks.append(asyncio.create_task(plain_listener(app, host, plain_port)))
    await asyncio.gather(*tasks)
