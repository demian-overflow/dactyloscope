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

from . import __version__, analysis, h2fp, tls
from .known import KnownShapes

log = logging.getLogger("dactyloscope")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 8 * 1024 * 1024
PEEK_LIMIT = 64 * 1024

# ---------------------------------------------------------------------------
# Connection record
# ---------------------------------------------------------------------------

class ConnInfo:
    def __init__(self, peer: tuple, scheme: str) -> None:
        self.id = secrets.token_hex(6)
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
    """Stateless: nothing about a visitor outlives the request that carries it.

    ``GET /`` captures the network layer of the navigation request and embeds it in the probe page. The page runs
    the JS probes and posts everything back to ``POST /analyze`` in one request, which returns the finished report.
    """

    def __init__(self, known: KnownShapes, ca_pem: Path, public: bool = False) -> None:
        # public: an Internet-facing instance; the client IP is left out of the report.
        self.public = public
        self.known = known
        self.ca_pem = ca_pem
        self.started = time.time()

    async def handle(self, req: Request) -> Response:
        try:
            resp = await self._route(req)
        except KeyError as e:
            resp = Response.json({"error": "not found", "detail": str(e)}, 404)
        except ValueError as e:
            resp = Response.json({"error": "bad request", "detail": str(e)}, 400)
        except Exception as e:  # noqa: BLE001
            log.exception("handler failed for %s %s", req.method, req.path)
            resp = Response.json({"error": "internal", "detail": f"{e.__class__.__name__}: {e}"}, 500)
        resp.headers += [("cache-control", "no-store"), ("server", f"dactyloscope/{__version__}")]
        return resp

    async def _route(self, req: Request) -> Response:
        p, m = req.path, req.method
        if p == "/" and m == "GET":
            return self.probe_page(req)
        if p == "/analyze" and m == "POST":
            return self.analyze(req)
        if p.startswith("/static/") and m == "GET":
            return self.static(p[len("/static/"):])
        if p == "/favicon.ico":
            return self.static("favicon-32.png")
        if p == "/ca.pem":
            return Response(200, self.ca_pem.read_bytes(), "application/x-pem-file",
                            [("content-disposition", 'inline; filename="dactyloscope-ca.pem"')])
        if p == "/healthz":
            return Response.json({"ok": True, "version": __version__, "uptime_s": round(time.time() - self.started)})
        raise KeyError(p)

    # ---- UI helpers ------------------------------------------------------
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
        """Serve the probe page with the navigation request's network fingerprint embedded in it."""
        net = req.conn.network_json(self.known)
        net["http"] = req.http_json()
        net["http"]["match"] = analysis.match_http(req, net)
        net["requests"] = []
        seed = {
            "dactyloscope_version": __version__,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "label": req.query.get("label"),
            "client": None if self.public else {"ip": req.conn.peer_ip, "port": req.conn.peer_port},
            "network": net,
        }
        # "<" escaped so header values can't close the <script> element.
        blob = json.dumps(seed, default=str).replace("<", "\\u003c")
        html = self._read_static("index.html")[0].decode()
        html = html.replace("__DACTY_VERSION__", __version__).replace("__SEED_JSON__", blob)
        return Response(200, html, "text/html; charset=utf-8")

    def analyze(self, req: Request) -> Response:
        """Turn the page's seed plus its probe results into a finished report. Nothing is kept."""
        try:
            data = json.loads(req.body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"invalid JSON: {e}") from e
        if not isinstance(data, dict) or not isinstance(data.get("network"), dict):
            raise ValueError("expected {network, probes, probe_errors}")
        probes = data.get("probes") if isinstance(data.get("probes"), dict) else {}
        errors = data.get("probe_errors") if isinstance(data.get("probe_errors"), dict) else {}
        net = data["network"]
        if not isinstance(net.get("requests"), list):
            net["requests"] = []
        net["requests"].append(self._subrequest(req))
        report = {
            "dactyloscope_version": __version__,
            "created": data.get("created"), "label": data.get("label"), "client": data.get("client"),
            "done": True,
            "network": net, "probes": probes, "probe_errors": errors,
            "probe_ms": data.get("elapsed_ms"), "probe_order": data.get("order"),
            "analysis": analysis.analyse(probes, net, self.known, errors),
        }
        return Response.json(report)

    def _subrequest(self, req: Request) -> dict[str, Any]:
        return {"method": req.method, "path": req.path, "version": req.version,
                "connection_id": req.conn.id, "http_version": req.conn.http_version,
                "headers": [[k, v] for k, v in req.headers],
                "ja3": (req.conn.tls or {}).get("ja3", {}).get("hash") if req.conn.tls else None}


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
