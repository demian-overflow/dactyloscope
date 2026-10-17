"""HTTP/2 preface fingerprinting (Akamai-style) from the raw byte stream.

We watch the first frames a client sends after the connection preface and
record SETTINGS (id/value order), the connection WINDOW_UPDATE increment,
PRIORITY frames, and the first HEADERS frame (flags, priority fields and the
pseudo-header order). The Akamai fingerprint string is
``SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER``.

Header *names* are decoded with a throw-away HPACK decoder; the request
itself is handled separately by the h2 state machine.
"""
from __future__ import annotations

import struct
from typing import Any

from hpack import Decoder

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
               5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
               9: "CONTINUATION", 12: "ORIGIN", 16: "PRIORITY_UPDATE"}

SETTINGS_NAMES = {1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
                  4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
                  8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES"}


class PrefaceParser:
    """Feed raw bytes; ``done`` becomes True once the first HEADERS block ended."""

    def __init__(self) -> None:
        self.buf = b""
        self.frames: list[dict[str, Any]] = []
        self.done = False
        self.preface_ok: bool | None = None
        self._decoder = Decoder()
        self._hdr_stream: int | None = None
        self._hdr_fragment = b""
        self._hdr_frame: dict[str, Any] | None = None

    def feed(self, data: bytes) -> None:
        if self.done:
            return
        self.buf += data
        if self.preface_ok is None:
            if len(self.buf) < len(PREFACE):
                return
            self.preface_ok = self.buf.startswith(PREFACE)
            if not self.preface_ok:
                self.done = True
                return
            self.buf = self.buf[len(PREFACE):]
        while not self.done and len(self.buf) >= 9:
            length = int.from_bytes(self.buf[0:3], "big")
            ftype, flags = self.buf[3], self.buf[4]
            stream = struct.unpack("!I", self.buf[5:9])[0] & 0x7FFFFFFF
            if len(self.buf) < 9 + length:
                return
            payload = self.buf[9:9 + length]
            self.buf = self.buf[9 + length:]
            self._frame(ftype, flags, stream, length, payload)
            if len(self.frames) > 40:  # safety valve
                self.done = True

    def _frame(self, ftype: int, flags: int, stream: int, length: int, payload: bytes) -> None:
        fr: dict[str, Any] = {"type": FRAME_TYPES.get(ftype, f"TYPE_{ftype}"), "stream": stream,
                              "flags": flags, "len": length}
        if ftype == 4 and not flags & 0x1:  # SETTINGS (not ACK)
            fr["settings"] = [[struct.unpack("!H", payload[i:i + 2])[0],
                               struct.unpack("!I", payload[i + 2:i + 6])[0]]
                              for i in range(0, len(payload) - 5, 6)]
        elif ftype == 4:
            fr["ack"] = True
        elif ftype == 8 and len(payload) >= 4:
            fr["increment"] = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
        elif ftype == 2 and len(payload) >= 5:
            dep = struct.unpack("!I", payload[:4])[0]
            fr.update(exclusive=bool(dep & 0x80000000), dep=dep & 0x7FFFFFFF, weight=payload[4] + 1)
        elif ftype == 1:
            p = 0
            if flags & 0x8:  # PADDED
                pad = payload[0]; p = 1; payload = payload[:len(payload) - pad]
            if flags & 0x20:  # PRIORITY
                dep = struct.unpack("!I", payload[p:p + 4])[0]
                fr.update(exclusive=bool(dep & 0x80000000), dep=dep & 0x7FFFFFFF, weight=payload[p + 4] + 1)
                p += 5
            self._hdr_stream = stream
            self._hdr_fragment = payload[p:]
            self._hdr_frame = fr
            if flags & 0x4:  # END_HEADERS
                self._finish_headers()
        elif ftype == 9 and stream == self._hdr_stream:
            self._hdr_fragment += payload
            if flags & 0x4:
                self._finish_headers()
        self.frames.append(fr)

    def _finish_headers(self) -> None:
        names: list[str] = []
        try:
            for name, _ in self._decoder.decode(self._hdr_fragment, raw=True):
                names.append(name.decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001 - fingerprinting must never kill the connection
            names.append(f"<hpack error: {e.__class__.__name__}>")
        if self._hdr_frame is not None:
            self._hdr_frame["headers"] = names
        self.done = True

    # ---- results -----------------------------------------------------
    def settings(self) -> list[list[int]]:
        for f in self.frames:
            if f["type"] == "SETTINGS" and "settings" in f:
                return f["settings"]
        return []

    def window_update(self) -> int:
        for f in self.frames:
            if f["type"] == "WINDOW_UPDATE" and f["stream"] == 0:
                return f.get("increment", 0)
        return 0

    def priorities(self) -> list[dict[str, Any]]:
        return [f for f in self.frames if f["type"] == "PRIORITY"]

    def first_headers(self) -> dict[str, Any] | None:
        for f in self.frames:
            if f["type"] == "HEADERS":
                return f
        return None

    def pseudo_order(self) -> str:
        h = self.first_headers()
        if not h:
            return ""
        return ",".join(n[1] for n in h.get("headers", []) if n.startswith(":") and len(n) > 1)

    def akamai(self) -> str:
        s = ";".join(f"{k}:{v}" for k, v in self.settings())
        pr = ",".join(f"{p['stream']}:{int(p['exclusive'])}:{p['dep']}:{p['weight']}" for p in self.priorities())
        return f"{s}|{self.window_update()}|{pr or '0'}|{self.pseudo_order()}"

    def summary(self) -> dict[str, Any]:
        h = self.first_headers() or {}
        return {
            "preface_ok": self.preface_ok,
            "akamai_fingerprint": self.akamai() if self.preface_ok else None,
            "settings": [{"id": k, "name": SETTINGS_NAMES.get(k, f"SETTING_{k}"), "value": v}
                         for k, v in self.settings()],
            "window_update": self.window_update(),
            "priority_frames": self.priorities(),
            "pseudo_header_order": self.pseudo_order(),
            "first_headers": {
                "stream": h.get("stream"), "flags": h.get("flags"),
                "exclusive": h.get("exclusive"), "dep": h.get("dep"), "weight": h.get("weight"),
                "names": h.get("headers", []),
            } if h else None,
            "frame_sequence": [f"{f['type']}" + (f"(s{f['stream']})" if f['stream'] else "") for f in self.frames],
            "frames": self.frames,
        }
