"""Byte builders for ClientHello records and HTTP/2 frames.

The recorded fixtures in ``fixtures/`` are real client bytes; these builders
cover the shapes no local client produces (reference browsers, PRIORITY
frames, padding, CONTINUATION, malformed input).
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from hpack import Encoder

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAPTURES = Path(__file__).resolve().parents[1] / "captures"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
GREASE = [0x0a0a + 0x1010 * i for i in range(16)]


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# ---- TLS ------------------------------------------------------------------

def u16(v: int) -> bytes:
    return struct.pack("!H", v)


def u16_list(vals: list[int], len_bytes: int = 2) -> bytes:
    body = b"".join(u16(v) for v in vals)
    return len(body).to_bytes(len_bytes, "big") + body


def ext_sni(host: str) -> bytes:
    name = host.encode()
    entry = b"\x00" + u16(len(name)) + name
    return u16(len(entry)) + entry


def ext_alpn(protos: list[str]) -> bytes:
    body = b"".join(bytes([len(p)]) + p.encode() for p in protos)
    return u16(len(body)) + body


def ext_key_share(shares: list[tuple[int, int]]) -> bytes:
    body = b"".join(u16(g) + u16(n) + b"\x00" * n for g, n in shares)
    return u16(len(body)) + body


def ext_u8_list(vals: list[int]) -> bytes:
    return bytes([len(vals)]) + bytes(vals)


def client_hello(ciphers: list[int], extensions: list[tuple[int, bytes]] | None, *,
                 version: int = 0x0303, record_version: int = 0x0301, session_id: bytes = b"\x11" * 32) -> bytes:
    """One TLS record holding one ClientHello; ``extensions=None`` omits the block."""
    body = u16(version) + b"\x22" * 32 + bytes([len(session_id)]) + session_id + u16_list(ciphers) + b"\x01\x00"
    if extensions is not None:
        exts = b"".join(u16(t) + u16(len(b)) + b for t, b in extensions)
        body += u16(len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + u16(record_version) + u16(len(hs)) + hs


def client_hello_from_capture(cap: dict[str, Any], sni: str | None = "example.com") -> bytes:
    """Re-encode a ``captures/*-clienthello.json`` shape as wire bytes."""
    grease = iter(GREASE)

    def num(v: Any) -> int:
        return next(grease) if v == "GREASE" else (int(v, 16) if isinstance(v, str) else v)

    stored = cap.get("extension_bodies_hex", {})
    exts: list[tuple[int, bytes]] = []
    for e in cap["extensions"]:
        t = num(e)
        if t == 0:
            if sni is None:
                continue
            body = ext_sni(sni)
        elif t == 10:
            body = u16_list([num(g) for g in cap["groups"]])
        elif t == 11:
            body = ext_u8_list([0])
        elif t == 13:
            body = u16_list([int(s, 16) for s in cap["sigalgs"]])
        elif t == 16:
            body = ext_alpn(cap["alpn"])
        elif t == 27:
            body = u16_list([int(c, 16) for c in cap["compress_cert"]], len_bytes=1)
        elif t == 43:
            body = u16_list([next(grease)] + [int(v, 16) for v in cap["supported_versions"]], len_bytes=1)
        elif t == 45:
            body = ext_u8_list([1])
        elif t == 51:
            body = ext_key_share([(num(g), n) for g, n in cap["keyshare"]])
        else:
            body = bytes.fromhex(stored.get(str(e), ""))
        exts.append((t, body))
    ciphers = [int(c, 16) for c in cap["ciphers"]]
    if any(e == "GREASE" for e in cap["extensions"]):
        ciphers = [next(grease)] + ciphers  # GREASE clients GREASE their cipher list too
    return client_hello(ciphers, exts)


# ---- HTTP/2 ------------------------------------------------------------------

def frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + struct.pack("!I", stream) + payload


def settings(pairs: list[tuple[int, int]]) -> bytes:
    return frame(4, 0, 0, b"".join(struct.pack("!HI", k, v) for k, v in pairs))


def window_update(increment: int, stream: int = 0) -> bytes:
    return frame(8, 0, stream, struct.pack("!I", increment))


def priority(stream: int, dep: int, weight: int, exclusive: bool = False) -> bytes:
    return frame(2, 0, stream, struct.pack("!I", dep | (0x80000000 if exclusive else 0)) + bytes([weight - 1]))


def header_block(headers: list[tuple[str, str]]) -> bytes:
    return Encoder().encode(headers)


def headers(stream: int, block: bytes, *, end_headers: bool = True, end_stream: bool = True,
            prio: tuple[bool, int, int] | None = None, pad: int = 0) -> bytes:
    """HEADERS frame; ``prio`` is (exclusive, dependency, weight)."""
    flags = (0x1 if end_stream else 0) | (0x4 if end_headers else 0)
    payload = block
    if prio is not None:
        exclusive, dep, weight = prio
        flags |= 0x20
        payload = struct.pack("!I", dep | (0x80000000 if exclusive else 0)) + bytes([weight - 1]) + payload
    if pad:
        flags |= 0x8
        payload = bytes([pad]) + payload + b"\x00" * pad
    return frame(1, flags, stream, payload)


def continuation(stream: int, block: bytes, end_headers: bool = True) -> bytes:
    return frame(9, 0x4 if end_headers else 0, stream, block)


def preface_from_capture(cap: dict[str, Any], hdrs: list[tuple[str, str]]) -> bytes:
    """Re-encode a ``captures/*-h2-preface.json`` capture as client bytes."""
    out = PREFACE
    for f in cap["frames"]:
        if f["type"] == "SETTINGS":
            out += settings([tuple(p) for p in f["settings"]])
        elif f["type"] == "WINDOW_UPDATE":
            out += window_update(f["increment"], f["stream"])
        elif f["type"] == "PRIORITY":
            out += priority(f["stream"], f["dep"], f["weight"], f["exclusive"])
        elif f["type"] == "HEADERS":
            prio = (f["exclusive"], f["dep"], f["weight"]) if f["flags"] & 0x20 else None
            out += headers(f["stream"], header_block(hdrs), prio=prio)
    return out
