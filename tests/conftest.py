from __future__ import annotations

import json
from typing import Any

import pytest
from hpack import Decoder

import wire
from dactyloscope import h2fp, known as known_mod, tls
from dactyloscope.known import KnownShapes
from dactyloscope.server import ConnInfo, Request

CHROME_152_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/152.0.0.0 Safari/537.36")
FIREFOX_154_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0"


@pytest.fixture(scope="session")
def known() -> KnownShapes:
    return KnownShapes().load()


def capture(name: str) -> dict[str, Any]:
    return json.loads((wire.CAPTURES / name).read_text())


def navigation_headers(family: str, ua: str, major: int | None = None) -> list[tuple[str, str]]:
    """The HTTP/2 navigation request the reference browser sends, in its order."""
    exp = known_mod.HTTP_EXPECTATIONS[family]
    pseudo = {"m": (":method", "GET"), "a": (":authority", "fixture.test"),
              "s": (":scheme", "https"), "p": (":path", "/")}
    values = {
        "sec-ch-ua": f'"Not)A;Brand";v="8", "Chromium";v="{major}", "Google Chrome";v="{major}"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Linux"', "upgrade-insecure-requests": "1",
        "user-agent": ua, "accept": exp["accept"], "accept-encoding": exp["accept_encoding"],
        "accept-language": "en-US,en;q=0.9", "priority": exp["priority"], "te": "trailers",
        **exp["sec_fetch"],
    }
    return [pseudo[c] for c in exp["pseudo_order"].split(",")] + [(h, values[h]) for h in exp["h2_order"]]


def decode_request_headers(h2_bytes: bytes) -> list[tuple[str, str]]:
    """Header list of the first HEADERS frame in a recorded h2 stream."""
    p = h2fp.PrefaceParser()
    p.feed(h2_bytes)
    buf = h2_bytes[len(wire.PREFACE):]
    while buf:
        length, ftype, flags = int.from_bytes(buf[:3], "big"), buf[3], buf[4]
        payload, buf = buf[9:9 + length], buf[9 + length:]
        if ftype == 1:
            assert not flags & 0x8, "padded HEADERS not expected in recordings"
            block = payload[5:] if flags & 0x20 else payload
            return [(k, v) for k, v in Decoder().decode(block)]
    raise AssertionError("no HEADERS frame")


def build_net(known: KnownShapes, *, client_hello: bytes | None = None, h2_bytes: bytes | None = None,
              headers: list[tuple[str, str]] | None = None, scheme: str = "https",
              tls_version: str = "TLSv1.3") -> dict[str, Any]:
    """The ``network`` block exactly as server.App.probe_page builds it."""
    conn = ConnInfo(("192.0.2.1", 50000), scheme)
    if client_hello is not None:
        ch = tls.parse_client_hello(client_hello)
        conn.tls = {"ja3": tls.ja3(ch), "ja3n": tls.ja3n(ch), "ja4": tls.ja4(ch), "shape": tls.shape(ch),
                    "decoded": tls.decoded(ch), "raw_len": len(client_hello)}
        conn.negotiated = {"version": tls_version, "cipher": "TLS_AES_128_GCM_SHA256", "alpn": None}
    version = "1.1"
    if h2_bytes is not None:
        p = h2fp.PrefaceParser()
        p.feed(h2_bytes)
        conn.h2 = p.summary()
        conn.http_version = version = "2"
    hdrs = headers or []
    req_headers = [(k, v) for k, v in hdrs if not k.startswith(":")]
    req = Request(conn, "GET", "/", req_headers, b"", version)
    net = conn.network_json(known)
    net["http"] = req.http_json()
    from dactyloscope import analysis
    net["http"]["match"] = analysis.match_http(req, net)
    net["requests"] = []
    return net
