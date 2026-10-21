import pytest

import wire
from conftest import CHROME_152_UA, FIREFOX_154_UA, capture, navigation_headers
from dactyloscope import h2fp

CHROMIUM = wire.fixture("chromium-141.h2.bin")
CURL = wire.fixture("curl.h2.bin")
SIMPLE_HEADERS = [(":method", "GET"), (":path", "/"), (":authority", "a.test"), (":scheme", "https"),
                  ("user-agent", "x")]


def parse(data: bytes) -> h2fp.PrefaceParser:
    p = h2fp.PrefaceParser()
    p.feed(data)
    return p


def test_chromium_preface():
    p = parse(CHROMIUM)
    assert p.preface_ok and p.done
    # 60058 (0xea9a) is a reserved "GREASE" setting this Chromium build sends; it is kept as-is.
    assert p.akamai() == "1:65536;2:0;4:6291456;6:262144;60058:3568808159|15663105|0|m,a,s,p"
    s = p.summary()
    assert s["frame_sequence"] == ["SETTINGS", "WINDOW_UPDATE", "HEADERS(s1)"]
    assert s["first_headers"]["exclusive"] is True
    assert s["first_headers"]["dep"] == 0 and s["first_headers"]["weight"] == 256
    assert s["first_headers"]["names"][:5] == [":method", ":authority", ":scheme", ":path", "sec-ch-ua"]
    assert s["settings"][0] == {"id": 1, "name": "HEADER_TABLE_SIZE", "value": 65536}
    assert s["settings"][-1]["name"] == "SETTING_60058"


def test_curl_preface():
    p = parse(CURL)
    assert p.akamai() == "3:100;4:10485760;2:0|1048510465|0|m,s,a,p"
    assert p.first_headers()["headers"] == [":method", ":scheme", ":authority", ":path", "user-agent", "accept"]
    assert p.first_headers().get("weight") is None  # no PRIORITY flag


def test_feeding_byte_by_byte_gives_the_same_result():
    p = h2fp.PrefaceParser()
    for i in range(len(CHROMIUM)):
        p.feed(CHROMIUM[i:i + 1])
    assert p.summary() == parse(CHROMIUM).summary()


def test_partial_preface_waits():
    p = parse(wire.PREFACE[:10])
    assert p.preface_ok is None and not p.done


def test_partial_frame_waits():
    p = parse(CHROMIUM[:len(wire.PREFACE) + 12])
    assert p.preface_ok and not p.done and p.frames == []


def test_not_http2():
    p = parse(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
    assert p.preface_ok is False and p.done
    assert p.summary()["akamai_fingerprint"] is None
    p.feed(CHROMIUM)  # ignored once done
    assert p.frames == []


def test_bytes_after_first_headers_are_ignored():
    p = parse(CURL + wire.settings([(1, 1)]))
    assert p.akamai() == parse(CURL).akamai()


def test_priority_frames_and_settings_ack():
    data = (wire.PREFACE + wire.settings([(1, 65536), (4, 131072), (5, 16384)])
            + wire.frame(4, 0x1, 0, b"") + wire.window_update(12517377)
            + wire.priority(3, 0, 201) + wire.priority(5, 0, 101) + wire.priority(7, 0, 1)
            + wire.priority(9, 7, 1) + wire.priority(11, 3, 1, exclusive=True)
            + wire.headers(13, wire.header_block(SIMPLE_HEADERS), prio=(False, 11, 42)))
    p = parse(data)
    assert p.akamai() == "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:1:3:1|m,p,a,s"
    assert p.frames[1] == {"type": "SETTINGS", "stream": 0, "flags": 1, "len": 0, "ack": True}
    assert p.first_headers()["dep"] == 11 and p.first_headers()["weight"] == 42


def test_padded_headers():
    p = parse(wire.PREFACE + wire.settings([]) + wire.headers(1, wire.header_block(SIMPLE_HEADERS),
                                                              prio=(True, 0, 256), pad=7))
    h = p.first_headers()
    assert h["headers"] == [":method", ":path", ":authority", ":scheme", "user-agent"]
    assert h["weight"] == 256 and h["exclusive"] is True
    assert p.akamai() == "|0|0|m,p,a,s"


def test_continuation_frames():
    block = wire.header_block(SIMPLE_HEADERS)
    p = parse(wire.PREFACE + wire.settings([(2, 0)])
              + wire.headers(1, block[:3], end_headers=False)
              + wire.continuation(1, block[3:6], end_headers=False)
              + wire.continuation(1, block[6:]))
    assert p.done
    assert [f["type"] for f in p.frames] == ["SETTINGS", "HEADERS", "CONTINUATION", "CONTINUATION"]
    assert p.pseudo_order() == "m,p,a,s"


def test_window_update_on_a_stream_is_not_the_connection_increment():
    p = parse(wire.PREFACE + wire.settings([]) + wire.window_update(5, stream=1)
              + wire.headers(1, wire.header_block(SIMPLE_HEADERS)))
    assert p.window_update() == 0


def test_hpack_garbage_is_reported_not_raised():
    p = parse(wire.PREFACE + wire.headers(1, b"\xff\xff\xff\xff\xff"))
    assert p.done
    assert p.first_headers()["headers"][0].startswith("<hpack error:")
    assert p.pseudo_order() == ""


def test_frame_limit_stops_parsing():
    p = parse(wire.PREFACE + wire.frame(6, 0, 0, b"\x00" * 8) * 50)
    assert p.done and len(p.frames) == 41


@pytest.mark.parametrize("name,family,ua,major", [
    ("chrome-152-h2-preface.json", "chrome", CHROME_152_UA, 152),
    ("firefox-154-h2-preface.json", "firefox", FIREFOX_154_UA, None),
])
def test_reference_capture_round_trip(known, name, family, ua, major):
    cap = capture(name)
    p = parse(wire.preface_from_capture(cap, navigation_headers(family, ua, major)))
    assert p.akamai() == cap["akamai_fingerprint"]
    m = known.match_h2(p.akamai())
    assert m["known"] and m["closest_family"] == family


def test_match_h2_reports_the_differing_parts(known):
    m = known.match_h2(parse(CURL).akamai())
    assert not m["known"]
    assert "pseudo-header order: m,s,a,p vs m,a,s,p" in m["differences"]
    assert known.match_h2(None) == {"known": False, "reason": "no HTTP/2"}
