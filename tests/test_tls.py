import hashlib

import pytest

import wire
from conftest import capture
from dactyloscope import tls

CHROMIUM = wire.fixture("chromium-141.clienthello.bin")
CURL = wire.fixture("curl.clienthello.bin")

# The Chrome example from the FoxIO JA4 specification (technical_details/JA4.md).
FOXIO_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
FOXIO_EXTS = [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0015, 0x0017,
              0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01]
FOXIO_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def foxio_hello(**over):
    bodies = {0x0000: wire.ext_sni("example.com"), 0x0010: wire.ext_alpn(["h2", "http/1.1"]),
              0x000d: wire.u16_list(FOXIO_SIGALGS),
              0x002b: wire.u16_list([0x0304, 0x0303], len_bytes=1)}
    exts = over.pop("exts", FOXIO_EXTS)
    return wire.client_hello(over.pop("ciphers", FOXIO_CIPHERS),
                             [(e, bodies.get(e, b"")) for e in exts], **over)


# ---- framing ---------------------------------------------------------------

def test_record_length_needs_five_bytes():
    with pytest.raises(tls.NeedMoreData):
        tls.record_length(CHROMIUM[:4])
    assert tls.record_length(CHROMIUM[:5]) == len(CHROMIUM)


@pytest.mark.parametrize("data", [b"GET / HTTP/1.1\r\n", b"\x17\x03\x03\x00\x10", b"\x16\x02\x00\x00\x10"])
def test_record_length_rejects_non_tls(data):
    with pytest.raises(tls.NotTls):
        tls.record_length(data)


def test_truncated_record_needs_more_data():
    with pytest.raises(tls.NeedMoreData):
        tls.parse_client_hello(CHROMIUM[:-1])


def test_trailing_bytes_after_record_are_ignored():
    ch = tls.parse_client_hello(CHROMIUM + b"\x14\x03\x03\x00\x01\x01")
    assert ch.record_len == len(CHROMIUM)
    assert tls.ja4(ch) == tls.ja4(tls.parse_client_hello(CHROMIUM))


def test_server_hello_is_not_a_client_hello():
    data = bytearray(CURL)
    data[5] = 2
    with pytest.raises(tls.NotTls):
        tls.parse_client_hello(bytes(data))


def test_hello_without_extensions():
    ch = tls.parse_client_hello(wire.client_hello([0x002f], None, session_id=b""))
    assert ch.ciphers == [0x002f] and ch.extensions == [] and ch.session_id_len == 0
    assert ch.tls_version() == 0x0303


def test_malformed_extension_body_is_skipped():
    data = wire.client_hello([0x1301], [(10, b"\x00\x08\x00\x1d"), (16, wire.ext_alpn(["h2"]))])
    ch = tls.parse_client_hello(data)
    assert ch.extensions == [10, 16]
    assert ch.alpn == ["h2"]


@pytest.mark.parametrize("v,grease", [(0x0a0a, True), (0xfafa, True), (0x1a1a, True),
                                      (0x0a0b, False), (0x1301, False)])
def test_is_grease(v, grease):
    assert tls.is_grease(v) is grease


# ---- real clients ----------------------------------------------------------------

def test_chromium_client_hello():
    ch = tls.parse_client_hello(CHROMIUM)
    assert ch.record_len == len(CHROMIUM) == 1538
    assert ch.record_version == 0x0301 and ch.handshake_version == 0x0303
    assert ch.tls_version() == 0x0304
    assert ch.session_id_len == 32
    assert ch.sni == "fixture.test"
    assert ch.alpn == ["h2", "http/1.1"]
    assert ch.ciphers_no_grease() == FOXIO_CIPHERS
    assert tls.is_grease(ch.ciphers[0])
    assert tls.is_grease(ch.extensions[0]) and tls.is_grease(ch.extensions[-1])
    assert ch.groups_no_grease() == [0x11ec, 0x001d, 0x0017, 0x0018]
    assert [(g, n) for g, n in ch.key_shares if not tls.is_grease(g)] == [(0x11ec, 1216), (0x001d, 32)]
    assert ch.compress_cert == [2]
    assert ch.ec_point_formats == [0]
    assert ch.psk_modes == [1]
    assert 51764 in ch.extensions  # trust_anchors


def test_chromium_decoded():
    d = tls.decoded(tls.parse_client_hello(CHROMIUM))
    assert d["record_version"] == "TLS 1.0" and d["offered_versions"] == ["TLS 1.3", "TLS 1.2"]
    assert d["grease"] == {"ciphers": 1, "extensions": 2, "groups": 1, "versions": 1}
    assert d["compress_cert"] == ["brotli"]
    assert d["key_shares"][1] == {"group": "X25519MLKEM768", "len": 1216}
    assert d["ciphers"][0] == {"id": "0x1301", "name": "TLS_AES_128_GCM_SHA256"}
    assert {"id": 17613, "name": "application_settings", "len": 5} in d["extensions"]
    assert d["trust_anchors_len"] == 2  # fresh profile: empty list


def test_chromium_shape_vocabulary():
    s = tls.shape(tls.parse_client_hello(CHROMIUM))
    assert s["extensions"][0] == "GREASE" and s["extensions"][-1] == "GREASE"
    assert s["groups"] == ["GREASE", "0x11ec", "0x1d", "0x17", "0x18"]
    assert s["keyshare"] == [["GREASE", 1], ["0x11ec", 1216], ["0x1d", 32]]
    assert s["supported_versions"] == ["0x304", "0x303"]
    assert s["client_hello_len"] == 1538


def test_curl_client_hello():
    ch = tls.parse_client_hello(CURL)
    assert ch.sni == "fixture.test"
    assert not any(tls.is_grease(x) for x in ch.ciphers + ch.extensions + ch.groups)
    assert ch.ec_point_formats == [0, 1, 2]
    assert ch.ciphers[-1] == 0x00ff
    assert ch.key_shares == [(0x001d, 32)]
    assert tls.decoded(ch)["trust_anchors_len"] is None


# ---- JA3 -------------------------------------------------------------------------

def test_ja3_curl():
    j = tls.ja3(tls.parse_client_hello(CURL))
    assert j["raw"] == (
        "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103"
        "-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21,"
        "29-23-30-25-24-256-257-258-259-260,0-1-2")
    assert j["hash"] == hashlib.md5(j["raw"].encode()).hexdigest() == "0149f47eabf9a20d0893e2a44e5a6323"


def test_ja3_drops_grease():
    ch = tls.parse_client_hello(CHROMIUM)
    ver, ciphers, exts, groups, fmts = tls.ja3(ch)["raw"].split(",")
    assert ver == "771" and fmts == "0"
    assert ciphers.split("-") == [str(c) for c in FOXIO_CIPHERS]
    assert len(exts.split("-")) == len(ch.extensions) - 2
    assert groups == "4588-29-23-24"


def test_ja3n_is_extension_order_insensitive():
    a = tls.parse_client_hello(CHROMIUM)
    b = tls.parse_client_hello(CHROMIUM)
    b.extensions = list(reversed(b.extensions))
    assert tls.ja3(a)["hash"] != tls.ja3(b)["hash"]
    assert tls.ja3n(a) == tls.ja3n(b)
    assert tls.ja4(a)["hash"] == tls.ja4(b)["hash"]
    assert tls.ja4(a)["original"] != tls.ja4(b)["original"]


# ---- JA4 -------------------------------------------------------------------------

def test_ja4_foxio_reference_vector():
    j = tls.ja4(tls.parse_client_hello(foxio_hello()))
    assert j["hash"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert j["raw"] == ("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
                        "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_"
                        "0403,0804,0401,0503,0805,0501,0806,0601")


def test_ja4_chromium_cipher_part_matches_chrome():
    j = tls.ja4(tls.parse_client_hello(CHROMIUM))
    assert j["hash"].startswith("t13d1516h2_8daaf6152771_")


def test_ja4_curl():
    assert tls.ja4(tls.parse_client_hello(CURL))["hash"] == "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6"


def test_ja4_without_sni_is_ip():
    exts = [e for e in FOXIO_EXTS if e != 0]
    assert tls.ja4(tls.parse_client_hello(foxio_hello(exts=exts)))["hash"].startswith("t13i1515h2_")


def test_ja4_quic_transport_prefix():
    assert tls.ja4(tls.parse_client_hello(foxio_hello()), transport="q")["hash"].startswith("q13d")


def test_ja4_tls12_only():
    exts = [e for e in FOXIO_EXTS if e != 0x002b]
    assert tls.ja4(tls.parse_client_hello(foxio_hello(exts=exts)))["hash"][:3] == "t12"


def test_ja4_ignores_grease_sigalgs():
    ch = tls.parse_client_hello(foxio_hello())
    ch.sigalgs = [0x7a7a] + ch.sigalgs
    assert tls.ja4(ch)["hash"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4_empty_lists_hash_to_zeros():
    j = tls.ja4(tls.ClientHello(handshake_version=0x0303))
    assert j["hash"] == "t12i000000_000000000000_000000000000"


@pytest.mark.parametrize("alpn,code", [([], "00"), ([""], "00"), (["h2"], "h2"), (["http/1.1"], "h1"),
                                       (["h3", "h2"], "h3"), (["#x/"], "2f")])
def test_ja4_alpn_code(alpn, code):
    assert tls._ja4_alpn(alpn) == code


def test_ja4_counts_cap_at_99():
    ch = tls.ClientHello(handshake_version=0x0303, ciphers=list(range(1, 150)))
    assert tls.ja4(ch)["hash"][:10] == "t12i990000"


# ---- reference captures ---------------------------------------------------------

@pytest.mark.parametrize("name", sorted(p.name for p in wire.CAPTURES.glob("*-clienthello.json")))
def test_capture_round_trips_through_the_wire(name):
    """A capture re-encoded as bytes parses back to the same shape and fingerprints."""
    cap = capture(name)
    sni = None if 0 not in cap["extensions"] else "example.com"
    ch = tls.parse_client_hello(wire.client_hello_from_capture(cap, sni=sni))
    ref = tls.from_capture(cap)
    observed = tls.shape(ch)
    assert tls.compare_shapes(observed, tls.shape(ref)) == []
    assert observed["extensions"] == tls.shape(ref)["extensions"]
    if sni:
        assert tls.ja3(ch) == tls.ja3(ref)
        assert tls.ja4(ch)["hash"] == tls.ja4(ref)["hash"]


def test_from_capture_firefox():
    ch = tls.from_capture(capture("firefox-154-clienthello.json"))
    assert ch.ec_point_formats == [0]
    assert ch.record_len == 1872
    assert tls.ja4(ch)["hash"].startswith("t13d1516h2_")


# ---- compare_shapes ---------------------------------------------------------------

@pytest.fixture
def chrome_ref():
    s = tls.shape(tls.from_capture(capture("chrome-152-stable-clienthello.json")))
    s["extension_order"] = "random"
    return s


def test_compare_identical(chrome_ref):
    assert tls.compare_shapes(dict(chrome_ref), chrome_ref) == []


def test_compare_ignores_permutation_when_random(chrome_ref):
    obs = dict(chrome_ref, extensions=list(reversed(chrome_ref["extensions"])))
    assert tls.compare_shapes(obs, chrome_ref) == []
    fixed = dict(chrome_ref, extension_order=None)
    assert tls.compare_shapes(obs, fixed) == ["extension order differs (same set)"]


def test_compare_ignores_sni_padding_psk(chrome_ref):
    obs = dict(chrome_ref, extensions=[e for e in chrome_ref["extensions"] if e != 0] + [21, 41, 42])
    assert tls.compare_shapes(obs, chrome_ref) == []


def test_compare_names_missing_and_extra(chrome_ref):
    obs = dict(chrome_ref, extensions=[e for e in chrome_ref["extensions"] if e != 65037] + [22],
               groups=["GREASE", "0x1d", "0x17"], alpn=["http/1.1"])
    diffs = tls.compare_shapes(obs, chrome_ref)
    assert "extensions: missing 65037 (encrypted_client_hello); extra 22 (encrypt_then_mac)" in diffs
    assert "supported groups: missing 0x11ec (X25519MLKEM768), 0x18 (secp384r1)" in diffs
    assert "ALPN ['http/1.1'] vs ['h2', 'http/1.1']" in diffs


def test_compare_order_only_cipher_difference(chrome_ref):
    obs = dict(chrome_ref, ciphers=list(reversed(chrome_ref["ciphers"])))
    assert tls.compare_shapes(obs, chrome_ref) == ["cipher suites: order differs"]
