"""TLS ClientHello parsing and fingerprint derivation (JA3, JA4).

The parser mirrors ``tools/capture_clienthello.py`` so that the
decoded shape is directly comparable with the reference captures in
``captures/``. GREASE values (RFC 8701) are collapsed to the literal "GREASE".
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

# Extension numbers with names (for the UI). Unknown ones are shown as numbers.
EXT_NAMES = {
    0: "server_name", 5: "status_request", 10: "supported_groups",
    11: "ec_point_formats", 13: "signature_algorithms", 16: "alpn",
    17: "status_request_v2", 18: "signed_certificate_timestamp",
    21: "padding", 22: "encrypt_then_mac", 23: "extended_master_secret",
    27: "compress_certificate", 28: "record_size_limit",
    34: "delegated_credentials", 35: "session_ticket", 41: "pre_shared_key",
    43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes",
    49: "post_handshake_auth", 50: "signature_algorithms_cert",
    51: "key_share", 4832: "unknown_4832", 17513: "application_settings_old",
    17613: "application_settings", 51764: "trust_anchors",
    65037: "encrypted_client_hello", 65281: "renegotiation_info",
}

GROUP_NAMES = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001d: "x25519", 0x001e: "x448", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
    0x11ec: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00",
}

SIGALG_NAMES = {
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256",
    0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512",
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1",
    0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
    0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384", 0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0xcca8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xc013: "ECDHE-RSA-AES128-SHA", 0xc014: "ECDHE-RSA-AES256-SHA",
    0x009c: "AES128-GCM-SHA256", 0x009d: "AES256-GCM-SHA384",
    0x002f: "AES128-SHA", 0x0035: "AES256-SHA", 0x000a: "DES-CBC3-SHA",
    0xc009: "ECDHE-ECDSA-AES128-SHA", 0xc00a: "ECDHE-ECDSA-AES256-SHA",
    0xc023: "ECDHE-ECDSA-AES128-SHA256", 0xc027: "ECDHE-RSA-AES128-SHA256",
    0x0067: "DHE-RSA-AES128-SHA256", 0x0033: "DHE-RSA-AES128-SHA",
    0x0039: "DHE-RSA-AES256-SHA", 0x009e: "DHE-RSA-AES128-GCM-SHA256",
    0x009f: "DHE-RSA-AES256-GCM-SHA384", 0x00ff: "EMPTY_RENEGOTIATION_INFO_SCSV",
}

VERSION_NAMES = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1",
                 0x0301: "TLS 1.0", 0x0300: "SSL 3.0"}


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A


class NeedMoreData(Exception):
    """The buffer does not yet hold the complete first TLS record."""


class NotTls(Exception):
    """The first bytes are not a TLS handshake record."""


def record_length(buf: bytes) -> int:
    """Return the total length of the first TLS record, or raise."""
    if len(buf) < 5:
        raise NeedMoreData
    if buf[0] != 0x16 or buf[1] != 0x03:
        raise NotTls
    return 5 + struct.unpack("!H", buf[3:5])[0]


@dataclass
class ClientHello:
    record_version: int = 0
    handshake_version: int = 0
    random_hex: str = ""
    session_id_len: int = 0
    ciphers: list[int] = field(default_factory=list)          # raw, incl. GREASE
    compression: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)       # raw order, incl. GREASE
    groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    sigalgs: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    key_shares: list[tuple[int, int]] = field(default_factory=list)
    compress_cert: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    psk_modes: list[int] = field(default_factory=list)
    sni: str | None = None
    bodies: dict[int, bytes] = field(default_factory=dict)
    total_len: int = 0
    record_len: int = 0

    # ---- helpers -------------------------------------------------------
    def ciphers_no_grease(self) -> list[int]:
        return [c for c in self.ciphers if not is_grease(c)]

    def ext_no_grease(self) -> list[int]:
        return [e for e in self.extensions if not is_grease(e)]

    def groups_no_grease(self) -> list[int]:
        return [g for g in self.groups if not is_grease(g)]

    def tls_version(self) -> int:
        """Highest offered version (supported_versions, else handshake)."""
        vs = [v for v in self.supported_versions if not is_grease(v)]
        return max(vs) if vs else self.handshake_version


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse one complete ClientHello record (possibly followed by junk)."""
    rl = record_length(data)
    if len(data) < rl:
        raise NeedMoreData
    ch = ClientHello(record_len=rl)
    ch.record_version = struct.unpack("!H", data[1:3])[0]
    hs = data[5:rl]
    if not hs or hs[0] != 1:
        raise NotTls("not a ClientHello")
    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + hs_len]
    if len(body) < hs_len:
        # ClientHello spanning multiple records (rare); take what we have.
        body = hs[4:]
    ch.total_len = 4 + hs_len
    p = 0
    ch.handshake_version = struct.unpack("!H", body[p:p + 2])[0]; p += 2
    ch.random_hex = body[p:p + 32].hex(); p += 32
    sid_len = body[p]; p += 1
    ch.session_id_len = sid_len; p += sid_len
    cs_len = struct.unpack("!H", body[p:p + 2])[0]; p += 2
    ch.ciphers = [struct.unpack("!H", body[p + i:p + i + 2])[0] for i in range(0, cs_len, 2)]
    p += cs_len
    comp_len = body[p]; p += 1
    ch.compression = list(body[p:p + comp_len]); p += comp_len
    if p + 2 > len(body):
        return ch
    ext_len = struct.unpack("!H", body[p:p + 2])[0]; p += 2
    end = min(p + ext_len, len(body))
    while p + 4 <= end:
        et = struct.unpack("!H", body[p:p + 2])[0]
        el = struct.unpack("!H", body[p + 2:p + 4])[0]
        eb = body[p + 4:p + 4 + el]
        p += 4 + el
        ch.extensions.append(et)
        ch.bodies[et] = eb
        try:
            _parse_ext(ch, et, eb)
        except (struct.error, IndexError, UnicodeDecodeError):
            pass
    return ch


def _u16_list(b: bytes, off: int, n: int) -> list[int]:
    return [struct.unpack("!H", b[off + i:off + i + 2])[0] for i in range(0, n, 2)]


def _parse_ext(ch: ClientHello, et: int, b: bytes) -> None:
    if et == 0:  # server_name
        q = 2
        while q + 3 <= len(b):
            ntype = b[q]; nlen = struct.unpack("!H", b[q + 1:q + 3])[0]
            if ntype == 0:
                ch.sni = b[q + 3:q + 3 + nlen].decode("idna", "replace")
            q += 3 + nlen
    elif et == 10:
        n = struct.unpack("!H", b[:2])[0]; ch.groups = _u16_list(b, 2, n)
    elif et == 11:
        n = b[0]; ch.ec_point_formats = list(b[1:1 + n])
    elif et == 13:
        n = struct.unpack("!H", b[:2])[0]; ch.sigalgs = _u16_list(b, 2, n)
    elif et == 16:
        q = 2
        while q < len(b):
            l = b[q]; ch.alpn.append(b[q + 1:q + 1 + l].decode("ascii", "replace")); q += 1 + l
    elif et == 51:
        n = struct.unpack("!H", b[:2])[0]; q = 2
        while q + 4 <= 2 + n:
            g = struct.unpack("!H", b[q:q + 2])[0]; l = struct.unpack("!H", b[q + 2:q + 4])[0]
            ch.key_shares.append((g, l)); q += 4 + l
    elif et == 27:
        n = b[0]; ch.compress_cert = _u16_list(b, 1, n)
    elif et == 43:
        n = b[0]; ch.supported_versions = _u16_list(b, 1, n)
    elif et == 45:
        n = b[0]; ch.psk_modes = list(b[1:1 + n])


# ---------------------------------------------------------------------------
# JA3 (Salesforce) — md5 of "ver,ciphers,extensions,groups,ec_point_formats"
# ---------------------------------------------------------------------------

def ja3(ch: ClientHello) -> dict[str, str]:
    parts = [
        str(ch.handshake_version),
        "-".join(str(c) for c in ch.ciphers_no_grease()),
        "-".join(str(e) for e in ch.ext_no_grease()),
        "-".join(str(g) for g in ch.groups_no_grease()),
        "-".join(str(f) for f in ch.ec_point_formats),
    ]
    raw = ",".join(parts)
    return {"hash": hashlib.md5(raw.encode()).hexdigest(), "raw": raw}


def ja3n(ch: ClientHello) -> dict[str, str]:
    """JA3 with extensions sorted (order-insensitive variant)."""
    parts = [
        str(ch.handshake_version),
        "-".join(str(c) for c in ch.ciphers_no_grease()),
        "-".join(str(e) for e in sorted(ch.ext_no_grease())),
        "-".join(str(g) for g in ch.groups_no_grease()),
        "-".join(str(f) for f in ch.ec_point_formats),
    ]
    raw = ",".join(parts)
    return {"hash": hashlib.md5(raw.encode()).hexdigest(), "raw": raw}


# ---------------------------------------------------------------------------
# JA4 (FoxIO) — https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
# ---------------------------------------------------------------------------

def _ja4_version(v: int) -> str:
    return {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
            0x0300: "s3", 0x0002: "s2"}.get(v, "00")


def _ja4_alpn(alpn: list[str]) -> str:
    if not alpn:
        return "00"
    a = alpn[0]
    if not a:
        return "00"
    first, last = a[0], a[-1]
    if not (first.isalnum() and last.isalnum()):
        b = a.encode("utf-8", "replace")
        return f"{b[0]:02x}"[0] + f"{b[-1]:02x}"[-1]
    return first + last


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def ja4(ch: ClientHello, transport: str = "t") -> dict[str, str]:
    ciphers = ch.ciphers_no_grease()
    exts = ch.ext_no_grease()
    sigalgs = [x for x in ch.sigalgs if not is_grease(x)]  # Chrome GREASEs sigalgs too; JA4 drops GREASE
    a = "".join([
        transport,
        _ja4_version(ch.tls_version()),
        "d" if ch.sni else "i",
        f"{min(len(ciphers), 99):02d}",
        f"{min(len(exts), 99):02d}",
        _ja4_alpn(ch.alpn),
    ])
    cipher_sorted = ",".join(f"{c:04x}" for c in sorted(ciphers))
    cipher_orig = ",".join(f"{c:04x}" for c in ciphers)
    ext_hash_list = sorted(e for e in exts if e not in (0x0000, 0x0010))
    ext_sorted = ",".join(f"{e:04x}" for e in ext_hash_list)
    ext_orig = ",".join(f"{e:04x}" for e in exts)
    sig = ",".join(f"{s:04x}" for s in sigalgs)
    c_raw = ext_sorted + ("_" + sig if sig else "")
    c_raw_o = ext_orig + ("_" + sig if sig else "")
    b = _sha12(cipher_sorted) if ciphers else "000000000000"
    c = _sha12(c_raw) if exts else "000000000000"
    b_o = _sha12(cipher_orig) if ciphers else "000000000000"
    c_o = _sha12(c_raw_o) if exts else "000000000000"
    return {
        "hash": f"{a}_{b}_{c}",
        "raw": f"{a}_{cipher_sorted}_{c_raw}",
        "original": f"{a}_{b_o}_{c_o}",
        "original_raw": f"{a}_{cipher_orig}_{c_raw_o}",
    }


# ---------------------------------------------------------------------------
# JSON-friendly shape (same vocabulary as captures/*.json captures)
# ---------------------------------------------------------------------------

def shape(ch: ClientHello) -> dict[str, Any]:
    def g(v: int) -> str:
        return "GREASE" if is_grease(v) else hex(v)
    return {
        "ciphers": [hex(c) for c in ch.ciphers_no_grease()],
        "extensions": [e if not is_grease(e) else "GREASE" for e in ch.extensions],
        "groups": [g(x) for x in ch.groups],
        "sigalgs": [g(s) for s in ch.sigalgs],
        "alpn": list(ch.alpn),
        "keyshare": [[g(x), l] for x, l in ch.key_shares],
        "compress_cert": [hex(c) for c in ch.compress_cert],
        "supported_versions": [hex(v) for v in ch.supported_versions if not is_grease(v)],
        "client_hello_len": ch.record_len,
    }


def decoded(ch: ClientHello) -> dict[str, Any]:
    """Human-oriented decode for the UI."""
    return {
        "record_version": VERSION_NAMES.get(ch.record_version, hex(ch.record_version)),
        "handshake_version": VERSION_NAMES.get(ch.handshake_version, hex(ch.handshake_version)),
        "offered_versions": [VERSION_NAMES.get(v, hex(v)) for v in ch.supported_versions if not is_grease(v)],
        "sni": ch.sni,
        "session_id_len": ch.session_id_len,
        "grease": {
            "ciphers": sum(1 for c in ch.ciphers if is_grease(c)),
            "extensions": sum(1 for e in ch.extensions if is_grease(e)),
            "groups": sum(1 for g in ch.groups if is_grease(g)),
            "versions": sum(1 for v in ch.supported_versions if is_grease(v)),
        },
        "ciphers": [{"id": hex(c), "name": CIPHER_NAMES.get(c, "?")} for c in ch.ciphers_no_grease()],
        "extensions": [
            {"id": "GREASE" if is_grease(e) else e,
             "name": "GREASE" if is_grease(e) else EXT_NAMES.get(e, f"ext_{e}"),
             "len": len(ch.bodies.get(e, b""))}
            for e in ch.extensions
        ],
        "groups": [{"id": "GREASE" if is_grease(g) else hex(g),
                    "name": "GREASE" if is_grease(g) else GROUP_NAMES.get(g, "?")} for g in ch.groups],
        "sigalgs": [{"id": hex(s), "name": SIGALG_NAMES.get(s, "?")} for s in ch.sigalgs],
        "alpn": list(ch.alpn),
        "key_shares": [{"group": "GREASE" if is_grease(g) else GROUP_NAMES.get(g, hex(g)), "len": l}
                       for g, l in ch.key_shares],
        "compress_cert": [{1: "zlib", 2: "brotli", 3: "zstd"}.get(c, hex(c)) for c in ch.compress_cert],
        "psk_modes": ch.psk_modes,
        "ec_point_formats": ch.ec_point_formats,
        "record_len": ch.record_len,
        "trust_anchors_len": len(ch.bodies.get(51764, b"")) if 51764 in ch.bodies else None,
    }


def from_capture(cap: dict[str, Any]) -> ClientHello:
    """Rebuild a ClientHello from a captures/*.json capture (for JA3/JA4 of the reference)."""
    ch = ClientHello()
    ch.handshake_version = 0x0303
    ch.ciphers = [int(c, 16) for c in cap.get("ciphers", [])]
    ch.extensions = [0x0a0a if e == "GREASE" else int(e) for e in cap.get("extensions", [])]
    ch.groups = [0x0a0a if g == "GREASE" else int(g, 16) for g in cap.get("groups", [])]
    ch.sigalgs = [int(s, 16) for s in cap.get("sigalgs", [])]
    ch.alpn = list(cap.get("alpn", []))
    ch.key_shares = [(0x0a0a if g == "GREASE" else int(g, 16), l) for g, l in cap.get("keyshare", [])]
    ch.compress_cert = [int(c, 16) for c in cap.get("compress_cert", [])]
    ch.supported_versions = [int(v, 16) for v in cap.get("supported_versions", [])]
    ch.sni = "example.com"  # captures were made with an SNI present
    bodies = cap.get("extension_bodies_hex", {})
    for k, v in bodies.items():
        try:
            ch.bodies[int(k)] = bytes.fromhex(v)
        except ValueError:
            pass
    if 11 in ch.bodies:
        b = ch.bodies[11]
        ch.ec_point_formats = list(b[1:1 + b[0]]) if b else []
    elif 11 in ch.extensions:
        ch.ec_point_formats = [0]  # Chrome/Firefox send "uncompressed" only
    ch.record_len = cap.get("client_hello_len", 0)
    return ch


def compare_shapes(actual: dict[str, Any], reference: dict[str, Any]) -> list[str]:
    """Explain how an observed shape differs from a reference capture.

    Returns a list of human-readable differences (empty means identical in
    every fingerprint-relevant dimension). Ignored on purpose:

    * ext 21 (padding) — presence depends on the SNI length, not the browser;
    * ext 0 (SNI) — absent when the client connects to an IP literal;
    * ext 41 / 42 (pre_shared_key, early_data) — only present on session
      resumption, while reference captures are fresh connections;
    * GREASE values everywhere (they change per connection);
    * extension *order* when the reference says it is permuted per connection
      (Chrome ``permute_extensions``), signalled by ``extension_order: "random"``.
    """
    diffs: list[str] = []
    IGNORED_EXT = {0, 21, 41, 42}

    def norm_ext(lst):
        return [e for e in lst if e != "GREASE" and e not in IGNORED_EXT]

    def no_grease(lst):
        return [x for x in lst if x != "GREASE"]

    if no_grease(actual.get("ciphers", [])) != no_grease(reference.get("ciphers", [])):
        diffs.append(_list_diff("cipher suites", actual.get("ciphers", []), reference.get("ciphers", [])))
    a_ext, r_ext = norm_ext(actual.get("extensions", [])), norm_ext(reference.get("extensions", []))
    if a_ext != r_ext:
        if sorted(map(str, a_ext)) == sorted(map(str, r_ext)):
            if reference.get("extension_order") != "random":
                diffs.append("extension order differs (same set)")
        else:
            diffs.append(_list_diff("extensions", a_ext, r_ext))
    if no_grease(actual.get("groups", [])) != no_grease(reference.get("groups", [])):
        diffs.append(_list_diff("supported groups", actual.get("groups", []), reference.get("groups", [])))
    if no_grease(actual.get("sigalgs", [])) != no_grease(reference.get("sigalgs", [])):
        diffs.append(_list_diff("signature algorithms", actual.get("sigalgs", []), reference.get("sigalgs", [])))
    if actual.get("alpn") != reference.get("alpn"):
        diffs.append(f"ALPN {actual.get('alpn')} vs {reference.get('alpn')}")
    a_ks = [g for g, _ in actual.get("keyshare", []) if g != "GREASE"]
    r_ks = [g for g, _ in reference.get("keyshare", []) if g != "GREASE"]
    if a_ks != r_ks:
        diffs.append(f"key share groups {a_ks} vs {r_ks}")
    if actual.get("compress_cert") != reference.get("compress_cert"):
        diffs.append(f"certificate compression {actual.get('compress_cert')} vs {reference.get('compress_cert')}")
    if actual.get("supported_versions") != reference.get("supported_versions"):
        diffs.append(f"supported versions {actual.get('supported_versions')} vs {reference.get('supported_versions')}")
    return diffs


def _list_diff(what: str, a: list, r: list) -> str:
    a = [x for x in a if x != "GREASE"]
    r = [x for x in r if x != "GREASE"]
    sa, sr = set(map(str, a)), set(map(str, r))
    missing = [x for x in map(str, r) if x not in sa]
    extra = [x for x in map(str, a) if x not in sr]
    bits = []
    if missing:
        bits.append("missing " + ", ".join(_pretty(what, m) for m in missing))
    if extra:
        bits.append("extra " + ", ".join(_pretty(what, e) for e in extra))
    if not bits:
        bits.append("order differs")
    return f"{what}: " + "; ".join(bits)


def _pretty(what: str, v: str) -> str:
    try:
        n = int(v, 16) if v.startswith("0x") else int(v)
    except ValueError:
        return v
    table = {"extensions": EXT_NAMES, "supported groups": GROUP_NAMES,
             "signature algorithms": SIGALG_NAMES, "cipher suites": CIPHER_NAMES}.get(what, {})
    name = table.get(n)
    return f"{v} ({name})" if name else v
