import pytest

import wire
from conftest import (CHROME_152_UA, FIREFOX_154_UA, build_net, capture, decode_request_headers,
                      navigation_headers)
from dactyloscope import analysis

HEADLESS_141_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "HeadlessChrome/141.0.0.0 Safari/537.36")


def ids(report, severity=None):
    return {f["id"] for f in report["findings"] if severity in (None, f["severity"])}


def chrome_hello():
    return wire.client_hello_from_capture(capture("chrome-152-stable-clienthello.json"))


def chrome_preface(headers):
    return wire.preface_from_capture(capture("chrome-152-h2-preface.json"), headers)


def firefox_hello():
    return wire.client_hello_from_capture(capture("firefox-154-clienthello.json"), sni=None)


def firefox_preface(headers):
    return wire.preface_from_capture(capture("firefox-154-h2-preface.json"), headers)


# ---- User-Agent ------------------------------------------------------------------

@pytest.mark.parametrize("ua,family,major,os,headless,mobile", [
    (CHROME_152_UA, "chrome", 152, "linux", False, False),
    (HEADLESS_141_UA, "chrome", 141, "linux", True, False),
    (FIREFOX_154_UA, "firefox", 154, "linux", False, False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0", "edge", 150, "windows", False, False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/150.0.0.0 Safari/537.36 OPR/120.0.0.0", "opera", 120, "windows", False, False),
    ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/152.0.0.0 Mobile Safari/537.36", "chrome", 152, "android", False, True),
    ("curl/8.5.0", "other", None, "other", False, False),
    (None, "other", None, "other", False, False),
])
def test_parse_ua(ua, family, major, os, headless, mobile):
    u = analysis.parse_ua(ua)
    assert (u["family"], u["major"], u["os"], u["headless"], u["mobile"]) == (family, major, os, headless, mobile)


def test_family_maps():
    assert [analysis.tls_family_of(f) for f in ("chrome", "edge", "opera", "firefox", "safari")] == \
        ["chrome", "chrome", "chrome", "firefox", None]
    assert analysis.engine_of("edge") == "v8" and analysis.engine_of("firefox") == "spidermonkey"


# ---- network: reference browsers are clean ------------------------------------------

def test_chrome_152_reference_is_clean(known):
    hdrs = navigation_headers("chrome", CHROME_152_UA, 152)
    r = analysis.analyse({}, build_net(known, client_hello=chrome_hello(), h2_bytes=chrome_preface(hdrs),
                                       headers=hdrs), known)
    assert (r["score"], r["verdict"]) == (0, "clean")
    assert ids(r) == {"tls.known", "h2.known", "http.known"}
    idn = r["identity"]
    assert (idn["tls_family"], idn["h2_family"], idn["http_family"]) == ("chrome", "chrome", "chrome")
    assert idn["claimed"] == {"family": "chrome", "major": 152, "os": "linux", "headless_ua": False, "engine": "v8"}


def test_firefox_154_reference_is_clean(known):
    hdrs = navigation_headers("firefox", FIREFOX_154_UA)
    r = analysis.analyse({}, build_net(known, client_hello=firefox_hello(), h2_bytes=firefox_preface(hdrs),
                                       headers=hdrs), known)
    assert r["verdict"] == "clean", r["findings"]
    assert ids(r) == {"tls.known", "h2.known", "http.known"}


# ---- network: recorded clients ----------------------------------------------------------

def test_headless_chromium_141(known):
    h2_bytes = wire.fixture("chromium-141.h2.bin")
    hdrs = decode_request_headers(h2_bytes)
    assert dict(hdrs)["user-agent"] == HEADLESS_141_UA
    r = analysis.analyse({}, build_net(known, client_hello=wire.fixture("chromium-141.clienthello.bin"),
                                       h2_bytes=h2_bytes, headers=hdrs), known)
    assert ids(r, "fail") >= {"tls.unknown", "h2.unknown", "http.headless_ua"}
    tls_unknown = next(f for f in r["findings"] if f["id"] == "tls.unknown")
    assert "closest is Chrome 149" in tls_unknown["message"]
    assert tls_unknown["evidence"]["differences"] == ["extensions: missing 65037 (encrypted_client_hello)"]
    assert (r["score"], r["verdict"]) == (100, "automated")
    assert r["findings"][0]["severity"] == "fail"  # sorted fail, warn, info


def test_curl(known):
    h2_bytes = wire.fixture("curl.h2.bin")
    hdrs = decode_request_headers(h2_bytes)
    r = analysis.analyse({}, build_net(known, client_hello=wire.fixture("curl.clienthello.bin"),
                                       h2_bytes=h2_bytes, headers=hdrs), known)
    # No browser claimed, so unknown shapes are only suspicious.
    assert ids(r, "warn") == {"tls.unknown", "h2.unknown", "http.unknown_ua"}
    assert ids(r, "fail") == set()
    assert (r["score"], r["verdict"]) == (18, "suspicious")


# ---- network: lies ------------------------------------------------------------------------

def test_firefox_ua_on_chrome_tls(known):
    hdrs = navigation_headers("firefox", FIREFOX_154_UA)
    engine_hdrs = navigation_headers("chrome", FIREFOX_154_UA, 152)  # Chrome's pseudo-header order on the wire
    r = analysis.analyse({}, build_net(known, client_hello=chrome_hello(), h2_bytes=chrome_preface(engine_hdrs),
                                       headers=hdrs), known)
    assert {"tls.family_mismatch", "h2.family_mismatch"} <= ids(r, "fail")
    assert "tls.grease_firefox" in ids(r, "warn")


def test_chrome_ua_on_firefox_tls(known):
    hdrs = navigation_headers("chrome", CHROME_152_UA, 152)
    engine_hdrs = navigation_headers("firefox", CHROME_152_UA)
    r = analysis.analyse({}, build_net(known, client_hello=firefox_hello(), h2_bytes=firefox_preface(engine_hdrs),
                                       headers=hdrs), known)
    assert {"tls.family_mismatch", "h2.family_mismatch"} <= ids(r, "fail")
    assert "tls.no_grease" in ids(r, "warn")


def test_old_chrome_ua_on_new_chrome_tls(known):
    ua = CHROME_152_UA.replace("152.", "140.")
    hdrs = navigation_headers("chrome", ua, 140)
    r = analysis.analyse({}, build_net(known, client_hello=chrome_hello(), h2_bytes=chrome_preface(hdrs),
                                       headers=hdrs), known)
    mm = next(f for f in r["findings"] if f["id"] == "tls.major_mismatch")
    assert mm["severity"] == "warn"
    # Chrome 150's ClientHello equals 152's once the GREASE sigalg is set aside.
    assert mm["evidence"] == {"claimed_major": 140, "shape_majors": [150, 152, 152]}
    assert "the one of Chrome 150–152" in mm["message"]


def test_h2_offered_but_http1_used(known):
    r = analysis.analyse({}, build_net(known, client_hello=chrome_hello(), headers=[("user-agent", CHROME_152_UA)]),
                         known)
    assert "h2.not_used" in ids(r, "warn")


def test_tls12_negotiated(known):
    r = analysis.analyse({}, build_net(known, client_hello=chrome_hello(), tls_version="TLSv1.2",
                                       headers=[("user-agent", CHROME_152_UA)]), known)
    assert "tls.not_13" in ids(r, "warn")


def test_no_alpn_and_http1_over_tls(known):
    hello = wire.client_hello([0x1301], [(0, wire.ext_sni("a.test"))])
    r = analysis.analyse({}, build_net(known, client_hello=hello, headers=[("user-agent", "x")]), known)
    assert {"tls.no_alpn", "tls.unknown"} <= ids(r, "warn")
    assert "h2.absent" in ids(r, "warn")


def test_plain_http(known):
    r = analysis.analyse({}, build_net(known, scheme="http", headers=[("User-Agent", CHROME_152_UA)]), known)
    assert "tls.plain" in ids(r, "info")
    assert "h2.absent" not in ids(r)


def test_https_without_client_hello(known):
    r = analysis.analyse({}, {"scheme": "https", "http_version": "1.1", "tls": None, "http": {}}, known)
    assert "tls.none" in ids(r, "info")
    assert "http.no_ua" in ids(r, "fail")


def test_unparsable_client_hello(known):
    net = {"scheme": "https", "http_version": "1.1", "tls": {"error": "unparsable ClientHello: NeedMoreData"},
           "http": {"user_agent": "x"}}
    assert "tls.unparsable" in ids(analysis.analyse({}, net, known), "warn")


# ---- headers --------------------------------------------------------------------------------

def chrome_net_with(known, edit):
    hdrs = navigation_headers("chrome", CHROME_152_UA, 152)
    hdrs = edit(hdrs)
    return build_net(known, client_hello=chrome_hello(), h2_bytes=chrome_preface(hdrs), headers=hdrs)


def test_header_order(known):
    def swap(h):
        i = [k for k, _ in h].index("accept-language")
        h.insert(7, h.pop(i))
        return h
    r = analysis.analyse({}, chrome_net_with(known, swap), known)
    assert "http.header_order" in ids(r, "fail")


def test_missing_client_hints(known):
    r = analysis.analyse({}, chrome_net_with(known, lambda h: [x for x in h if not x[0].startswith("sec-ch")]), known)
    assert "http.client_hints" in ids(r, "fail")


@pytest.mark.parametrize("header,value,finding", [
    ("sec-ch-ua", '"Chromium";v="152", "Google Chrome";v="151"', "http.ch_ua_major"),
    ("sec-ch-ua", '"Chromium";v="151", "Google Chrome";v="152"', "http.ch_ua_chromium"),
    ("sec-ch-ua", '"Chromium";v="152"', "http.ch_ua_brand"),
    ("sec-ch-ua-platform", '"Windows"', "http.ch_ua_platform"),
])
def test_client_hint_coherence(known, header, value, finding):
    r = analysis.analyse({}, chrome_net_with(known, lambda h: [(k, value if k == header else v) for k, v in h]), known)
    assert finding in ids(r, "fail")


def test_client_hint_mobile(known):
    r = analysis.analyse({}, chrome_net_with(known, lambda h: [(k, "?1" if k == "sec-ch-ua-mobile" else v)
                                                               for k, v in h]), known)
    assert "http.ch_ua_mobile" in ids(r, "warn")


def test_accept_and_sec_fetch_values(known):
    def edit(h):
        return [(k, "*/*" if k == "accept" else "cross-site" if k == "sec-fetch-site" else v) for k, v in h]
    r = analysis.analyse({}, chrome_net_with(known, edit), known)
    assert "http.accept" in ids(r, "fail")
    assert "http.sec-fetch-site" in ids(r, "warn")


# ---- JS probes ----------------------------------------------------------------------------

def clean_chrome_net(known):
    hdrs = navigation_headers("chrome", CHROME_152_UA, 152)
    return build_net(known, client_hello=chrome_hello(), h2_bytes=chrome_preface(hdrs), headers=hdrs)


def test_webdriver_and_navigator_lies(known):
    probes = {"navigator": {"userAgent": CHROME_152_UA.replace("152", "151"), "webdriver": True, "languages": [],
                            "platform": "Win32", "vendor": "Google Inc.", "productSub": "20030107",
                            "deviceMemory": 8, "plugins": [{}] * 5, "userAgentData": None,
                            "webdriverDescriptor": {"onProto": True, "onInstance": True, "getterNative": False}}}
    r = analysis.analyse(probes, clean_chrome_net(known), known)
    assert {"nav.ua_header_mismatch", "nav.webdriver", "nav.webdriver_instance", "nav.webdriver_getter_lie",
            "nav.languages_empty", "nav.platform_os", "nav.uadata_missing"} <= ids(r, "fail")
    assert r["verdict"] == "automated"


def test_spidermonkey_engine_behind_a_chrome_ua(known):
    probes = {"engine": {"stackFirst": "@https://a.test/probe.js:1:1", "evalLen": 37,
                         "nativeToString": "function eval() {\n    [native code]\n}", "errorStackDesc": "accessor",
                         "errors": {"nullProp": "can't access property \"x\", null is null"},
                         "css": {"mozAppearance": True}}}
    r = analysis.analyse(probes, clean_chrome_net(known), known)
    assert {"engine.mismatch", "engine.moz_css"} <= ids(r, "fail")
    assert r["identity"]["js_engine"] == "spidermonkey"


def test_probe_errors_are_info(known):
    r = analysis.analyse({}, clean_chrome_net(known), known, probe_errors={"canvas": "TypeError: boom"})
    assert "probe_error.canvas" in ids(r, "info")
    assert r["score"] == 0


# ---- scoring and summary --------------------------------------------------------------------

@pytest.mark.parametrize("fails,warns,score,verdict", [
    (0, 1, 6, "clean"), (0, 2, 12, "suspicious"), (1, 3, 38, "suspicious"), (2, 0, 40, "automated"),
    (9, 0, 100, "automated"),
])
def test_score_thresholds(known, monkeypatch, fails, warns, score, verdict):
    def fake(f, *a):
        for i in range(fails):
            f.fail(f"x.f{i}", "x", "f")
        for i in range(warns):
            f.warn(f"x.w{i}", "x", "w")
    monkeypatch.setattr(analysis, "_network_checks", fake)
    r = analysis.analyse({}, {}, known)
    assert (r["score"], r["verdict"], r["counts"]) == (score, verdict, {"fail": fails, "warn": warns, "info": 0})


def test_text_summary(known):
    net = build_net(known, client_hello=wire.fixture("curl.clienthello.bin"), h2_bytes=wire.fixture("curl.h2.bin"),
                    headers=decode_request_headers(wire.fixture("curl.h2.bin")))
    report = {"network": net, "analysis": analysis.analyse({}, net, known), "label": "ci"}
    text = analysis.text_summary(report)
    assert "label=ci" in text
    assert "verdict: suspicious  score: 18/100  (fail 0, warn 3, info 0)" in text
    assert "ja4: t13d3112h2_e8f1e7e78f70_b26ce05bbdd6" in text
    assert "  - [http.unknown_ua] User-Agent is not a mainstream browser" in text
