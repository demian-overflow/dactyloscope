"""Turn raw network + probe data into findings, an identity summary and a score.

Every finding has ``id``, ``severity`` (info | warn | fail), ``category``,
``message`` and ``evidence``. The score is a weighted sum (fail 20, warn 6),
capped at 100, with verdicts: clean (< 10), suspicious (< 40), automated.
"""
from __future__ import annotations

import datetime as _dt
import re
import zoneinfo
from typing import Any

from . import known as known_mod

WEIGHTS = {"fail": 20, "warn": 6, "info": 0}


class Findings:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def add(self, fid: str, severity: str, category: str, message: str, evidence: Any = None) -> None:
        self.items.append({"id": fid, "severity": severity, "category": category,
                           "message": message, "evidence": evidence})

    fail = lambda self, *a, **k: self.add(a[0], "fail", *a[1:], **k)  # noqa: E731
    warn = lambda self, *a, **k: self.add(a[0], "warn", *a[1:], **k)  # noqa: E731
    info = lambda self, *a, **k: self.add(a[0], "info", *a[1:], **k)  # noqa: E731


# ---------------------------------------------------------------------------
# User-Agent parsing (enough for consistency checks)
# ---------------------------------------------------------------------------

def parse_ua(ua: str | None) -> dict[str, Any]:
    ua = ua or ""
    out: dict[str, Any] = {"raw": ua, "family": "other", "major": None, "os": "other", "headless": False, "mobile": False}
    if "HeadlessChrome" in ua or "Headless" in ua:
        out["headless"] = True
    if m := re.search(r"Edg[eA]?/(\d+)", ua):
        out["family"], out["major"] = "edge", int(m.group(1))
    elif m := re.search(r"OPR/(\d+)", ua):
        out["family"], out["major"] = "opera", int(m.group(1))
    elif m := re.search(r"(?:Headless)?Chrome/(\d+)", ua):
        out["family"], out["major"] = "chrome", int(m.group(1))
    elif m := re.search(r"Firefox/(\d+)", ua):
        out["family"], out["major"] = "firefox", int(m.group(1))
    elif "Safari/" in ua and (m := re.search(r"Version/(\d+)", ua)):
        out["family"], out["major"] = "safari", int(m.group(1))
    elif "Servo" in ua:
        out["family"] = "servo"
    if "Windows NT" in ua:
        out["os"] = "windows"
    elif "Android" in ua:
        out["os"] = "android"; out["mobile"] = True
    elif "iPhone" in ua or "iPad" in ua:
        out["os"] = "ios"; out["mobile"] = True
    elif "Mac OS X" in ua or "Macintosh" in ua:
        out["os"] = "macos"
    elif "CrOS" in ua:
        out["os"] = "chromeos"
    elif "Linux" in ua or "X11" in ua:
        out["os"] = "linux"
    if "Mobile" in ua:
        out["mobile"] = True
    return out


def tls_family_of(ua_family: str) -> str | None:
    return {"chrome": "chrome", "edge": "chrome", "opera": "chrome", "firefox": "firefox"}.get(ua_family)


def engine_of(ua_family: str) -> str | None:
    return {"chrome": "v8", "edge": "v8", "opera": "v8", "firefox": "spidermonkey", "safari": "jsc",
            "servo": "spidermonkey"}.get(ua_family)


# ---------------------------------------------------------------------------
# HTTP header comparison
# ---------------------------------------------------------------------------

def match_http(req: Any, net: dict[str, Any]) -> dict[str, Any]:
    ua = parse_ua(req.header("user-agent"))
    fam = tls_family_of(ua["family"]) or ua["family"]
    exp = known_mod.HTTP_EXPECTATIONS.get(fam)
    names = [k for k, _ in req.headers if not k.startswith(":")]
    lower = [n.lower() for n in names]
    out: dict[str, Any] = {"claimed_family": ua["family"], "reference": fam if exp else None, "differences": []}
    if not exp:
        out["reference"] = None
        return out
    is_h2 = req.version == "2"
    # Order: compare the subsequence of expected headers that are present.
    expected = [h.lower() for h in (exp["h2_order"] if is_h2 else exp["h1_order"])]
    present = [h for h in lower if h in expected]
    exp_present = [h for h in expected if h in lower]
    if present != exp_present:
        out["differences"].append({"what": "header order", "observed": present, "expected": exp_present})
    missing = [h for h in expected if h not in lower and h not in ("connection", "host", "te", "priority", "sec-fetch-user")]
    if missing:
        out["differences"].append({"what": "missing headers", "expected": missing})
    if not is_h2:
        casing = [n for n in names if n.lower() in expected]
        exp_case = {h.lower(): h for h in exp["h1_order"]}
        wrong = [f"{n} (expected {exp_case[n.lower()]})" for n in casing if exp_case[n.lower()] != n]
        if wrong:
            out["differences"].append({"what": "header casing", "observed": wrong})
    acc = req.header("accept")
    if acc and acc != exp["accept"]:
        out["differences"].append({"what": "Accept", "observed": acc, "expected": exp["accept"]})
    enc = req.header("accept-encoding")
    if enc and enc != exp["accept_encoding"]:
        out["differences"].append({"what": "Accept-Encoding", "observed": enc, "expected": exp["accept_encoding"]})
    if exp["client_hints"] and not req.header("sec-ch-ua"):
        out["differences"].append({"what": "Client Hints", "observed": None, "expected": "sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform"})
    if not exp["client_hints"] and req.header("sec-ch-ua"):
        out["differences"].append({"what": "Client Hints", "observed": req.header("sec-ch-ua"), "expected": "none (Firefox sends no Sec-CH-UA)"})
    if fam == "firefox" and is_h2 and (req.header("te") or "") != "trailers":
        out["differences"].append({"what": "te", "observed": req.header("te"), "expected": "trailers"})
    for h, v in exp["sec_fetch"].items():
        got = req.header(h)
        if got is not None and got != v:
            out["differences"].append({"what": h, "observed": got, "expected": v})
    if req.header("priority") is not None and req.header("priority") != exp["priority"]:
        out["differences"].append({"what": "priority", "observed": req.header("priority"), "expected": exp["priority"]})
    out["known"] = not out["differences"]
    return out


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(probes: dict[str, Any] | None, net: dict[str, Any], known: Any,
            probe_errors: dict[str, Any] | None = None) -> dict[str, Any]:
    f = Findings()
    probes = probes or {}
    http = net.get("http") or {}
    ua = parse_ua(http.get("user_agent"))
    identity: dict[str, Any] = {
        "claimed": {"family": ua["family"], "major": ua["major"], "os": ua["os"], "headless_ua": ua["headless"],
                    "engine": engine_of(ua["family"])},
        "tls_family": None, "h2_family": None, "http_family": None,
        "js_engine": None, "js_engine_evidence": [], "os_evidence": [],
    }
    _network_checks(f, net, ua, identity, known)
    if probes:
        _js_checks(f, probes, net, ua, identity)
    for name, err in (probe_errors or {}).items():
        f.info(f"probe_error.{name}", "probe", f"probe '{name}' threw: {err}", err)
    score = min(100, sum(WEIGHTS.get(x["severity"], 0) for x in f.items))
    verdict = "clean" if score < 10 else "suspicious" if score < 40 else "automated"
    counts = {s: sum(1 for x in f.items if x["severity"] == s) for s in ("fail", "warn", "info")}
    order = {"fail": 0, "warn": 1, "info": 2}
    f.items.sort(key=lambda x: order[x["severity"]])
    return {"score": score, "verdict": verdict, "counts": counts, "identity": identity,
            "findings": f.items, "probes_present": sorted(probes.keys())}


def _network_checks(f: Findings, net: dict[str, Any], ua: dict[str, Any], identity: dict[str, Any], known: Any) -> None:
    tls = net.get("tls")
    h2 = net.get("h2")
    http = net.get("http") or {}
    want_fam = tls_family_of(ua["family"])
    # --- TLS ------------------------------------------------------------
    if tls and tls.get("shape"):
        m = tls.get("match") or {}
        identity["tls_family"] = m.get("closest_family") if m.get("known") else None
        cands = known.family_candidates(tls["shape"]) if hasattr(known, "family_candidates") else []
        if m.get("known"):
            f.info("tls.known", "tls", f"ClientHello matches {', '.join(m.get('exact_matches') or [m.get('closest')])}",
                   {"ja3": tls["ja3"]["hash"], "ja4": tls["ja4"]["hash"]})
            if want_fam and cands and want_fam not in cands:
                f.fail("tls.family_mismatch", "tls",
                       f"UA claims {ua['family'].capitalize()} but the TLS ClientHello is a {m.get('closest')} shape",
                       {"claimed": ua["family"], "tls": m.get("exact_matches")})
            elif ua["major"] and m.get("closest_family") == want_fam:
                majors = [int(re.search(r"(\d+)", x).group(1)) for x in m.get("exact_matches", []) if re.search(r"(\d+)", x)]
                if majors and ua["major"] not in majors and want_fam == "chrome":
                    lo, hi = min(majors), max(majors)
                    f.warn("tls.major_mismatch", "tls",
                           f"UA claims Chrome {ua['major']} but the ClientHello shape is the one of Chrome {lo}{'–' + str(hi) if hi != lo else ''}",
                           {"claimed_major": ua["major"], "shape_majors": majors})
        else:
            sev = "warn" if not want_fam else "fail"
            f.add("tls.unknown", sev, "tls",
                  f"ClientHello matches no reference browser capture; closest is {m.get('closest')}: " + "; ".join(m.get("differences") or []),
                  {"ja3": tls["ja3"]["hash"], "ja4": tls["ja4"]["hash"], "differences": m.get("differences")})
        dec = tls.get("decoded") or {}
        if want_fam == "chrome" and dec.get("grease", {}).get("extensions", 0) == 0:
            f.warn("tls.no_grease", "tls", "Chrome always sends GREASE values; none seen", dec.get("grease"))
        if want_fam == "firefox" and dec.get("grease", {}).get("extensions", 0) > 0:
            f.warn("tls.grease_firefox", "tls", "Firefox never sends GREASE, but the ClientHello has GREASE values", dec.get("grease"))
        if not tls["shape"].get("alpn"):
            f.warn("tls.no_alpn", "tls", "no ALPN extension; every browser offers h2 and http/1.1")
        neg = tls.get("negotiated") or {}
        if neg.get("version") and neg["version"] != "TLSv1.3":
            f.warn("tls.not_13", "tls", f"negotiated {neg['version']}; modern browsers negotiate TLS 1.3", neg)
    elif tls and tls.get("error"):
        f.warn("tls.unparsable", "tls", tls["error"])
    elif net.get("scheme") == "https":
        f.info("tls.none", "tls", "no ClientHello captured for this connection")
    else:
        f.info("tls.plain", "tls", "plain HTTP connection: no TLS fingerprint available (use the https port)")
    # --- HTTP/2 -----------------------------------------------------------
    if net.get("http_version") == "2" and h2:
        m = h2.get("match") or {}
        identity["h2_family"] = m.get("closest_family") if m.get("known") else None
        if m.get("known"):
            f.info("h2.known", "h2", f"HTTP/2 preface matches {', '.join(m.get('exact_matches') or [])}", h2.get("akamai_fingerprint"))
            if want_fam and m.get("closest_family") != want_fam:
                f.fail("h2.family_mismatch", "h2", f"UA claims {ua['family'].capitalize()} but the HTTP/2 preface is {m.get('closest')}'s",
                       h2.get("akamai_fingerprint"))
        else:
            f.add("h2.unknown", "fail" if want_fam else "warn", "h2",
                  f"HTTP/2 preface matches no reference browser; closest {m.get('closest')}: " + "; ".join(m.get("differences") or []),
                  {"akamai": h2.get("akamai_fingerprint"), "differences": m.get("differences")})
        if (h2.get("first_headers") or {}).get("weight") and want_fam == "chrome" and h2["first_headers"].get("weight") != 256:
            f.warn("h2.priority", "h2", "Chrome sends exclusive priority weight 256 on the first stream", h2["first_headers"])
    elif tls and tls.get("shape") and "h2" in (tls["shape"].get("alpn") or []) and net.get("http_version") != "2":
        f.warn("h2.not_used", "h2", "client offered h2 in ALPN but spoke HTTP/1.1")
    elif net.get("scheme") == "https" and net.get("http_version") != "2":
        f.warn("h2.absent", "h2", "HTTP/1.1 over TLS: every current browser negotiates HTTP/2")
    # --- Headers ------------------------------------------------------------
    m = http.get("match") or {}
    if m.get("reference"):
        diffs = m.get("differences") or []
        if not diffs:
            f.info("http.known", "http", f"navigation headers match {m['reference'].capitalize()} in order, casing and values")
            identity["http_family"] = m["reference"]
        else:
            for d in diffs:
                what = d.get("what")
                sev = "fail" if what in ("Client Hints", "Accept", "header order") else "warn"
                f.add(f"http.{what.lower().replace(' ', '_')}", sev, "http",
                      f"{what} differs from {m['reference'].capitalize()}: observed {d.get('observed')!r}, expected {d.get('expected')!r}", d)
    if ua["headless"]:
        f.fail("http.headless_ua", "http", "User-Agent announces HeadlessChrome", ua["raw"])
    if ua["family"] == "servo":
        f.fail("http.servo_ua", "http", "User-Agent announces Servo", ua["raw"])
    if ua["family"] == "other" and http.get("user_agent"):
        f.warn("http.unknown_ua", "http", "User-Agent is not a mainstream browser", http.get("user_agent"))
    if not http.get("user_agent"):
        f.fail("http.no_ua", "http", "no User-Agent header")
    # Client Hints coherence
    hdr = {k.lower(): v for k, v in (http.get("headers") or [])}
    ch_ua = hdr.get("sec-ch-ua")
    if ch_ua and ua["major"]:
        vs = re.findall(r'"([^"]+)";v="(\d+)"', ch_ua)
        brand_major = {b: int(v) for b, v in vs}
        exp_brand = {"chrome": "Google Chrome", "edge": "Microsoft Edge", "opera": "Opera"}.get(ua["family"])
        if exp_brand and exp_brand not in brand_major:
            f.fail("http.ch_ua_brand", "http", f"Sec-CH-UA lacks the {exp_brand!r} brand", ch_ua)
        elif exp_brand and brand_major.get(exp_brand) != ua["major"]:
            f.fail("http.ch_ua_major", "http", f"Sec-CH-UA says {exp_brand} {brand_major.get(exp_brand)} but the UA says {ua['major']}", ch_ua)
        if "Chromium" in brand_major and brand_major["Chromium"] != ua["major"]:
            f.fail("http.ch_ua_chromium", "http", f"Sec-CH-UA Chromium {brand_major['Chromium']} but UA major {ua['major']}", ch_ua)
    plat = hdr.get("sec-ch-ua-platform")
    if plat:
        p = plat.strip('"').lower()
        exp_p = {"windows": "windows", "macos": "macos", "linux": "linux", "android": "android", "chromeos": "chrome os"}.get(ua["os"])
        if exp_p and p != exp_p:
            f.fail("http.ch_ua_platform", "http", f"Sec-CH-UA-Platform {plat} disagrees with UA OS {ua['os']}", plat)
    mob = hdr.get("sec-ch-ua-mobile")
    if mob and (mob == "?1") != ua["mobile"]:
        f.warn("http.ch_ua_mobile", "http", f"Sec-CH-UA-Mobile {mob} disagrees with UA mobility", mob)


# ---------------------------------------------------------------------------
# JS checks
# ---------------------------------------------------------------------------

def _js_checks(f: Findings, p: dict[str, Any], net: dict[str, Any], ua: dict[str, Any], identity: dict[str, Any]) -> None:  # noqa: C901
    nav = p.get("navigator") or {}
    http = net.get("http") or {}
    hdr = {k.lower(): v for k, v in (http.get("headers") or [])}
    fam = ua["family"]
    is_chromium = fam in ("chrome", "edge", "opera")

    # ---- navigator vs headers --------------------------------------------
    if nav:
        if nav.get("userAgent") and http.get("user_agent") and nav["userAgent"] != http["user_agent"]:
            f.fail("nav.ua_header_mismatch", "navigator", "navigator.userAgent differs from the User-Agent header",
                   {"js": nav["userAgent"], "header": http["user_agent"]})
        if nav.get("webdriver") is True:
            f.fail("nav.webdriver", "automation", "navigator.webdriver is true (WebDriver-controlled)")
        wd = nav.get("webdriverDescriptor") or {}
        if wd.get("onInstance"):
            f.fail("nav.webdriver_instance", "integrity", "navigator.webdriver is an own property of the instance (overridden), not a prototype getter", wd)
        if wd and not wd.get("onProto") and is_chromium:
            f.fail("nav.webdriver_missing", "integrity", "Navigator.prototype has no 'webdriver' getter; Chrome always defines it (value false)", wd)
        if wd.get("getterNative") is False:
            f.fail("nav.webdriver_getter_lie", "integrity", "the navigator.webdriver getter is not native code", wd)
        langs = nav.get("languages") or []
        al = hdr.get("accept-language")
        if al and langs:
            first = al.split(",")[0].split(";")[0].strip().lower()
            if first != str(langs[0]).lower():
                f.warn("nav.accept_language", "locale", f"Accept-Language starts with {first!r} but navigator.languages[0] is {langs[0]!r}", {"header": al, "js": langs})
        if isinstance(langs, list) and len(langs) == 0:
            f.fail("nav.languages_empty", "automation", "navigator.languages is empty (classic headless tell)")
        plat = nav.get("platform")
        exp_plat = {"windows": ["Win32"], "macos": ["MacIntel"], "linux": ["Linux x86_64", "Linux aarch64", "Linux armv8l"],
                    "android": ["Linux armv8l", "Linux aarch64", "Linux armv7l"], "ios": ["iPhone", "iPad"]}.get(ua["os"])
        if plat and exp_plat and plat not in exp_plat:
            f.fail("nav.platform_os", "navigator", f"navigator.platform {plat!r} does not match UA OS {ua['os']}", {"platform": plat, "expected": exp_plat})
        if is_chromium:
            if nav.get("vendor") != "Google Inc.":
                f.fail("nav.vendor", "navigator", f"navigator.vendor is {nav.get('vendor')!r}; Chromium reports 'Google Inc.'")
            if nav.get("productSub") != "20030107":
                f.fail("nav.productSub", "navigator", f"navigator.productSub is {nav.get('productSub')!r}; Chromium reports '20030107'")
            if "deviceMemory" not in nav or nav.get("deviceMemory") is None:
                f.fail("nav.deviceMemory_missing", "navigator", "navigator.deviceMemory missing; Chromium exposes it")
            elif nav["deviceMemory"] not in (0.25, 0.5, 1, 2, 4, 8, 16, 32, 64, 128):
                f.warn("nav.deviceMemory_value", "navigator", f"navigator.deviceMemory {nav['deviceMemory']} is not a value Chrome reports (powers of two from 0.25)")
            plugins = nav.get("plugins") or []
            if len(plugins) == 0:
                f.warn("nav.plugins_empty", "automation", "navigator.plugins is empty; desktop Chrome lists 5 PDF plugins")
            elif len(plugins) != 5 and not ua["mobile"]:
                f.info("nav.plugins_count", "navigator", f"navigator.plugins has {len(plugins)} entries; desktop Chrome has 5", [x.get("name") for x in plugins])
            if nav.get("userAgentData") is None:
                f.fail("nav.uadata_missing", "navigator", "navigator.userAgentData missing on a Chromium UA")
            else:
                uad = nav["userAgentData"]
                brands = {b.get("brand"): b.get("version") for b in uad.get("brands", [])}
                if ch_ua := hdr.get("sec-ch-ua"):
                    hdr_brands = dict(re.findall(r'"([^"]+)";v="(\d+)"', ch_ua))
                    if hdr_brands and {k: str(v) for k, v in brands.items()} != hdr_brands:
                        f.fail("nav.uadata_header", "navigator", "navigator.userAgentData.brands differs from the Sec-CH-UA header", {"js": brands, "header": hdr_brands})
                exp_pl = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "android": "Android", "chromeos": "Chrome OS"}.get(ua["os"])
                if exp_pl and uad.get("platform") != exp_pl:
                    f.fail("nav.uadata_platform", "navigator", f"userAgentData.platform {uad.get('platform')!r} vs UA OS {ua['os']}")
                he = nav.get("uaHighEntropy") or {}
                if he.get("uaFullVersion") and ua["major"] and not str(he["uaFullVersion"]).startswith(f"{ua['major']}."):
                    f.fail("nav.uadata_fullversion", "navigator", f"uaFullVersion {he['uaFullVersion']} vs UA major {ua['major']}")
                if he.get("platformVersion") is not None and ua["os"] == "windows":
                    try:
                        pv = int(str(he["platformVersion"]).split(".")[0])
                        if "Windows NT 10.0" in ua["raw"] and pv not in range(0, 40):
                            f.warn("nav.uadata_platformversion", "navigator", f"platformVersion {he['platformVersion']} unusual for Windows", he)
                    except ValueError:
                        pass
        if fam == "firefox":
            if nav.get("vendor") not in ("", None):
                f.fail("nav.vendor", "navigator", f"navigator.vendor is {nav.get('vendor')!r}; Firefox reports ''")
            if nav.get("productSub") != "20100101":
                f.fail("nav.productSub", "navigator", f"navigator.productSub {nav.get('productSub')!r}; Firefox reports '20100101'")
            if nav.get("deviceMemory") is not None:
                f.fail("nav.deviceMemory_firefox", "navigator", "navigator.deviceMemory present; Firefox has no such property")
            if nav.get("userAgentData") is not None:
                f.fail("nav.uadata_firefox", "navigator", "navigator.userAgentData present; Firefox has no Client Hints API")
            if nav.get("oscpu") is None:
                f.warn("nav.oscpu_missing", "navigator", "navigator.oscpu missing; Firefox exposes it")
            if nav.get("buildID") != "20181001000000":
                f.warn("nav.buildID", "navigator", f"navigator.buildID {nav.get('buildID')!r}; Firefox reports the frozen '20181001000000'")
        hc = nav.get("hardwareConcurrency")
        if hc is not None and (not isinstance(hc, (int, float)) or hc <= 0 or hc > 128):
            f.warn("nav.hardwareConcurrency", "navigator", f"hardwareConcurrency {hc!r} implausible")
        if nav.get("maxTouchPoints") not in (None, 0) and ua["os"] in ("windows", "macos", "linux") and not ua["mobile"]:
            if ua["os"] == "macos":
                f.warn("nav.touch_mac", "navigator", f"maxTouchPoints {nav['maxTouchPoints']} on macOS (Macs have no touch screens)")
        conn = nav.get("connection")
        if is_chromium and conn is None:
            f.warn("nav.connection_missing", "navigator", "navigator.connection missing; Chromium exposes NetworkInformation")
        if conn and conn.get("rtt") == 0 and conn.get("downlink") == 0:
            f.warn("nav.connection_zero", "automation", "navigator.connection reports rtt 0 / downlink 0 (typical of headless)")
        if fam == "firefox" and conn is not None:
            f.warn("nav.connection_firefox", "navigator", "navigator.connection present; desktop Firefox does not expose it")

    # ---- engine detection -----------------------------------------------------
    eng = p.get("engine") or {}
    ev: list[str] = []
    votes = {"v8": 0, "spidermonkey": 0, "jsc": 0}

    def vote(e: str, why: str, w: int = 1) -> None:
        votes[e] += w; ev.append(f"{why} → {e}")

    if eng:
        sf = eng.get("stackFirst") or ""
        if re.match(r"^\s*at ", sf) or sf.startswith("Error"):
            vote("v8", "Error.stack uses V8 'at ' frames", 2)
        elif "@" in sf:
            vote("spidermonkey" if not eng.get("jscLike") else "jsc", "Error.stack uses 'func@file:line' frames", 2)
        el = eng.get("evalLen")
        if el == 33:
            vote("v8", "eval.toString().length == 33")
        elif el == 37:
            vote("spidermonkey", "eval.toString().length == 37 (also JSC)")
        nts = eng.get("nativeToString") or ""
        if "\n" in nts:
            vote("spidermonkey", "native function toString is multi-line", 2)
        elif nts:
            vote("v8", "native function toString is single-line")
        esd = eng.get("errorStackDesc")
        if esd == "accessor":
            vote("spidermonkey", "Error.prototype.stack is an accessor", 2)
        elif esd == "none":
            vote("v8", "no Error.prototype.stack (V8 puts stack on instances)")
        if eng.get("v8BreakIterator"):
            vote("v8", "Intl.v8BreakIterator exists", 2)
        errs = eng.get("errors") or {}
        np_ = errs.get("nullProp") or ""
        if "Cannot read properties of null" in np_:
            vote("v8", "TypeError text 'Cannot read properties of null'", 2)
        elif "can't access property" in np_ or "null has no properties" in np_ or "is null" in np_:
            vote("spidermonkey", "TypeError text is SpiderMonkey's", 2)
        elif "null is not an object" in np_:
            vote("jsc", "TypeError text is JavaScriptCore's", 2)
        tf = errs.get("toFixed") or ""
        if "toFixed() digits argument must be between" in tf:
            vote("v8", "RangeError text for toFixed is V8's")
        elif "precision" in tf and "out of range" in tf:
            vote("spidermonkey", "RangeError text for toFixed is SpiderMonkey's")
        al_ = errs.get("arrayLen") or ""
        if al_ == "Invalid array length":
            vote("v8", "RangeError 'Invalid array length' (capital I)")
        elif al_ == "invalid array length":
            vote("spidermonkey", "RangeError 'invalid array length' (lower-case)")
        detected = max(votes, key=votes.get) if any(votes.values()) else None
        identity["js_engine"] = detected
        identity["js_engine_votes"] = votes
        identity["js_engine_evidence"] = ev
        claimed = identity["claimed"].get("engine")
        if detected and claimed and detected != claimed and votes[detected] >= 3:
            f.fail("engine.mismatch", "engine",
                   f"JavaScript engine is {detected} but the UA claims {fam.capitalize()} ({claimed})", ev)
        # layout engine tells
        css = eng.get("css") or {}
        if is_chromium and css.get("mozAppearance"):
            f.fail("engine.moz_css", "engine", "CSS '-moz-appearance' is supported; Blink does not implement it (Gecko/Stylo does)", css)
        if is_chromium and eng.get("defaultFontFamily") and eng["defaultFontFamily"] not in ('"Times New Roman"', "Times New Roman"):
            f.warn("engine.default_font", "engine", f"computed default font-family is {eng['defaultFontFamily']!r}; Chrome reports '\"Times New Roman\"'", eng.get("defaultFontFamily"))
        if fam == "firefox" and eng.get("defaultFontFamily") and eng["defaultFontFamily"] != "serif":
            f.warn("engine.default_font", "engine", f"computed default font-family is {eng['defaultFontFamily']!r}; Firefox reports 'serif'")
        if is_chromium and css.get("webkitAppRegion") is False:
            f.warn("engine.no_app_region", "engine", "CSS '-webkit-app-region' unsupported; Blink supports it", css)

    # ---- APIs (family-specific surface) -----------------------------------------
    apis = p.get("apis") or {}
    if apis:
        exp_fam = "chrome" if is_chromium else ("firefox" if fam == "firefox" else None)
        if exp_fam:
            missing = [k for k, fmly in known_mod.API_FAMILY.items() if fmly == exp_fam and apis.get(k) is False]
            foreign = [k for k, fmly in known_mod.API_FAMILY.items() if fmly != exp_fam and apis.get(k) is True]
            if missing:
                f.add("apis.missing", "fail" if len(missing) >= 3 else "warn", "apis",
                      f"{len(missing)} {exp_fam.capitalize()}-specific APIs are missing: {', '.join(missing[:8])}{'…' if len(missing) > 8 else ''}", missing)
            if exp_fam == "chrome" and apis.get("navigator.bluetooth") is not None:
                has_bt = apis["navigator.bluetooth"] is True
                if ua["os"] == "linux" and has_bt:
                    f.info("apis.bluetooth_linux", "apis", "navigator.bluetooth is present; Linux desktop Chrome does not ship Web Bluetooth by default")
                elif ua["os"] not in ("linux", "other") and not has_bt:
                    f.warn("apis.bluetooth_missing", "apis", f"navigator.bluetooth missing; Chrome on {ua['os']} exposes Web Bluetooth")
            if foreign:
                f.add("apis.foreign", "fail" if len(foreign) >= 2 else "warn", "apis",
                      f"{len(foreign)} APIs of another browser family are present: {', '.join(foreign)}", foreign)
        core_missing = [k for k in ("WebAssembly", "WebSocket", "IntersectionObserver", "ResizeObserver", "OffscreenCanvas",
                                    "BroadcastChannel", "TextEncoder", "structuredClone", "AbortController", "Intl.Segmenter",
                                    "crypto.subtle", "RTCPeerConnection", "Notification", "PerformanceObserver", "CompressionStream",
                                    "navigator.mediaDevices", "speechSynthesis", "AudioContext", "MediaSource", "WebGL2RenderingContext")
                        if apis.get(k) is False]
        if core_missing:
            f.add("apis.core_missing", "fail" if len(core_missing) >= 4 else "warn", "apis",
                  f"{len(core_missing)} APIs every current browser has are missing: {', '.join(core_missing)}", core_missing)

    # ---- screen / window ----------------------------------------------------------
    sc = p.get("screen") or {}
    if sc:
        ow, oh, iw, ih = sc.get("outerWidth"), sc.get("outerHeight"), sc.get("innerWidth"), sc.get("innerHeight")
        if ow == 0 or oh == 0:
            f.fail("screen.outer_zero", "automation", "window.outerWidth/outerHeight is 0 (headless)", {"outer": [ow, oh]})
        elif iw and ow and iw > ow:
            f.warn("screen.inner_gt_outer", "screen", "innerWidth exceeds outerWidth", {"inner": [iw, ih], "outer": [ow, oh]})
        elif ow == iw and oh == ih and not ua["mobile"]:
            f.warn("screen.outer_eq_inner", "screen", "outer size equals inner size: no browser chrome (toolbars) at all", {"inner": [iw, ih], "outer": [ow, oh]})
        if sc.get("availHeight") and sc.get("height") and sc["availHeight"] > sc["height"]:
            f.warn("screen.avail_gt_screen", "screen", "availHeight larger than height")
        if sc.get("availHeight") == sc.get("height") and sc.get("availWidth") == sc.get("width") and ua["os"] in ("windows", "macos"):
            f.warn("screen.no_taskbar", "screen", f"avail size equals screen size; {ua['os']} normally reserves a taskbar/menu bar", {"screen": [sc.get("width"), sc.get("height")], "avail": [sc.get("availWidth"), sc.get("availHeight")]})
        if ih and sc.get("height") and ih > sc["height"]:
            f.warn("screen.inner_gt_screen", "screen", "viewport taller than the screen")
        if ua["os"] == "macos" and sc.get("dpr") == 1:
            f.info("screen.mac_dpr1", "screen", "devicePixelRatio 1 on macOS (most Macs are Retina, 2x)")
        if sc.get("colorDepth") not in (24, 30, 32, None):
            f.warn("screen.colorDepth", "screen", f"colorDepth {sc.get('colorDepth')} unusual")
        med = sc.get("media") or {}
        if med.get("pointerFine") is False and not ua["mobile"]:
            f.warn("screen.no_fine_pointer", "screen", "(pointer: fine) is false on a desktop UA (no mouse?)")
        if med.get("hoverHover") is False and not ua["mobile"]:
            f.warn("screen.no_hover", "screen", "(hover: hover) is false on a desktop UA")

    # ---- timezone / locale -----------------------------------------------------------
    tz = p.get("timezone") or {}
    if tz:
        iana, off = tz.get("iana"), tz.get("offsetNow")
        if iana and off is not None:
            try:
                z = zoneinfo.ZoneInfo(iana)
                expected = -int(_dt.datetime.now(z).utcoffset().total_seconds() // 60)
                if expected != off:
                    f.fail("tz.offset_mismatch", "timezone", f"getTimezoneOffset() {off} does not match {iana} (expected {expected})", tz)
            except (zoneinfo.ZoneInfoNotFoundError, KeyError):
                f.warn("tz.unknown_zone", "timezone", f"unknown IANA zone {iana!r}")
        if not iana:
            f.warn("tz.no_intl_zone", "timezone", "Intl.DateTimeFormat().resolvedOptions().timeZone is empty")
        if tz.get("offsetJan") is not None and tz.get("offsetJan") == tz.get("offsetJul") and iana and any(
                iana.startswith(x) for x in ("Europe/", "America/New_York", "America/Los_Angeles", "America/Chicago", "America/Denver", "Australia/Sydney")):
            f.warn("tz.no_dst", "timezone", f"{iana} observes DST but January and July offsets are equal", tz)
        loc = tz.get("intlLocale")
        langs = (nav.get("languages") or [None])
        if loc and langs and langs[0] and loc.split("-")[0].lower() != str(langs[0]).split("-")[0].lower():
            f.warn("tz.intl_locale", "locale", f"Intl default locale {loc!r} vs navigator.language {langs[0]!r}")

    # ---- canvas ----------------------------------------------------------------------
    cv = p.get("canvas") or {}
    if cv:
        if cv.get("supported") is False:
            f.fail("canvas.unsupported", "canvas", "2D canvas unavailable")
        else:
            if cv.get("hash1") and cv.get("hash2") and cv["hash1"] != cv["hash2"]:
                f.fail("canvas.nondeterministic", "canvas", "two identical canvas renders hash differently: per-call noise injection", {"hash1": cv["hash1"], "hash2": cv["hash2"]})
            uni = cv.get("uniform") or {}
            if uni.get("mismatched"):
                f.fail("canvas.noise", "canvas", f"a solid fill came back with {uni['mismatched']} perturbed pixels: canvas noise injection", uni)
            if cv.get("toDataURLNative") is False or cv.get("getImageDataNative") is False:
                f.fail("canvas.hooked", "integrity", "canvas toDataURL/getImageData are not native functions", {"toDataURL": cv.get("toDataURLNative"), "getImageData": cv.get("getImageDataNative")})
            if cv.get("hash3") and cv.get("hash1") and cv["hash3"] != cv["hash1"] and cv.get("offscreenSameSize"):
                f.info("canvas.offscreen_differs", "canvas", "OffscreenCanvas renders differently from the DOM canvas (normal in Firefox; in Chrome it can mean noise is injected only on DOM canvases)", {"dom": cv["hash1"], "offscreen": cv["hash3"]})
            if cv.get("emojiTofu"):
                f.warn("canvas.emoji_tofu", "canvas", "emoji render as tofu/missing glyphs (no colour emoji font)", cv.get("emojiWidth"))
            if cv.get("textWidth") == 0:
                f.warn("canvas.no_text", "canvas", "measureText returns 0 width: text rendering broken")
            if cv.get("blank"):
                f.fail("canvas.blank", "canvas", "canvas render came back blank (all pixels identical)")

    # ---- WebGL --------------------------------------------------------------------------
    gl = p.get("webgl") or {}
    if gl:
        if gl.get("supported") is False:
            f.fail("webgl.unsupported", "webgl", "WebGL unavailable; every desktop browser has it")
        else:
            r = (gl.get("unmaskedRenderer") or gl.get("renderer") or "")
            v = (gl.get("unmaskedVendor") or gl.get("vendor") or "")
            low = r.lower()
            if any(x in low for x in ("swiftshader", "llvmpipe", "softpipe", "mesa offscreen", "software")):
                f.fail("webgl.software", "webgl", f"software renderer: {r!r} (headless / no GPU)", r)
            if ua["os"] == "windows" and r and not any(x in low for x in ("direct3d", "d3d11", "d3d9", "vulkan")):
                f.warn("webgl.renderer_os", "webgl", f"Windows UA but renderer {r!r} has no ANGLE Direct3D marker", r)
            if ua["os"] == "macos" and r and not any(x in low for x in ("apple", "metal", "amd", "intel", "radeon")):
                f.warn("webgl.renderer_os", "webgl", f"macOS UA but renderer {r!r} looks foreign", r)
            if ua["os"] == "linux" and r and "direct3d" in low:
                f.fail("webgl.renderer_os", "webgl", f"Linux UA but renderer {r!r} is Direct3D", r)
            if is_chromium and r and not low.startswith("angle") and ua["os"] != "android":
                f.warn("webgl.no_angle", "webgl", f"Chrome renderer strings start with 'ANGLE (' ; got {r!r}", r)
            if fam == "firefox" and ua["os"] == "windows" and r and not low.startswith("angle"):
                f.info("webgl.ff_no_angle", "webgl", f"Firefox on Windows also uses ANGLE; got {r!r}", r)
            if gl.get("webgl2") is False:
                f.warn("webgl.no_webgl2", "webgl", "WebGL2 unavailable")
            if gl.get("renderHash") and gl.get("renderHash2") and gl["renderHash"] != gl["renderHash2"]:
                f.fail("webgl.nondeterministic", "webgl", "two identical WebGL renders differ: noise injection")
            if gl.get("getParameterNative") is False:
                f.fail("webgl.hooked", "integrity", "WebGLRenderingContext.getParameter is not native")
            exts = gl.get("extensions") or []
            if r and len(exts) < 10:
                f.warn("webgl.few_extensions", "webgl", f"only {len(exts)} WebGL extensions; real GPUs expose 25–40", exts)
            if v and "nvidia" in low and gl.get("params", {}).get("MAX_TEXTURE_SIZE") not in (None, 16384, 32768):
                f.warn("webgl.params_gpu", "webgl", f"renderer claims NVIDIA but MAX_TEXTURE_SIZE is {gl['params'].get('MAX_TEXTURE_SIZE')} (NVIDIA: 16384/32768)", gl.get("params"))

    # ---- audio ------------------------------------------------------------------------------
    au = p.get("audio") or {}
    if au:
        if au.get("supported") is False:
            f.fail("audio.unsupported", "audio", "OfflineAudioContext unavailable")
        else:
            if au.get("hash1") and au.get("hash2") and au["hash1"] != au["hash2"]:
                f.fail("audio.nondeterministic", "audio", "two identical audio renders differ: noise injection", {"hash1": au["hash1"], "hash2": au["hash2"]})
            if au.get("silenceNonzero"):
                f.fail("audio.noise", "audio", f"rendering silence produced {au['silenceNonzero']} non-zero samples: audio noise injection")
            if au.get("getChannelDataNative") is False:
                f.fail("audio.hooked", "integrity", "AudioBuffer.getChannelData is not native")
            fp = au.get("fingerprint")
            if isinstance(fp, (int, float)) and is_chromium and not (100 < fp < 130):
                f.warn("audio.value_chrome", "audio", f"audio fingerprint {fp:.6f} is outside the Chrome range (~124.04)", fp)
            if isinstance(fp, (int, float)) and fam == "firefox" and not (30 < fp < 40):
                f.warn("audio.value_firefox", "audio", f"audio fingerprint {fp:.6f} is outside the Firefox range (~35.7)", fp)
            if au.get("sampleRate") not in (None, 44100, 48000):
                f.warn("audio.sample_rate", "audio", f"AudioContext sampleRate {au.get('sampleRate')} unusual")

    # ---- fonts -----------------------------------------------------------------------------
    fo = p.get("fonts") or {}
    if fo:
        det = set(fo.get("detected") or [])
        win = {"Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma", "Microsoft Sans Serif", "Segoe UI Emoji"}
        mac = {"Helvetica Neue", "Menlo", "Monaco", "Geneva", "Lucida Grande", "SF Pro", "Apple Color Emoji", "PingFang SC"}
        lin = {"DejaVu Sans", "Liberation Sans", "Ubuntu", "Noto Sans", "Cantarell", "Nimbus Sans", "FreeSans", "Droid Sans"}
        w, m, l = len(det & win), len(det & mac), len(det & lin)
        identity["os_evidence"].append(f"fonts: windows={w} mac={m} linux={l}")
        if ua["os"] == "windows" and w == 0 and det:
            f.fail("fonts.no_windows", "fonts", "Windows UA but none of the Windows system fonts (Segoe UI, Calibri, Consolas…) are installed", sorted(det)[:20])
        if ua["os"] == "macos" and m == 0 and det:
            f.fail("fonts.no_mac", "fonts", "macOS UA but none of the macOS system fonts (Helvetica Neue, Menlo…) are installed", sorted(det)[:20])
        if ua["os"] in ("windows", "macos") and l >= 2:
            f.fail("fonts.linux_on_desktop", "fonts", f"{ua['os']} UA but Linux fonts are installed: {', '.join(sorted(det & lin))}", sorted(det & lin))
        if fo.get("count", 0) == 0:
            f.warn("fonts.none", "fonts", "no fonts detected at all (font probing broken or bare system)")
        elif fo.get("count", 0) < 6 and not ua["mobile"]:
            f.warn("fonts.few", "fonts", f"only {fo['count']} of {fo.get('tested')} probed fonts present", sorted(det))

    # ---- automation artefacts ----------------------------------------------------------------
    am = p.get("automation") or {}
    if am:
        for g in am.get("globalsSuspicious") or []:
            f.fail(f"auto.global.{g}", "automation", f"suspicious global '{g}' present (driver / automation artefact)")
        for a in am.get("documentAttrs") or []:
            f.fail(f"auto.docattr.{a}", "automation", f"document element has automation attribute '{a}'")
        if am.get("cdpLeak"):
            f.fail("auto.cdp_runtime", "automation", "Error.stack getter was evaluated by console serialisation: a DevTools/CDP client has Runtime enabled")
        if am.get("processObj"):
            f.fail("auto.node_globals", "automation", "window.process / require / Buffer present (Electron/Node)")
        chrome = am.get("chrome") or {}
        if is_chromium:
            if not chrome.get("present"):
                f.fail("auto.no_window_chrome", "automation", "window.chrome missing on a Chrome UA")
            else:
                for k in ("app", "csi", "loadTimes"):
                    if chrome.get(k) is False:
                        f.warn(f"auto.chrome_{k}", "automation", f"window.chrome.{k} missing (present in real Chrome)")
                if chrome.get("runtime") is True:
                    f.info("auto.chrome_runtime", "automation", "window.chrome.runtime present on a plain page")
        elif chrome.get("present"):
            f.fail("auto.chrome_foreign", "automation", f"window.chrome present on a {fam.capitalize()} UA")
        n = am.get("notification") or {}
        if n.get("permission") == "denied" and n.get("queryState") == "prompt":
            f.fail("auto.notification_inconsistent", "automation", "Notification.permission 'denied' but permissions.query says 'prompt' (headless Chrome)", n)
        if am.get("errorStackMarkers"):
            f.fail("auto.stack_markers", "automation", f"stack traces mention {am['errorStackMarkers']}")
        if am.get("iframeContentWindowNative") is False:
            f.fail("auto.iframe_hooked", "integrity", "HTMLIFrameElement.contentWindow getter is not native (stealth patch)")
        if am.get("functionBindNative") is False:
            f.fail("auto.bind_hooked", "integrity", "Function.prototype.bind is not native")
        if am.get("permissionsQueryNative") is False:
            f.fail("auto.permissions_hooked", "integrity", "Permissions.query is not native")
        if am.get("hasFocus") is False:
            f.info("auto.no_focus", "automation", "document.hasFocus() is false")
        if am.get("visibilityState") == "hidden":
            f.info("auto.hidden", "automation", "document.visibilityState is 'hidden'")
        if am.get("mouseMoved") is False:
            f.info("auto.no_mouse", "automation", "no mouse movement observed during the probe run")
        if am.get("timingAnomaly"):
            if fam == "firefox":
                f.info("auto.timing", "automation", "performance.now() is clamped to 1 ms (Firefox privacy.reduceTimerPrecision default)", am["timingAnomaly"])
            else:
                f.warn("auto.timing", "automation", "performance.now() has suspiciously coarse or irregular resolution (Chrome clamps to 100 µs)", am["timingAnomaly"])

    # ---- integrity (native function checks) ---------------------------------------------------
    it = p.get("integrity") or {}
    lies = [x for x in (it.get("checks") or []) if x.get("native") is False or x.get("own") or x.get("hasPrototype") or x.get("proxy")]
    if it:
        if it.get("toStringNative") is False:
            f.fail("integrity.tostring_hooked", "integrity", "Function.prototype.toString itself is patched: everything else it says is untrustworthy")
        if lies:
            f.add("integrity.lies", "fail" if len(lies) >= 2 else "warn", "integrity",
                  f"{len(lies)} native API(s) are patched or proxied: {', '.join(x['path'] for x in lies[:8])}{'…' if len(lies) > 8 else ''}",
                  lies)
        else:
            f.info("integrity.ok", "integrity", f"all {len(it.get('checks') or [])} inspected native functions look genuine")

    # ---- worker / iframe consistency -----------------------------------------------------------
    wk = p.get("worker") or {}
    if wk:
        if wk.get("ok") is False:
            f.warn("worker.unavailable", "worker", f"dedicated Worker unavailable: {wk.get('err')}")
        else:
            mism = []
            for k in ("userAgent", "platform", "hardwareConcurrency", "deviceMemory", "language", "languages", "timezone"):
                a, b = wk.get(k), (nav.get(k) if k != "timezone" else (p.get("timezone") or {}).get("iana"))
                if a is not None and b is not None and a != b:
                    mism.append({k: {"worker": a, "main": b}})
            if mism:
                f.fail("worker.mismatch", "worker", "Worker scope reports different values than the window (spoofing not applied to workers)", mism)
            if wk.get("uaData") is not None and nav.get("userAgentData") is not None and wk["uaData"] != {"brands": nav["userAgentData"].get("brands"), "mobile": nav["userAgentData"].get("mobile"), "platform": nav["userAgentData"].get("platform")}:
                f.fail("worker.uadata_mismatch", "worker", "userAgentData differs between Worker and window", {"worker": wk["uaData"], "main": nav["userAgentData"]})
    ifr = p.get("iframe") or {}
    if ifr and ifr.get("ok"):
        mism = {k: {"iframe": ifr.get(k), "main": nav.get(k)} for k in ("userAgent", "platform", "webdriver", "hardwareConcurrency", "deviceMemory")
                if ifr.get(k) is not None and nav.get(k) is not None and ifr.get(k) != nav.get(k)}
        if mism:
            f.fail("iframe.mismatch", "iframe", "a fresh iframe's navigator differs from the top window", mism)
        if ifr.get("protoHash") and nav.get("protoHash") and ifr["protoHash"] != nav["protoHash"]:
            f.warn("iframe.proto_hash", "iframe", "Navigator.prototype property set differs between iframe and top window")
    elif ifr and ifr.get("ok") is False:
        f.warn("iframe.unavailable", "iframe", f"iframe probe failed: {ifr.get('err')}")

    # ---- permissions / media / misc -----------------------------------------------------------
    md = p.get("media") or {}
    if md:
        dv = md.get("devices") or {}
        if dv and not dv.get("err") and sum(v for v in dv.values() if isinstance(v, int)) == 0:
            f.warn("media.no_devices", "media", "enumerateDevices() lists no audio/video devices (headless / server)")
        if md.get("voices") == 0 and not ua["mobile"]:
            f.info("media.no_voices", "media", "speechSynthesis has no voices (headless Chrome / Linux without speech-dispatcher)")
        rtc = md.get("webrtc") or {}
        if rtc.get("supported") is False:
            f.warn("media.no_webrtc", "media", "RTCPeerConnection unavailable")
        cpt = md.get("canPlayType") or {}
        if cpt and is_chromium and cpt.get("h264") in ("", None):
            f.warn("media.no_h264", "media", "video/mp4 H.264 not playable; Chrome reports 'probably'")
    st = p.get("storage") or {}
    if st:
        q = st.get("quota")
        if isinstance(q, (int, float)) and 0 < q < 200 * 1024 * 1024:
            f.warn("storage.small_quota", "storage", f"storage quota {q / 1e6:.0f} MB (incognito/headless-like)", q)
        if st.get("localStorage") is False or st.get("indexedDB") is False:
            f.warn("storage.missing", "storage", "localStorage or indexedDB unavailable", st)
    tm = p.get("timing") or {}
    if tm and tm.get("perfMemory") is None and is_chromium:
        f.warn("timing.no_perf_memory", "engine", "performance.memory missing; Chrome exposes it")
    if tm and tm.get("perfMemory") and fam == "firefox":
        f.warn("timing.perf_memory_firefox", "engine", "performance.memory present; Firefox has no such property")


# ---------------------------------------------------------------------------
# Plain-text summary (for agents, `Accept: text/plain`)
# ---------------------------------------------------------------------------

def text_summary(r: dict[str, Any]) -> str:
    a = r.get("analysis") or {}
    net = r.get("network") or {}
    tls = net.get("tls") or {}
    h2 = net.get("h2") or {}
    http = net.get("http") or {}
    idn = a.get("identity") or {}
    cl = idn.get("claimed") or {}
    lines = [
        f"Dactyloscope report {r.get('id', '(whoami)')}" + (f"  tag={r['tag']}" if r.get("tag") else ""),
        f"verdict: {a.get('verdict')}  score: {a.get('score')}/100  (fail {a.get('counts', {}).get('fail', 0)}, warn {a.get('counts', {}).get('warn', 0)}, info {a.get('counts', {}).get('info', 0)})"
        + ("" if r.get("done", True) else "  [JS probes not finished]"),
        f"claimed: {cl.get('family')} {cl.get('major') or ''} on {cl.get('os')}  | js engine: {idn.get('js_engine') or '?'}  | tls: {idn.get('tls_family') or 'unknown'}  | h2: {idn.get('h2_family') or 'unknown'}  | headers: {idn.get('http_family') or 'differs'}",
        f"ua: {http.get('user_agent')}",
        f"ja3: {(tls.get('ja3') or {}).get('hash')}  ja4: {(tls.get('ja4') or {}).get('hash')}  tls match: {(tls.get('match') or {}).get('closest')} {'(exact)' if (tls.get('match') or {}).get('known') else '(differs)'}",
        f"h2: {h2.get('akamai_fingerprint')}  match: {(h2.get('match') or {}).get('closest')} {'(exact)' if (h2.get('match') or {}).get('known') else '(differs)'}",
        "",
    ]
    for sev in ("fail", "warn"):
        items = [x for x in a.get("findings", []) if x["severity"] == sev]
        if items:
            lines.append(f"{sev.upper()} ({len(items)}):")
            lines += [f"  - [{x['id']}] {x['message']}" for x in items]
    infos = [x for x in a.get("findings", []) if x["severity"] == "info"]
    if infos:
        lines.append(f"INFO ({len(infos)}):")
        lines += [f"  - [{x['id']}] {x['message']}" for x in infos[:15]]
        if len(infos) > 15:
            lines.append(f"  … {len(infos) - 15} more")
    if idn.get("js_engine_evidence"):
        lines += ["", "engine evidence:"] + [f"  - {e}" for e in idn["js_engine_evidence"]]
    return "\n".join(lines) + "\n"
