"""Reference fingerprints of real browsers.

Two sources:

* ``captures/*.json`` — decoded ClientHello / HTTP/2 preface captures made
  with the tools in ``tools/``. Loaded at start-up so that a
  report can say "matches Chrome 152 stable" or list the exact deviations.
* Embedded HTTP header expectations (navigation request) for the two browser
  major browser families. These are transcribed from real captures on
  2026-09-04 and are the values a detector compares against.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import tls

_HERE = Path(__file__).resolve()
DEFAULT_CAPTURE_DIRS = [
    _HERE.parents[1] / "captures",      # <repo>/captures (checkout and Docker image)
]

_NAME_RE = re.compile(r"^(chrome|firefox|edge|safari)-(\d+)(?:-(.+?))?-(clienthello|h2-preface)\.json$")


class KnownShapes:
    def __init__(self) -> None:
        self.tls: list[dict[str, Any]] = []
        self.h2: list[dict[str, Any]] = []

    def load(self, dirs: list[Path] | None = None) -> "KnownShapes":
        for d in dirs or DEFAULT_CAPTURE_DIRS:
            if not d.is_dir():
                continue
            for f in sorted(d.glob("*.json")):
                m = _NAME_RE.match(f.name)
                if not m:
                    continue
                family, major, variant, kind = m.group(1), int(m.group(2)), m.group(3) or "", m.group(4)
                try:
                    data = json.loads(f.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                entry = {"file": f.name, "family": family, "major": major, "variant": variant,
                         "label": f"{family.capitalize()} {major}" + (f" ({variant})" if variant else ""),
                         "meta": data.get("_meta", {})}
                if kind == "clienthello":
                    ch = tls.from_capture(data)
                    entry.update(shape=tls.shape(ch), ja3=tls.ja3(ch), ja4=tls.ja4(ch))
                    entry["shape"]["client_hello_len"] = data.get("client_hello_len")
                    # Chrome permutes extension order per connection (permute_extensions).
                    if family == "chrome" or "permute" in str(entry["meta"].get("note", "")):
                        entry["shape"]["extension_order"] = "random"
                    self.tls.append(entry)
                else:
                    entry.update(akamai=data.get("akamai_fingerprint"), frames=data.get("frames", []))
                    self.h2.append(entry)
        return self

    # ---- TLS ---------------------------------------------------------
    def match_tls(self, observed_shape: dict[str, Any]) -> dict[str, Any]:
        """Best reference for an observed shape, plus the diff against it."""
        best: dict[str, Any] | None = None
        best_diffs: list[str] = []
        for ref in self.tls:
            diffs = tls.compare_shapes(observed_shape, ref["shape"])
            if best is None or len(diffs) < len(best_diffs) or (
                    len(diffs) == len(best_diffs) and ref["major"] > best["major"]):
                best, best_diffs = ref, diffs
        if best is None:
            return {"known": False, "reason": "no reference captures loaded"}
        exact = [r["label"] for r in self.tls if not tls.compare_shapes(observed_shape, r["shape"])]
        return {
            "known": not best_diffs,
            "closest": best["label"],
            "closest_family": best["family"],
            "closest_major": best["major"],
            "exact_matches": exact,
            "differences": best_diffs,
        }

    def family_candidates(self, observed_shape: dict[str, Any]) -> list[str]:
        return sorted({r["family"] for r in self.tls if not tls.compare_shapes(observed_shape, r["shape"])})

    # ---- HTTP/2 -------------------------------------------------------
    def match_h2(self, akamai: str | None) -> dict[str, Any]:
        if not akamai:
            return {"known": False, "reason": "no HTTP/2"}
        exact = [r["label"] for r in self.h2 if r.get("akamai") == akamai]
        if exact:
            return {"known": True, "exact_matches": exact, "closest": exact[0],
                    "closest_family": next(r["family"] for r in self.h2 if r["label"] == exact[0]),
                    "differences": []}
        # Closest by component.
        parts = akamai.split("|")
        best, best_score, best_diff = None, -1, []
        for r in self.h2:
            rp = (r.get("akamai") or "").split("|")
            names = ["SETTINGS", "WINDOW_UPDATE", "PRIORITY", "pseudo-header order"]
            score = sum(1 for a, b in zip(parts, rp) if a == b)
            diff = [f"{n}: {a} vs {b}" for n, a, b in zip(names, parts, rp) if a != b]
            if score > best_score:
                best, best_score, best_diff = r, score, diff
        if best is None:
            return {"known": False, "reason": "no reference captures loaded"}
        return {"known": False, "exact_matches": [], "closest": best["label"],
                "closest_family": best["family"], "differences": best_diff}

    def as_json(self) -> dict[str, Any]:
        return {
            "tls": [{k: v for k, v in r.items() if k != "shape"} | {"shape": r["shape"]} for r in self.tls],
            "h2": [{"label": r["label"], "family": r["family"], "major": r["major"],
                    "akamai": r["akamai"], "meta": r["meta"]} for r in self.h2],
            "http": HTTP_EXPECTATIONS,
        }


# ---------------------------------------------------------------------------
# HTTP header expectations for a top-level navigation (Accept: text/html).
# ---------------------------------------------------------------------------

HTTP_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "chrome": {
        "source": "Google Chrome 152 stable, linux, 2026-09-04 (HTTP/2 and HTTP/1.1 navigation)",
        # HTTP/2 lowercased header order after the pseudo-headers.
        "h2_order": ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
                     "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
                     "sec-fetch-dest", "accept-encoding", "accept-language", "priority"],
        # HTTP/1.1 order with the casing Chrome uses on the wire.
        "h1_order": ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                     "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                     "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept_encoding": "gzip, deflate, br, zstd",
        "pseudo_order": "m,a,s,p",
        "priority": "u=0, i",
        "client_hints": True,
        "sec_fetch": {"sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1",
                      "sec-fetch-dest": "document"},
        "subresource": {
            "script": {"accept": "*/*", "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors"},
            "fetch": {"accept": "*/*", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors"},
            "style": {"accept": "text/css,*/*;q=0.1", "sec-fetch-dest": "style"},
        },
    },
    "firefox": {
        "source": "Firefox 154, linux, 2026-09-04 (HTTP/2 and HTTP/1.1 navigation)",
        "h2_order": ["user-agent", "accept", "accept-language", "accept-encoding",
                     "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
                     "sec-fetch-user", "priority", "te"],
        "h1_order": ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection",
                     "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
                     "Sec-Fetch-User", "Priority"],
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",  # Firefox 154 (image/* types were dropped from the navigation Accept)
        "accept_encoding": "gzip, deflate, br, zstd",
        "pseudo_order": "m,p,a,s",
        "priority": "u=0, i",
        "client_hints": False,
        "te": "trailers",
        "sec_fetch": {"sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1",
                      "sec-fetch-dest": "document"},
        "subresource": {
            "script": {"accept": "*/*", "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors"},
            "fetch": {"accept": "*/*", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors"},
            "style": {"accept": "text/css,*/*;q=0.1", "sec-fetch-dest": "style"},
        },
    },
}

# Chrome-only / Firefox-only JavaScript surface. Each entry is a probe key from
# static/probe.js ("apis" section) mapped to the family that has it.
# navigator.bluetooth is Chrome-only but not shipped on Linux desktop, so it is
# checked separately (see analysis) rather than listed here. Firefox 154 ships
# navigator.serial, trustedTypes and documentPictureInPicture, and no longer
# exposes style.MozAppearance — verified against real Firefox 154, so those
# are deliberately absent.
API_FAMILY: dict[str, str] = {
    "window.chrome": "chrome",
    "navigator.userAgentData": "chrome",
    "navigator.deviceMemory": "chrome",
    "navigator.usb": "chrome",
    "navigator.hid": "chrome",
    "navigator.keyboard": "chrome",
    "navigator.scheduling": "chrome",
    "navigator.getBattery": "chrome",
    "window.showOpenFilePicker": "chrome",
    "window.webkitRequestFileSystem": "chrome",
    "window.PeriodicSyncManager": "chrome",
    "document.featurePolicy": "chrome",
    "Intl.v8BreakIterator": "chrome",
    "performance.memory": "chrome",
    "window.launchQueue": "chrome",
    "css.-webkit-app-region": "chrome",
    "navigator.oscpu": "firefox",
    "navigator.buildID": "firefox",
    "window.mozInnerScreenX": "firefox",
    "window.netscape": "firefox",
    "window.dump": "firefox",
    "css.-moz-appearance": "firefox",
    "Error.prototype.stack accessor": "firefox",
}
