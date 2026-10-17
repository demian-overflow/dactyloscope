"""Field-by-field diff of two reports (or a report against a baseline)."""
from __future__ import annotations

import re
from typing import Any

# Keys that legitimately differ between runs and are not fingerprint material.
VOLATILE = {"id", "created", "created_ts", "done", "tag", "label", "client", "probe_ms", "probe_order",
            "connection_id", "received", "requests", "raw_len", "random_hex", "session_id_len", "dactyloscope_version",
            "elapsed", "ms", "now", "timeOrigin", "dateNow", "nowResolution", "loopMs", "usage", "frames",
            "frame_sequence", "priority_frames", "first_headers", "record_len", "client_hello_len", "trust_anchors_len",
            "decoded", "probes_present", "findings", "counts", "score", "verdict", "evidence", "js_engine_evidence",
            "os_evidence", "hash1", "hash2", "hash3", "renderHash", "renderHash2", "dataUrlLen", "fingerprint", "bodies"}


def diff_reports(a: dict[str, Any], b: dict[str, Any], name_a: str = "a", name_b: str = "b") -> dict[str, Any]:
    diffs: list[dict[str, Any]] = []
    _walk("", _normalise(a), _normalise(b), diffs)
    diffs = [d for d in diffs if not _volatile(d["path"])]
    by_section: dict[str, int] = {}
    for d in diffs:
        top = d["path"].split(".")[1] if d["path"].startswith("probes.") else d["path"].split(".")[0]
        by_section[top] = by_section.get(top, 0) + 1
    return {
        "a": {"ref": name_a, "id": a.get("id"), "ua": ((a.get("network") or {}).get("http") or {}).get("user_agent"),
              "score": (a.get("analysis") or {}).get("score"), "verdict": (a.get("analysis") or {}).get("verdict")},
        "b": {"ref": name_b, "id": b.get("id"), "ua": ((b.get("network") or {}).get("http") or {}).get("user_agent"),
              "score": (b.get("analysis") or {}).get("score"), "verdict": (b.get("analysis") or {}).get("verdict")},
        "count": len(diffs), "by_section": by_section, "differences": diffs,
        "findings_only_in_a": _finding_ids(a) - _finding_ids(b),
        "findings_only_in_b": _finding_ids(b) - _finding_ids(a),
    }


def _finding_ids(r: dict[str, Any]) -> set[str]:
    return {x["id"] for x in (r.get("analysis") or {}).get("findings", [])}


def _volatile(path: str) -> bool:
    return any(re.sub(r"\[\d+\]$", "", seg) in VOLATILE for seg in path.split("."))


# Header names whose values are per-run (query strings with tags, report ids).
_PER_RUN_HEADERS = {":path", "referer", "content-length"}


def _normalise(r: dict[str, Any]) -> dict[str, Any]:
    """Drop per-run request details so only browser-shaped differences remain."""
    net = r.get("network") or {}
    http = dict(net.get("http") or {})
    if isinstance(http.get("headers"), list):
        http["headers"] = [h for h in http["headers"] if not (isinstance(h, list) and h and str(h[0]).lower() in _PER_RUN_HEADERS)]
    for k in ("path", "query"):
        http.pop(k, None)
    return {**r, "network": {**net, "http": http}}


def _walk(path: str, a: Any, b: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in a:
                out.append({"path": p, "a": None, "b": _short(b[k]), "kind": "only_b"})
            elif k not in b:
                out.append({"path": p, "a": _short(a[k]), "b": None, "kind": "only_a"})
            else:
                _walk(p, a[k], b[k], out)
    elif isinstance(a, list) and isinstance(b, list):
        if a != b:
            if all(isinstance(x, (str, int, float, bool, type(None))) for x in a + b):
                sa, sb = set(map(str, a)), set(map(str, b))
                out.append({"path": path, "a": _short(a), "b": _short(b), "kind": "list",
                            "only_a": sorted(sa - sb)[:50], "only_b": sorted(sb - sa)[:50],
                            "order_only": sa == sb})
            elif len(a) == len(b) and all(isinstance(x, (dict, list)) for x in a + b):
                for i, (x, y) in enumerate(zip(a, b)):
                    _walk(f"{path}[{i}]", x, y, out)
            else:
                out.append({"path": path, "a": _short(a), "b": _short(b), "kind": "list"})
    else:
        if a != b and not (_num(a) and _num(b) and abs(a - b) < 1e-9):
            out.append({"path": path, "a": _short(a), "b": _short(b), "kind": "value"})


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _short(v: Any, n: int = 400) -> Any:
    if isinstance(v, str) and len(v) > n:
        return v[:n] + f"… ({len(v)} chars)"
    if isinstance(v, list) and len(v) > 60:
        return v[:60] + [f"… ({len(v)} items)"]
    if isinstance(v, dict) and len(v) > 60:
        return {k: v[k] for k in list(v)[:60]} | {"…": f"{len(v)} keys"}
    return v
