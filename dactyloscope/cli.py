#!/usr/bin/env python3
"""Dactyloscope command line.

  python -m dactyloscope serve  [--host 0.0.0.0] [--tls-port 8443] [--plain-port 8080] [--certs DIR]
  python -m dactyloscope check  --webdriver http://127.0.0.1:7000 [--server https://127.0.0.1:8443] [--label ci] [--fail-on warn|fail] [--json]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

DATA = Path.cwd() / "data"

from dactyloscope import __version__  # noqa: E402


def cmd_serve(a: argparse.Namespace) -> int:
    from dactyloscope import certs, server
    from dactyloscope.known import KnownShapes

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("hpack", "h2", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    log = logging.getLogger("dactyloscope")
    if a.tls_cert and a.tls_key:
        # A publicly trusted certificate (e.g. Let's Encrypt); /ca.pem then serves its chain.
        pem, key = Path(a.tls_cert), Path(a.tls_key)
        ca_pem = pem
    else:
        ca_pem, pem, key = certs.ensure_certs(Path(a.certs), a.san)
    known = KnownShapes().load([Path(d) for d in a.captures] if a.captures else None)
    log.info("loaded %d TLS and %d HTTP/2 reference captures", len(known.tls), len(known.h2))
    host_for_url = "127.0.0.1" if a.host in ("0.0.0.0", "::", "") else a.host
    app = server.App(known, ca_pem, public=a.public)
    ctx = server.make_ssl_context(pem, key)
    log.info("Dactyloscope %s — probe page https://%s:%d/  plain %s  CA %s", __version__, host_for_url, a.tls_port,
             f"http://{host_for_url}:{a.plain_port}" if a.plain_port else None, ca_pem)
    log.info("trust hint for BoringSSL/OpenSSL clients: SSL_CERT_FILE=%s", ca_pem)
    try:
        asyncio.run(server.serve(app, a.host, a.tls_port, a.plain_port, ctx))
    except KeyboardInterrupt:
        pass
    return 0


def _print_report(r: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(r, indent=1))
        return
    from dactyloscope.analysis import text_summary
    print(text_summary(r), end="")


def cmd_check(a: argparse.Namespace) -> int:
    from dactyloscope.webdriver import run_probe

    caps = json.loads(a.capabilities) if a.capabilities else None
    r = run_probe(a.webdriver, a.server.rstrip("/"), a.label, wait=a.wait, capabilities=caps, keep_session=a.keep_session)
    _print_report(r, a.json)
    counts = (r.get("analysis") or {}).get("counts") or {}
    if not r.get("done"):
        print("error: report did not finish in time", file=sys.stderr)
        return 3
    if a.fail_on == "fail" and counts.get("fail"):
        return 1
    if a.fail_on == "warn" and (counts.get("fail") or counts.get("warn")):
        return 1
    return 0


def cmd_firefox_profile(a: argparse.Namespace) -> int:
    from dactyloscope.certs import firefox_profile
    pem = Path(a.certs) / "server.pem"
    if not pem.is_file():
        print(f"no certificate at {pem}; start `python -m dactyloscope serve` once first", file=sys.stderr)
        return 2
    d = firefox_profile(Path(a.dir), pem, a.host or None, a.port)
    print(f"Firefox profile ready: {d}\n  firefox --headless --profile {d} https://127.0.0.1:{a.port}/")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dactyloscope", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the Dactyloscope server")
    s.add_argument("--host", default=os.environ.get("DACTYLOSCOPE_HOST", "0.0.0.0"))
    s.add_argument("--tls-port", type=int, default=int(os.environ.get("DACTYLOSCOPE_TLS_PORT", "8443")))
    s.add_argument("--plain-port", type=int, default=int(os.environ.get("DACTYLOSCOPE_PLAIN_PORT", "8080")), help="0 disables the plain listener")
    s.add_argument("--certs", default=os.environ.get("DACTYLOSCOPE_CERTS", str(DATA / "certs")))
    s.add_argument("--tls-cert", default=os.environ.get("DACTYLOSCOPE_TLS_CERT"), help="PEM certificate chain to serve instead of the self-signed one")
    s.add_argument("--tls-key", default=os.environ.get("DACTYLOSCOPE_TLS_KEY"), help="private key for --tls-cert")
    s.add_argument("--captures", action="append", help="directory with captures/-style reference captures (repeatable)")
    s.add_argument("--san", action="append", help="extra hostname/IP for the certificate (repeatable)")
    s.add_argument("--public", action="store_true", default=os.environ.get("DACTYLOSCOPE_PUBLIC") == "1",
                   help="Internet-facing mode: the client IP is left out of the report")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_serve)

    c = sub.add_parser("check", help="run the probe page in a WebDriver browser and print the report")
    c.add_argument("--webdriver", default=os.environ.get("DACTYLOSCOPE_WEBDRIVER", "http://127.0.0.1:7000"))
    c.add_argument("--server", default=os.environ.get("DACTYLOSCOPE_URL", "https://127.0.0.1:8443"), help="Dactyloscope URL as the browser reaches it")
    c.add_argument("--label", help="label shown at the top of the report")
    c.add_argument("--wait", type=float, default=120, help="seconds to wait for the probes")
    c.add_argument("--capabilities", help="JSON capabilities for the WebDriver session (e.g. browser-specific options)")
    c.add_argument("--keep-session", action="store_true")
    c.add_argument("--fail-on", choices=["none", "warn", "fail"], default="none", help="exit 1 when findings at this level exist")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_check)

    fp = sub.add_parser("firefox-profile", help="write a Firefox profile that trusts the Dactyloscope certificate (cert_override.txt)")
    fp.add_argument("dir")
    fp.add_argument("--certs", default=os.environ.get("DACTYLOSCOPE_CERTS", str(DATA / "certs")))
    fp.add_argument("--host", action="append", help="host to pin (repeatable; default 127.0.0.1 and localhost)")
    fp.add_argument("--port", type=int, default=int(os.environ.get("DACTYLOSCOPE_TLS_PORT", "8443")))
    fp.set_defaults(fn=cmd_firefox_profile)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
