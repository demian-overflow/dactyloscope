"""Self-signed CA + leaf certificate for the TLS listener (via the openssl CLI).

The CA certificate is served at ``/ca.pem`` so a client can trust it. For
BoringSSL-based clients set ``SSL_CERT_FILE=<path to ca.pem>`` — BoringSSL honours that
environment variable in ``set_default_verify_paths``.
"""
from __future__ import annotations

import socket
import subprocess
from pathlib import Path


def ensure_certs(cert_dir: Path, extra_hosts: list[str] | None = None) -> tuple[Path, Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key, ca_pem = cert_dir / "ca.key", cert_dir / "ca.pem"
    key, pem = cert_dir / "server.key", cert_dir / "server.pem"
    if ca_pem.is_file() and pem.is_file() and key.is_file():
        return ca_pem, pem, key
    hosts = {"localhost", "dactyloscope", "dactyloscope.local", "host.docker.internal"}
    try:
        hosts.add(socket.gethostname())
    except OSError:
        pass
    hosts.update(extra_hosts or [])
    ips = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except OSError:
        pass
    for h in list(hosts):
        if _looks_like_ip(h):
            hosts.discard(h); ips.add(h)
    san = ",".join([f"DNS:{h}" for h in sorted(hosts)] + [f"IP:{i}" for i in sorted(ips)])
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)  # noqa: E731
    if not ca_pem.is_file():
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_pem), "-days", "3650",
            "-subj", "/CN=Dactyloscope Local CA/O=Dactyloscope",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    csr = cert_dir / "server.csr"
    ext = cert_dir / "server.ext"
    ext.write_text(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", "/CN=Dactyloscope/O=Dactyloscope")
    run("x509", "-req", "-in", str(csr), "-CA", str(ca_pem), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(pem), "-days", "825", "-extfile", str(ext))
    csr.unlink(missing_ok=True); ext.unlink(missing_ok=True)
    return ca_pem, pem, key


def _looks_like_ip(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in s else socket.AF_INET, s)
        return True
    except OSError:
        return False


def firefox_profile(profile_dir: Path, pem: Path, hosts: list[str] | None = None, port: int = 8443) -> Path:
    """Create/refresh a Firefox profile that trusts the Dactyloscope leaf certificate.

    Firefox does not honour SSL_CERT_FILE; the portable trick is a
    ``cert_override.txt`` pinning the leaf certificate's SHA-256 fingerprint
    for each host:port. Also writes a ``user.js`` that keeps a headless run
    quiet (no first-run tabs, no telemetry chatter).
    """
    profile_dir.mkdir(parents=True, exist_ok=True)
    fp = subprocess.run(["openssl", "x509", "-in", str(pem), "-noout", "-fingerprint", "-sha256"],
                        check=True, capture_output=True, text=True).stdout.split("=", 1)[1].strip()
    hosts = hosts or ["127.0.0.1", "localhost"]
    lines = ["# PSM Certificate Override Settings file", "# This is a generated file!  Do not edit."]
    for h in hosts:
        lines.append(f"{h}:{port}:\tOID.2.16.840.1.101.3.4.2.1\t{fp}\t\t")
    (profile_dir / "cert_override.txt").write_text("\n".join(lines) + "\n")
    (profile_dir / "user.js").write_text("\n".join([
        'user_pref("browser.shell.checkDefaultBrowser", false);',
        'user_pref("browser.startup.homepage_override.mstone", "ignore");',
        'user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);',
        'user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);',
        'user_pref("browser.aboutwelcome.enabled", false);',
    ]) + "\n")
    return profile_dir
