#!/usr/bin/env python3
"""Record raw ClientHello and HTTP/2 preface bytes for the test fixtures.

Listens on 127.0.0.1 (DACTYLOSCOPE_CAPTURE_PORT, default 8443), accepts one
connection and writes two files:

* ``<name>.clienthello.bin``: the first TLS record exactly as it arrived;
* ``<name>.h2.bin``: the decrypted client bytes of the first ~2 s after the
  handshake (the HTTP/2 preface when the client picked h2 via ALPN).

Usage: see README.md next to this file.
"""
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

PORT = int(os.environ.get("DACTYLOSCOPE_CAPTURE_PORT", "8443"))


def main() -> None:
    out = sys.argv[1]
    tmp = tempfile.mkdtemp()
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=fixture.test",
                    "-addext", "subjectAltName=DNS:fixture.test,IP:127.0.0.1"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", PORT))
    ls.listen(1)
    ls.settimeout(60)
    while True:  # browsers may open a speculative connection and drop it
        sock, _ = ls.accept()
        sock.settimeout(5)
        raw = b""
        while True:
            raw = sock.recv(65536, socket.MSG_PEEK)
            if not raw or len(raw) >= 5 and len(raw) >= 5 + struct.unpack("!H", raw[3:5])[0]:
                break
            time.sleep(0.05)
        try:
            tls_sock = ctx.wrap_socket(sock, server_side=True)
            break
        except (ssl.SSLError, OSError):
            continue
    with open(out + ".clienthello.bin", "wb") as f:
        f.write(raw[:5 + struct.unpack("!H", raw[3:5])[0]])
    tls_sock.settimeout(0.5)
    data, deadline = b"", time.time() + 2
    if tls_sock.selected_alpn_protocol() == "h2":
        # An empty SETTINGS frame so the client does not stall before HEADERS.
        tls_sock.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
    while time.time() < deadline:
        try:
            chunk = tls_sock.recv(65536)
        except (socket.timeout, ssl.SSLError):
            continue
        if not chunk:
            break
        data += chunk
    with open(out + ".h2.bin", "wb") as f:
        f.write(data)
    print(f"{out}: alpn={tls_sock.selected_alpn_protocol()} clienthello={len(raw)} h2={len(data)}")


if __name__ == "__main__":
    main()
