#!/usr/bin/env python3
"""Capture a browser's HTTP/2 connection preface (SETTINGS, WINDOW_UPDATE,
PRIORITY, first HEADERS pseudo-header order) behind a local TLS server.

Serves a self-signed cert for 127.0.0.1 with ALPN "h2", accepts one
connection, reads ~2 s of frames and writes them as JSON. The four values
that make up the Akamai HTTP/2 fingerprint (SETTINGS order+values, the
connection WINDOW_UPDATE increment, PRIORITY frames, pseudo-header order)
are decoded; everything else is listed by frame type only.

Usage:
    python3 tools/capture_h2_preface.py out.json [profile_dir] &
    google-chrome --headless=new --user-data-dir=/tmp/x \
        --ignore-certificate-errors https://127.0.0.1:8443/
    # Firefox: pass its profile dir as 2nd arg so the script can write a
    # cert_override.txt entry for the generated certificate, then
    firefox --headless --profile <profile_dir> https://127.0.0.1:8443/

Reference captures live in captures/.
"""
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

PORT = int(os.environ.get("DACTYLOSCOPE_CAPTURE_PORT", "8443"))
STATIC_NAMES = [None, ':authority', ':method', ':method', ':path', ':path', ':scheme', ':scheme',
 ':status', ':status', ':status', ':status', ':status', ':status', ':status', 'accept-charset',
 'accept-encoding', 'accept-language', 'accept-ranges', 'accept', 'access-control-allow-origin',
 'age', 'allow', 'authorization', 'cache-control', 'content-disposition', 'content-encoding',
 'content-language', 'content-length', 'content-location', 'content-range', 'content-type',
 'cookie', 'date', 'etag', 'expect', 'expires', 'from', 'host', 'if-match', 'if-modified-since',
 'if-none-match', 'if-range', 'if-unmodified-since', 'last-modified', 'link', 'location',
 'max-forwards', 'proxy-authenticate', 'proxy-authorization', 'range', 'referer', 'refresh',
 'retry-after', 'server', 'set-cookie', 'strict-transport-security', 'transfer-encoding',
 'user-agent', 'vary', 'via', 'www-authenticate']

def hpack_int(buf, pos, prefix):
    mask = (1 << prefix) - 1
    v = buf[pos] & mask; pos += 1
    if v < mask:
        return v, pos
    m = 0
    while True:
        b = buf[pos]; pos += 1
        v += (b & 0x7f) << m; m += 7
        if not b & 0x80:
            return v, pos

def hpack_names(block):
    """Return header names in wire order (values skipped, dynamic table tracked by name)."""
    names, dyn, pos = [], [], 0
    while pos < len(block):
        b = block[pos]
        if b & 0x80:
            idx, pos = hpack_int(block, pos, 7)
            names.append(STATIC_NAMES[idx] if idx < len(STATIC_NAMES) else dyn[idx - len(STATIC_NAMES)])
            continue
        if b & 0xc0 == 0x40:
            idx, pos = hpack_int(block, pos, 6); indexed = True
        elif b & 0xe0 == 0x20:
            _, pos = hpack_int(block, pos, 5); continue  # table size update
        else:
            idx, pos = hpack_int(block, pos, 4); indexed = False
        if idx == 0:
            n, pos = hpack_int(block, pos, 7)
            name = block[pos:pos + n]; pos += n
            name = '<huff>' if block[pos - n - 1] & 0x80 else name.decode()
        else:
            name = STATIC_NAMES[idx] if idx < len(STATIC_NAMES) else dyn[idx - len(STATIC_NAMES)]
        n, pos = hpack_int(block, pos, 7); pos += n
        names.append(name)
        if indexed:
            dyn.insert(0, name)
    return names

def main():
    out = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else None
    tmp = tempfile.mkdtemp()
    cert, key = os.path.join(tmp, 'c.pem'), os.path.join(tmp, 'k.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                    '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-days', '7'], check=True, capture_output=True)
    if profile:
        fp = subprocess.run(['openssl', 'x509', '-in', cert, '-noout', '-fingerprint', '-sha256'],
                            check=True, capture_output=True, text=True).stdout.split('=')[1].strip()
        with open(os.path.join(profile, 'cert_override.txt'), 'w') as f:
            f.write('# PSM Certificate Override Settings file\n# This is a generated file!  Do not edit.\n')
            f.write(f'127.0.0.1:{PORT}:\tOID.2.16.840.1.101.3.4.2.1\t{fp}\t\t\n')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(['h2'])
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', PORT)); srv.listen(4)
    data = b''
    # Chrome probes once, fails cert verification, closes, then reconnects
    # with the error bypassed -- so keep accepting until a preface arrives.
    for _ in range(8):
        conn, _ = srv.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            continue
        tls.settimeout(2.5)
        try:
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        if data.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'):
            break
        data = b''
    assert data.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'), data[:40]
    pos, frames = 24, []
    while pos + 9 <= len(data):
        length = int.from_bytes(data[pos:pos + 3], 'big'); ftype, flags = data[pos + 3], data[pos + 4]
        stream = struct.unpack('!I', data[pos + 5:pos + 9])[0] & 0x7fffffff
        payload = data[pos + 9:pos + 9 + length]; pos += 9 + length
        fr = {'type': {0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 4: 'SETTINGS', 8: 'WINDOW_UPDATE'}.get(ftype, ftype),
              'stream': stream, 'flags': flags, 'len': length}
        if ftype == 4 and not flags & 1:
            fr['settings'] = [[struct.unpack('!H', payload[i:i + 2])[0], struct.unpack('!I', payload[i + 2:i + 6])[0]]
                              for i in range(0, length, 6)]
        elif ftype == 8:
            fr['increment'] = struct.unpack('!I', payload)[0] & 0x7fffffff
        elif ftype == 2:
            dep = struct.unpack('!I', payload[:4])[0]
            fr.update({'exclusive': bool(dep >> 31), 'dep': dep & 0x7fffffff, 'weight': payload[4] + 1})
        elif ftype == 1:
            block, p = payload, 0
            if flags & 0x8:
                pad = block[0]; block, p = block[1:], 0; block = block[:len(block) - pad]
            if flags & 0x20:
                dep = struct.unpack('!I', block[:4])[0]
                fr.update({'exclusive': bool(dep >> 31), 'dep': dep & 0x7fffffff, 'weight': block[4] + 1})
                block = block[5:]
            try:
                fr['headers'] = hpack_names(block)
            except Exception as e:  # noqa: BLE001
                fr['headers_error'] = repr(e)
        frames.append(fr)
    settings = next((f['settings'] for f in frames if f['type'] == 'SETTINGS'), [])
    wu = next((f['increment'] for f in frames if f['type'] == 'WINDOW_UPDATE' and f['stream'] == 0), 0)
    prio = [f for f in frames if f['type'] == 'PRIORITY']
    pseudo = next((','.join(h[1] for h in f['headers'] if h.startswith(':')) for f in frames
                   if f['type'] == 'HEADERS' and 'headers' in f), '')
    akamai = '|'.join([';'.join(f'{k}:{v}' for k, v in settings), str(wu),
                       ','.join(f"{p['stream']}:{int(p['exclusive'])}:{p['dep']}:{p['weight']}" for p in prio) or '0',
                       pseudo])
    json.dump({'akamai_fingerprint': akamai, 'frames': frames}, open(out, 'w'), indent=1)
    print('captured', akamai)

if __name__ == '__main__':
    main()
