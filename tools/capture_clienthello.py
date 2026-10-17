#!/usr/bin/env python3
"""Capture and decode a browser's TLS ClientHello without root.

Listens on 127.0.0.1:8443 (override with DACTYLOSCOPE_CAPTURE_PORT), accepts one connection, parses the ClientHello
(ciphers, extension order, supported groups, signature algorithms, ALPN, key
shares, certificate compression, supported versions) and writes it as JSON.
GREASE values are collapsed to the literal "GREASE".

Usage:
    python3 tools/capture_clienthello.py out.json &
    google-chrome --headless=new --user-data-dir=/tmp/x \
        --ignore-certificate-errors https://127.0.0.1:8443/

Reference captures live in captures/. Chrome for Testing builds of any
milestone can be captured the same way (see captures/README.md). For the
HTTP/2 preface use capture_h2_preface.py.
"""
import json
import os
import socket
import struct
import sys

PORT = int(os.environ.get("DACTYLOSCOPE_CAPTURE_PORT", "8443"))

def isg(v):
    """RFC 8701 GREASE value (0x?a?a)."""
    return (v & 0x0f0f) == 0x0a0a
def parse_client_hello(data):
    # TLS record: type(1) ver(2) len(2)
    assert data[0]==0x16, "not handshake"
    hs=data[5:]
    assert hs[0]==1, "not ClientHello"
    p=4
    ver=hs[p:p+2]; p+=2
    p+=32  # random
    sidlen=hs[p]; p+=1+sidlen
    cslen=struct.unpack('!H',hs[p:p+2])[0]; p+=2
    ciphers=[struct.unpack('!H',hs[p+i:p+i+2])[0] for i in range(0,cslen,2)]; p+=cslen
    complen=hs[p]; p+=1+complen
    extlen=struct.unpack('!H',hs[p:p+2])[0]; p+=2
    end=p+extlen
    exts=[]; groups=[]; sigalgs=[]; alpn=[]; keyshare=[]; compress=[]; versions=[]; bodies={}
    while p<end:
        et=struct.unpack('!H',hs[p:p+2])[0]; el=struct.unpack('!H',hs[p+2:p+4])[0]; body=hs[p+4:p+4+el]; p+=4+el
        exts.append(et)
        if et not in (0, 51, 10, 13, 16, 43, 45, 27) and not isg(et):
            bodies[str(et)]=body.hex()
        if et==10:
            n=struct.unpack('!H',body[:2])[0]; groups=[struct.unpack('!H',body[2+i:4+i])[0] for i in range(0,n,2)]
        elif et==13:
            n=struct.unpack('!H',body[:2])[0]; sigalgs=[struct.unpack('!H',body[2+i:4+i])[0] for i in range(0,n,2)]
        elif et==16:
            q=2
            while q<len(body):
                l=body[q]; alpn.append(body[q+1:q+1+l].decode()); q+=1+l
        elif et==51:
            n=struct.unpack('!H',body[:2])[0]; q=2
            while q<2+n:
                g=struct.unpack('!H',body[q:q+2])[0]; l=struct.unpack('!H',body[q+2:q+4])[0]; keyshare.append((g,l)); q+=4+l
        elif et==27:
            n=body[0]; compress=[struct.unpack('!H',body[1+i:3+i])[0] for i in range(0,n,2)]
        elif et==43:
            n=body[0]; versions=[struct.unpack('!H',body[1+i:3+i])[0] for i in range(0,n,2)]
    return dict(
        ciphers=[hex(c) for c in ciphers if not isg(c)],
        extensions=[e if not isg(e) else 'GREASE' for e in exts],
        groups=[hex(g) if not isg(g) else 'GREASE' for g in groups],
        sigalgs=[hex(s) for s in sigalgs],
        alpn=alpn,
        keyshare=[(hex(g) if not isg(g) else 'GREASE', l) for g,l in keyshare],
        compress_cert=[hex(c) for c in compress],
        supported_versions=[hex(v) for v in versions if not isg(v)],
        extension_bodies_hex=bodies,
        client_hello_len=len(data),
    )
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',PORT)); s.listen(5); s.settimeout(40)
results=[]
try:
    while len(results)<1:
        c,_=s.accept(); c.settimeout(5)
        buf=b''
        try:
            while len(buf)<5 or len(buf)<5+struct.unpack('!H',buf[3:5])[0]:
                chunk=c.recv(65536)
                if not chunk: break
                buf+=chunk
        except Exception as e: pass
        c.close()
        if buf[:1]==b'\x16':
            results.append(parse_client_hello(buf))
except socket.timeout:
    pass
json.dump(results, open(sys.argv[1],'w'), indent=1)
print("captured", len(results))
