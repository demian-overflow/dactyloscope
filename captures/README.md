# TLS / HTTP-2 reference captures

Decoded ClientHellos and HTTP/2 prefaces of real browsers, captured with the
two tools in `tools/`. Dactyloscope loads them at start-up and compares every
incoming connection against them.

| File | Browser | What it pins down |
|------|---------|-------------------|
| `chrome-152-clienthello.json` | Google Chrome 152 stable (2026-09-03) | first evidence that 152 differs from the 147 shape |
| `chrome-152-stable-clienthello.json` | Google Chrome 152.0.7977.64 stable | same, with extension bodies — source of `CHROME_TRUST_ANCHORS_LIST` |
| `chrome-145..151-clienthello.json` | Chrome for Testing 145–151 (latest patch of each) | which major introduced which extra (see table below) |
| `firefox-154-clienthello.json` | Firefox 154 | the whole Firefox family shape |
| `chrome-152-h2-preface.json`, `firefox-154-h2-preface.json` | same browsers | HTTP/2 SETTINGS / WINDOW_UPDATE / pseudo-header order |

## Chrome ClientHello by major (all else equal)

| major | `trust_anchors` (51764) | ML-DSA sigalgs `0x0904–0x0906` | GREASE sigalg | extra |
|-------|------|------|------|------|
| ≤ 144 (assumed; older decrypted 147 capture) | – | – | – | – |
| 145 – 149 (current patch builds) | ✓ | – | – | – |
| 150 | ✓ | ✓ | – | – |
| 151 | ✓ | ✓ | – | empty extension 4832 (0x12e0) |
| 152 | ✓ | ✓ | ✓ | – |

Ciphers, supported groups (`GREASE, X25519MLKEM768, X25519, P-256, P-384`),
key shares (`GREASE, X25519MLKEM768, X25519`), ALPN, ALPS codepoint 17613,
brotli certificate compression and ECH GREASE are identical across 145–152.
An earlier decrypted capture of a real Chrome 147 (2026-05) had no
`trust_anchors`; the latest 145 and 147 patch builds do, so the extension was
turned on by a later patch / component and every major ≥ 145 is treated as
sending it.

The `trust_anchors` body is the Chrome Root Store's trust-anchor-ID list. It
is delivered by the root-store *component*, so a fresh Chrome for Testing
profile sends an empty list (`00 00`) while a long-lived stable install sends
the full list. A real user's Chrome sends the full list, so refresh it from a
new stable capture when the root store changes.

## Re-capturing

```bash
# Both tools listen on 127.0.0.1:8443; set DACTYLOSCOPE_CAPTURE_PORT to move them.
# ClientHello (one connection, no root needed)
python3 tools/capture_clienthello.py out.json &
google-chrome --headless=new --user-data-dir=/tmp/x --ignore-certificate-errors https://127.0.0.1:8443/
# any milestone: download Chrome for Testing from
# https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json
# Firefox (snap): the profile dir must be somewhere the snap can see
firefox --headless --profile "$PWD/ffcap" https://127.0.0.1:8443/

# HTTP/2 preface (self-signed cert; Firefox needs the profile dir so the tool
# can drop a cert_override.txt for it)
python3 tools/capture_h2_preface.py out.json [firefox-profile-dir] &
```

Name new files `<browser>-<major>[-<variant>]-{clienthello,h2-preface}.json`
and they are picked up automatically. Expected differences between two captures
of the same browser: Chrome permutes extension order per connection (compare
as a set), GREASE values differ, the ECH GREASE payload length is random, and
the `trust_anchors` body depends on the root-store component (see above).
