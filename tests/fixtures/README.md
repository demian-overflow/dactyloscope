# Test fixtures

Raw client bytes recorded with `record.py` on 2026-10-21. They are what the
server sees on the wire, so the tests exercise the same parsing path as a live
connection.

| File | Client | Contents |
|------|--------|----------|
| `chromium-141.clienthello.bin` | Chromium 141.0.7390.37 (Playwright build), `--headless=new` | first TLS record |
| `chromium-141.h2.bin` | same connection | decrypted client bytes: HTTP/2 preface, SETTINGS, WINDOW_UPDATE, HEADERS |
| `curl.clienthello.bin` | curl 8.5.0 / OpenSSL 3.0.13, `--http2` | first TLS record |
| `curl.h2.bin` | same connection | decrypted HTTP/2 preface and request |

Both clients connected to `fixture.test`, so the ClientHellos carry an SNI.
This Chromium build sends no ECH GREASE extension and an extra reserved
HTTP/2 setting (60058), which is why it matches no reference capture.

Reference browsers (Chrome 152, Firefox 154) have no raw recording; the tests
re-encode their `captures/*.json` shapes as bytes with `tests/wire.py`.

## Re-recording

```bash
export DACTYLOSCOPE_CAPTURE_PORT=18443
python3 tests/fixtures/record.py tests/fixtures/chromium-141 &
chrome --headless=new --no-proxy-server --ignore-certificate-errors \
    --user-data-dir="$(mktemp -d)" \
    --host-resolver-rules="MAP fixture.test 127.0.0.1" https://fixture.test:18443/
python3 tests/fixtures/record.py tests/fixtures/curl &
curl -sk --noproxy '*' --http2 --resolve fixture.test:18443:127.0.0.1 https://fixture.test:18443/
```

Values asserted in the tests (JA3/JA4 hashes, Akamai strings) change with a
new recording and have to be updated with it.
