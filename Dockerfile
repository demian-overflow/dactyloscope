# Dactyloscope — browser fingerprint inspection service.
# Tiny image: Python 3.12 + openssl (self-signed CA) + the `h2` library.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY dactyloscope ./dactyloscope
# Reference ClientHello / HTTP-2 captures the analysis compares against.
COPY captures ./captures

ENV DACTYLOSCOPE_DATA=/app/data \
    DACTYLOSCOPE_CERTS=/app/data/certs \
    DACTYLOSCOPE_HOST=0.0.0.0 \
    DACTYLOSCOPE_TLS_PORT=8443 \
    DACTYLOSCOPE_PLAIN_PORT=8080
VOLUME ["/app/data"]
EXPOSE 8443 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

ENTRYPOINT ["python", "-m", "dactyloscope"]
CMD ["serve", "--san", "dactyloscope"]
