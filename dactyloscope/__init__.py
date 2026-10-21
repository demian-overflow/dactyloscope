"""Dactyloscope — a fingerprint inspection service.

Point any browser at it and reports everything a
bot-detection or anti-fraud vendor could see: the TLS ClientHello (JA3/JA4
and the decoded shape), the HTTP/2 preface (Akamai fingerprint), HTTP header
order and values, and a large battery of in-page JavaScript probes (canvas,
WebGL, audio, fonts, engine tells, automation artefacts, API integrity).

Findings are produced server-side, but nothing is stored: the probe page posts
its results to `/analyze` and renders the report it gets back. Agents read the
same report out of the page over WebDriver (`python -m dactyloscope check`).
"""

__version__ = "0.1.0"
