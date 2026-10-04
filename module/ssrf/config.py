"""SSRF 검사 기본값."""

import os


TIMEOUT = float(os.getenv("SSRF_TIMEOUT", "5"))
PROBE_URL = os.getenv(
    "SSRF_PROBE_URL",
    "http://internal-service:9000/course",
)
EXPECTED_MARKERS = tuple(
    marker.strip()
    for marker in os.getenv(
        "SSRF_EXPECTED_MARKERS",
        "SSRF SUCCESS - internal-service reached|internal-service:9000 reached",
    ).split("|")
    if marker.strip()
)
