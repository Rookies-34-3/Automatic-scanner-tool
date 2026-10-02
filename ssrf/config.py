import os


# ==============================
# Scanner
# ==============================

TIMEOUT = 10


# ==============================
# OpenAI
# ==============================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ==============================
# SSRF Verifier
# ==============================

# 대상 웹 서버가 Docker 내부에서 접근할 검증 URL
VERIFIER_PAYLOAD_URL = os.getenv(
    "SSRF_VERIFIER_PAYLOAD_URL",
    "http://ssrf-verifier:9001/check"
)

# Scanner PC가 외부에서 조회할 검증 결과 URL
VERIFIER_STATUS_URL = os.getenv(
    "SSRF_VERIFIER_STATUS_URL",
    "http://13.125.233.51/ssrf-verify/status"
)

VERIFIER_TIMEOUT = 5
