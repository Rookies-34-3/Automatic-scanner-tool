import os


# ==============================
# Target Web Server
# ==============================

TARGET_URL = "http://13.125.233.51"


# ==============================
# Login
# ==============================

LOGIN_ENDPOINT = "/login"

USERNAME = os.getenv("SSrf_USERNAME")
PASSWORD = os.getenv("SSrf_PASSWORD")


# ==============================
# SSRF Endpoint
# ==============================

ENDPOINT = "/pre-course/write"

METHOD = "POST"

PARAMETER = "url"

ACTION_PARAMETER = "action"

ACTION_VALUE = "preview"

TITLE_PARAMETER = "title"

TITLE_VALUE = "SSRF Scanner Test"


# ==============================
# Test URLs
# ==============================

EXTERNAL_URL = "https://example.com"

INTERNAL_TEST_URL = "http://internal-service:9000/health"


# ==============================
# Request
# ==============================

TIMEOUT = 10


# ==============================
# OpenAI
# ==============================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")