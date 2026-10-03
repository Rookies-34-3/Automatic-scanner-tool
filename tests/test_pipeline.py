"""파이프라인 어댑터 단위 테스트 (네트워크 불필요).

공통 출력 스키마(finding-output.schema.json) 준수와 설정 변환을 검증한다.
실행: python -m pytest tests/
"""
from fileio_scanner.pipeline import to_common, to_common_skip, resolve_config, RESULT_MAP

REQUIRED_KEYS = {"scanner_id", "name", "url", "method", "parameters",
                 "result", "severity", "reason", "details"}
RESULT_ENUM = {"VULNERABLE", "PASS", "REVIEW", "ERROR"}


def _sample_finding():
    return {
        "scan_id": "SCAN-001",
        "category": "IDOR - Enumeration (Download)",
        "target_url": "http://127.0.0.1:8080/download/{id}",
        "method": "GET",
        "parameter": "id",
        "payload": "1..200",
        "status_code": 200,
        "result": "POTENTIAL",
        "severity": "MEDIUM",
        "evidence": "순차 ID 열거 - 구조적 약점",
        "details": {"accessible_count": 98},
    }


def test_to_common_has_exact_keys():
    out = to_common(_sample_finding())
    assert set(out.keys()) == REQUIRED_KEYS


def test_to_common_result_in_enum():
    for internal in ("VULNERABLE", "SAFE", "POTENTIAL", "SKIPPED", "ERROR", "INFO"):
        f = _sample_finding()
        f["result"] = internal
        assert to_common(f)["result"] in RESULT_ENUM


def test_result_mapping():
    assert RESULT_MAP["VULNERABLE"] == "VULNERABLE"
    assert RESULT_MAP["SAFE"] == "PASS"
    assert RESULT_MAP["POTENTIAL"] == "REVIEW"
    assert RESULT_MAP["SKIPPED"] == "REVIEW"
    assert RESULT_MAP["ERROR"] == "ERROR"


def test_parameters_shape():
    params = to_common(_sample_finding())["parameters"]
    assert isinstance(params, list)
    for p in params:
        assert set(p.keys()) == {"name", "location"}
        assert p["location"] in {"path", "query", "body", "header"}


def test_skip_is_review():
    out = to_common_skip({"skip_id": "SKIP-001", "category": "X", "reason": "no config"})
    assert set(out.keys()) == REQUIRED_KEYS
    assert out["result"] == "REVIEW"


def test_resolve_config_accepts_common_input():
    native = {
        "base_url": "http://127.0.0.1:8080",
        "login_path": "/login",
        "accounts": {"victim": {"userId": "u", "password_env": "X_NOPE"}},
        "endpoints": [
            {"url": "http://127.0.0.1:8080/board/write", "method": "POST",
             "parameters": [{"name": "file", "location": "body"}]},
            {"url": "http://127.0.0.1:8080/download/{id}", "method": "GET",
             "parameters": [{"name": "id", "location": "path"}]},
        ],
    }
    cfg = resolve_config(native)
    assert cfg["upload_path"] == "/board/write"
    assert cfg["download"]["url_template"] == "/download/{id}"
    assert "victim" in cfg["credentials"]


def test_resolve_config_accepts_runner_native_shape():
    native = {
        "base_url": "http://127.0.0.1:8080",
        "accounts": {"victim": {"userId": "u", "password_env": "X_NOPE"}},
        "endpoints": [
            {"name": "up", "path": "/board/write", "method": "POST"},
            {"name": "dl", "path": "/download/{id}", "method": "GET"},
        ],
    }
    cfg = resolve_config(native)
    assert cfg["upload_path"] == "/board/write"
    assert cfg["download"]["url_template"] == "/download/{id}"
