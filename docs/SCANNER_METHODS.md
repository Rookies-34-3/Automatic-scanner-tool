# 스캐너 실행 메서드 모음

통합 파이프라인에서는 팀별 원본 함수를 직접 호출하지 않고 `module/tool_registry.py`의
`execute_tool()`을 사용한다. AI에는 URL·메서드·파라미터만 공개하고 세션 쿠키는 로컬
실행부가 별도로 주입한다.

| 취약점 | 원본 코드 | Function tool | 필요한 환경변수 |
|---|---|---|---|
| SQL Injection | `module/sqli/scanner.py` | `scan_sqli` | 없음 |
| Reflected XSS | `module/xss/reflected_xss.py` | `scan_reflected_xss` | 없음 |
| SSRF | `module/ssrf/scanner.py` | `scan_ssrf` | 선택: `SSRF_PROBE_URL`, `SSRF_EXPECTED_MARKERS` |
| 불충분한 인증 | `module/authn_scanner/` | `scan_authn` | 선택: `ROOKIESCAN_AUTHN_CONFIG`, `ROOKIESCAN_PASSWORD` |
| IDOR/BOLA | `module/authz_scanner/` | `scan_authz` | `ROOKIESCAN_AUTHZ_CONFIG`, `ROOKIESCAN_PASSWORD` |
| 파일 업로드/다운로드 | `module/fileio_scanner/` | `scan_fileio` | `ROOKIESCAN_FILEIO_CONFIG`, `ROOKIESCAN_PASSWORD` |
| 관리자 페이지 노출 | `module/scan/admin_exposure/scanner.py` | `scan_admin_exposure` | 없음 |
| 디렉터리 인덱싱 | `module/scan/directory_indexing/scanner.py` | `scan_directory_indexing` | 없음 |
| 비허용 포트 노출 | `module/scan/portscan/scanner.py` | `scan_portscan` | 없음 |

공통 Python 호출 형식은 다음과 같다.

```python
execute_tool(
    name,
    {"url": url, "method": method, "parameters": parameters},
    session_cookie=session_cookie,
)
```

모든 finding은 아래 필드를 가진다.

```text
scanner_id, name, url, method, parameters,
vuln, result, severity, details
```

`vuln` 값은 `VULNERABLE`, `PASS`, `REVIEW`, `ERROR`로 제한한다. 최종 JSON의 예시는
`examples/final-output.example.json`을 참고한다.
