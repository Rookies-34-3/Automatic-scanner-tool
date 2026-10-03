"""Finding 모델 - 출력 JSON 스키마 정의.

모든 체크는 Finding 객체를 반환하고, 엔진이 scan_id 를 자동 채번한다.
출력 스키마(사용자 지정):
  scan_id, category, target_url, method, parameter, payload,
  status_code, result, severity, evidence, details
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# result 값
VULNERABLE = "VULNERABLE"       # 취약 확증
POTENTIAL = "POTENTIAL"         # 의심(수동확인 권장)
SAFE = "SAFE"                   # 방어됨
INFO = "INFO"                   # 정보/관찰
ERROR = "ERROR"                 # 검사 중 오류
SKIPPED = "SKIPPED"             # 설정 부족으로 미수행(건너뜀)

# severity 값
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
SEV_INFO = "INFO"


@dataclass
class Finding:
    category: str                       # 취약점 유형명
    target_url: str = ""                # 검사 대상 URL(건너뜀 항목은 비어있을 수 있음)
    method: str = "POST"                # HTTP 메서드
    parameter: str = ""                 # 대상 파라미터(파일필드명/다운로드 id 등)
    payload: str = ""                   # 사용한 페이로드(파일명/경로문자열 등)
    status_code: Optional[int] = None   # 응답 상태코드
    result: str = INFO                  # VULNERABLE / POTENTIAL / SAFE / INFO / ERROR
    severity: str = SEV_INFO            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    evidence: str = ""                  # 판단 근거(사람이 읽는 한 줄)
    details: dict = field(default_factory=dict)  # 재현/부가정보
    scan_id: str = ""                   # 엔진이 채번 (SCAN-001 ...)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # 스키마 순서 보장
        order = ["scan_id", "category", "target_url", "method", "parameter",
                 "payload", "status_code", "result", "severity", "evidence",
                 "details"]
        return {k: d[k] for k in order}


# 심각도 정렬 가중치
SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, SEV_INFO: 4}
RESULT_ORDER = {VULNERABLE: 0, POTENTIAL: 1, INFO: 2, SAFE: 3, ERROR: 4, SKIPPED: 5}


def skipped(category, reason):
    """건너뛴 테스트를 기록하는 헬퍼. result=SKIPPED 인 Finding 반환."""
    return Finding(category=category, result=SKIPPED, severity=SEV_INFO,
                   evidence=reason)
