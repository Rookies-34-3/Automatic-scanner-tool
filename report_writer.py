"""각 취약점 모듈의 결과를 모아 최종 보고서를 작성할 모듈.

JSON을 기준 결과로 사용하고 Streamlit 화면과 HTML 보고서로 표현할 예정이다.
구현은 다음 단계에서 추가한다.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4


def save_sink_summary(summary: dict, target_url: str) -> Path:
    """Sink 집계 결과를 호스트별 고유 JSON 파일로 저장한다."""
    parts = urlsplit(target_url)
    host = re.sub(r"[^A-Za-z0-9.-]", "-", (parts.hostname or "target").encode("idna").decode("ascii"))
    if parts.port:
        host += f"-{parts.port}"
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"openai-sinks-{host}-{stamp}-{uuid4().hex[:8]}.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(summary, output, ensure_ascii=False, separators=(",", ":"))
    return path
