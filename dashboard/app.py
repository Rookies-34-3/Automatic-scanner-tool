"""ROOKIESCAN 대시보드 복구본: 기존/팀 공통 JSON 포맷을 모두 읽습니다."""
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent
# 여러 스캐너를 합칠 때 목록에 파일 경로를 추가합니다.
app.config["FINDING_FILES"] = [ROOT / "results" / "findings.json"]
app.config["SAMPLE_FILES"] = [ROOT / "samples" / "findings.json"]
RESULTS = {"VULNERABLE": "취약", "SAFE": "양호", "N/A": "판정불가"}
SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


def load_findings(paths):
    findings, warnings = [], []
    for path in paths:
        path = Path(path)
        try:
            rows = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(rows, list):
                raise ValueError("최상위 데이터는 JSON 배열이어야 합니다.")
        except (OSError, ValueError) as exc:
            warnings.append(f"{path.name}: 파일을 읽지 못했습니다 ({type(exc).__name__}). 경로와 JSON 문법을 확인하세요.")
            continue
        for index, row in enumerate(rows, 1):
            try:
                if not isinstance(row, dict):
                    raise ValueError()
                item = dict(row)
                # 최신 포맷(vuln/result 객체)을 기존 UI에서 사용할 필드로 변환합니다.
                if "vuln" in row:
                    details = row.get("result")
                    if not isinstance(details, dict):
                        raise ValueError()
                    parameter = row.get("parameters", "")
                    if isinstance(parameter, list):
                        parameter = ", ".join(parameter)
                    item.update(target_url=row.get("url", ""), parameter=parameter,
                                result=row["vuln"], payload=details.get("payload"),
                                evidence=details.get("evidence", ""), status_code=details.get("status_code"))
                if item.get("result") not in tuple(RESULTS) or item.get("severity") not in SEVERITIES:
                    raise ValueError()
                for field in ("scan_id", "category", "target_url", "method", "parameter",
                              "evidence", "remediation", "scanned_at"):
                    if not isinstance(item.get(field), str):
                        raise ValueError()
                if item.get("payload") is not None and not isinstance(item["payload"], str):
                    raise ValueError()
                item.setdefault("payload", None)
                item.setdefault("status_code", None)
                findings.append(item)
            except (ValueError, TypeError):
                warnings.append(f"{path.name}의 {index}번째 항목: 필드 형식이 맞지 않아 제외했습니다.")
    return findings, warnings


def summarize(findings):
    results = Counter(item["result"] for item in findings)
    categories = sorted({item["category"] for item in findings})
    vulnerable = Counter(item["category"] for item in findings if item["result"] == "VULNERABLE")
    severity = Counter(item["severity"] for item in findings)
    return dict(total=len(findings), results={key: results[key] for key in RESULTS},
                categories=categories, vulnerable_counts=[vulnerable[key] for key in categories],
                severity_labels=list(SEVERITIES), severity_counts=[severity[key] for key in SEVERITIES])


@app.get("/")
def dashboard():
    # 전달용 폴더에는 실데이터를 넣지 않습니다. 실데이터가 없으면 샘플 모드로 열립니다.
    default_sample = not any(Path(path).exists() for path in app.config["FINDING_FILES"])
    sample = request.args.get("sample", "1" if default_sample else "0") == "1"
    paths = app.config["SAMPLE_FILES" if sample else "FINDING_FILES"]
    findings, warnings = load_findings(paths)
    response = app.make_response(render_template(
        "dashboard.html", findings=findings, summary=summarize(findings), warnings=warnings,
        result_labels=RESULTS, sample=sample, sources=[Path(path).name for path in paths],
        loaded_at=datetime.now().astimezone().strftime("%Y.%m.%d %H:%M:%S %Z")))
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
