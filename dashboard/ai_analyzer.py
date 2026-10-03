import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openai import OpenAI


SENSITIVE_KEYS = {
    "session_cookie", "cookie", "authorization", "password",
    "token", "access_token", "refresh_token", "api_key", "secret",
}


class VulnerabilityResultAnalyzer:
    def __init__(self):
        self.model = "gpt-6-luna"
        self.client = OpenAI()

    @staticmethod
    def _load_json(path: str | Path) -> dict[str, Any]:
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _save_json(path: str | Path, data: dict[str, Any]) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _source_hash(data: dict[str, Any]) -> str:
        raw = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _sanitize(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (
                    "[REDACTED]"
                    if key.lower() in SENSITIVE_KEYS
                    else VulnerabilityResultAnalyzer._sanitize(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [VulnerabilityResultAnalyzer._sanitize(item) for item in value]
        return value

    @staticmethod
    def _build_statistics(scan_result: dict[str, Any]) -> dict[str, Any]:
        results = scan_result.get("results", [])
        verdict_counts: dict[str, int] = {}
        vulnerability_counts: dict[str, int] = {}
        vulnerable_type_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        endpoint_keys: set[tuple[str, str]] = set()

        for item in results:
            endpoint_keys.add((item.get("method", ""), item.get("url", "")))

            verdict = item.get("verdict", "unknown")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

            vuln_type = item.get("vulnerability_type")
            if vuln_type:
                vulnerability_counts[vuln_type] = vulnerability_counts.get(vuln_type, 0) + 1

            if verdict == "vulnerable":
                if vuln_type:
                    vulnerable_type_counts[vuln_type] = vulnerable_type_counts.get(vuln_type, 0) + 1

                severity = item.get("result", {}).get("severity", "UNKNOWN")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_tasks": len(results),
            "unique_endpoints": len(endpoint_keys),
            "verdict_counts": verdict_counts,
            "scanner_candidate_counts": vulnerability_counts,
            "vulnerable_type_counts": vulnerable_type_counts,
            "severity_counts": severity_counts,
        }

    @staticmethod
    def _extract_vulnerable_findings(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []

        for item in scan_result.get("results", []):
            if item.get("verdict") != "vulnerable":
                continue

            result = item.get("result", {})
            params = [
                p.get("name")
                for p in item.get("parameters", [])
                if p.get("name")
            ]

            findings.append({
                "url": item.get("url"),
                "method": item.get("method"),
                "path_template": item.get("path_template"),
                "vulnerability_type": item.get("vulnerability_type"),
                "parameters": params,
                "severity": result.get("severity", "UNKNOWN"),
                "evidence": result.get("evidence", ""),
                "scanner_message": result.get("message", ""),
            })

        return findings

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            return "\n".join(lines).strip()
        return text

    def _call_ai(
        self,
        target_url: str,
        statistics: dict[str, Any],
        vulnerable_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload = {
            "target_url": target_url,
            "statistics": statistics,
            "vulnerable_findings": self._sanitize(vulnerable_findings),
        }

        instructions = """
당신은 웹 애플리케이션 취약점 진단 결과를 분석하는 보안 분석가이다.

입력 데이터는 자동화 취약점 스캐너가 생성한 사실 데이터이다.
입력에 존재하지 않는 취약점, 엔드포인트, 파라미터, 공격 성공 사실을
임의로 만들어내지 마라.

규칙:
1. 취약점 존재 여부는 입력의 vulnerable_findings를 그대로 따른다.
2. 통계 수치는 statistics 값을 그대로 사용한다.
3. 설명은 한국어로 작성한다.
4. 필요한 보안 기술 용어는 영어 원어를 함께 사용한다.
5. 위험 수준은 CRITICAL, HIGH, MEDIUM, LOW, INFO만 사용한다.
6. 근거가 부족하면 "추가 검증 필요"라고 명시한다.
7. Markdown을 사용하지 말고 유효한 JSON 객체 하나만 반환한다.
"""

        schema_prompt = """
아래 JSON 구조를 정확히 지켜라.

{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "executive_summary": "전체 진단 결과 3~5문장 요약",
  "key_findings": [
    {
      "vulnerability_type": "취약점 유형",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "url": "발견 URL",
      "method": "HTTP Method",
      "parameters": ["관련 파라미터"],
      "summary": "발견 내용",
      "impact": "발생 가능한 영향",
      "recommendation": "권장 조치",
      "validation_note": "추가 확인 사항 또는 없음"
    }
  ],
  "priority_actions": [
    {
      "priority": 1,
      "title": "우선 조치 제목",
      "reason": "우선 처리 이유",
      "related_vulnerability_types": ["sqli"]
    }
  ],
  "vulnerability_analysis": {
    "sqli": "",
    "xss": "",
    "ssrf": "",
    "authz": "",
    "fileio": ""
  },
  "general_recommendations": []
}

key_findings는 입력의 vulnerable_findings에 있는 항목만 포함하라.
priority_actions는 최대 5개까지만 작성하라.
"""

        response = self.client.responses.create(
            model=self.model,
            instructions=instructions,
            input=(
                schema_prompt
                + "\n\n분석할 스캔 결과:\n"
                + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            ),
        )

        text = self._strip_code_fence(response.output_text)

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "AI 응답을 JSON으로 파싱하지 못했습니다.\n"
                f"응답 내용:\n{text}"
            ) from exc

    def analyze_file(
        self,
        input_path: str | Path,
        output_path: str | Path,
        force: bool = False,
    ) -> dict[str, Any]:
        scan_result = self._load_json(input_path)
        source_hash = self._source_hash(scan_result)
        output_path = Path(output_path)

        if output_path.exists() and not force:
            previous = self._load_json(output_path)
            if previous.get("source_hash") == source_hash:
                print("동일한 스캔 결과가 이미 분석되어 있어 API를 호출하지 않습니다.")
                return previous

        statistics = self._build_statistics(scan_result)
        vulnerable_findings = self._extract_vulnerable_findings(scan_result)

        target_url = scan_result.get("target_url") or scan_result.get("target")
        if not target_url and scan_result.get("results"):
            target_url = scan_result["results"][0].get("url", "")

        ai_analysis = self._call_ai(
            target_url=target_url or "",
            statistics=statistics,
            vulnerable_findings=vulnerable_findings,
        )

        output = {
            "source_hash": source_hash,
            "source_file": Path(input_path).name,
            "model": self.model,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "statistics": statistics,
            "analysis": ai_analysis,
        }

        self._save_json(output_path, output)
        print(f"AI 분석 결과 저장 완료: {output_path}")
        return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="취약점 스캔 결과 JSON을 AI로 분석해 대시보드용 JSON으로 저장합니다."
    )
    parser.add_argument("input", help="통합 스캐너 결과 JSON")
    parser.add_argument(
        "-o",
        "--output",
        default="output/ai_analysis2.json",
        help="AI 분석 결과 JSON",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="동일한 결과라도 API를 다시 호출합니다.",
    )
    args = parser.parse_args()

    analyzer = VulnerabilityResultAnalyzer()
    analyzer.analyze_file(
        input_path=args.input,
        output_path=args.output,
        force=args.force,
    )


if __name__ == "__main__":
    main()
