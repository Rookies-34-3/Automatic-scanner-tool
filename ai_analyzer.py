import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from openai import OpenAI


SENSITIVE_KEYS = {
    "session_cookie",
    "cookie",
    "authorization",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "secret",
}

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
ANALYSIS_VERSION = "2"


class VulnerabilityResultAnalyzer:
    def __init__(self):
        self.model = "gpt-6.1-sol"
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
        """현재 통합 스캐너 최종 포맷의 summary/findings를 기준으로 통계를 생성한다."""
        source_summary = scan_result.get("summary", {})
        results = scan_result.get("results", [])
        findings = scan_result.get("findings", [])

        verdict_counts: dict[str, int] = {}
        scanner_candidate_counts: dict[str, int] = {}
        vulnerable_type_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        endpoint_keys: set[tuple[str, str]] = set()

        for item in findings:
            url = str(item.get("url", ""))
            method = str(item.get("method", ""))
            endpoint_keys.add((method, url))

            verdict = str(item.get("vuln", "UNKNOWN")).strip().lower()
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

            scanner_id = str(item.get("scanner_id", "")).strip()
            if scanner_id:
                scanner_candidate_counts[scanner_id] = (
                    scanner_candidate_counts.get(scanner_id, 0) + 1
                )

            if verdict != "vulnerable":
                continue

            if scanner_id:
                vulnerable_type_counts[scanner_id] = (
                    vulnerable_type_counts.get(scanner_id, 0) + 1
                )

            severity = str(item.get("severity", "UNKNOWN")).upper()
            if severity not in ALLOWED_SEVERITIES:
                severity = "UNKNOWN"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        total_tasks = int(source_summary.get("total_scans", len(results)))
        unique_endpoints = int(
            source_summary.get("total_endpoints", len(endpoint_keys))
        )
        total_findings = int(
            source_summary.get("total_findings", len(findings))
        )
        verified_vulnerable_count = verdict_counts.get("vulnerable", 0)

        return {
            "total_tasks": total_tasks,
            "unique_endpoints": unique_endpoints,
            "total_findings": total_findings,
            "verdict_counts": verdict_counts,
            "scanner_candidate_counts": scanner_candidate_counts,
            "vulnerable_type_counts": vulnerable_type_counts,
            "severity_counts": severity_counts,
            "verified_vulnerable_count": verified_vulnerable_count,
        }

    @staticmethod
    def _calculate_overall_risk(statistics: dict[str, Any]) -> str:
        severity_counts = statistics.get("severity_counts", {})
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if severity_counts.get(severity, 0) > 0:
                return severity
        return "INFO"

    @staticmethod
    def _assessment_intro(target_url: str, statistics: dict[str, Any]) -> str:
        total = statistics["verified_vulnerable_count"]
        severities = statistics.get("severity_counts", {})
        high_risk = severities.get("HIGH", 0) + severities.get("CRITICAL", 0)
        return (
            f"본 모의해킹은 대상 웹 시스템({target_url or '대상 주소 미제공'})을 대상으로 "
            "ROOKIESCAN 프로그램에 의해 수행되었습니다. "
            f"진단 결과, 총 {total}건의 취약점이 발견되었으며, "
            f"이 중 고위험(High-Risk, HIGH 및 CRITICAL 등급) 취약점은 {high_risk}건 확인되었습니다."
        )

    @staticmethod
    def _extract_verified_findings(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
        """최상위 findings[]에서 VULNERABLE로 판정된 항목만 AI 분석 대상으로 추출한다."""
        verified_findings: list[dict[str, Any]] = []

        for item in scan_result.get("findings", []):
            if str(item.get("vuln", "")).upper() != "VULNERABLE":
                continue

            params: list[dict[str, str]] = []
            seen_params: set[tuple[str, str]] = set()

            for parameter in item.get("parameters", []):
                if not isinstance(parameter, dict):
                    continue

                name = str(parameter.get("name", "")).strip()
                location = str(parameter.get("location", "unknown")).strip()

                if not name:
                    continue

                key = (name, location)
                if key in seen_params:
                    continue

                seen_params.add(key)
                params.append({"name": name, "location": location})

            severity = str(item.get("severity", "UNKNOWN")).upper()
            if severity not in ALLOWED_SEVERITIES:
                severity = "UNKNOWN"

            scanner_id = str(item.get("scanner_id", "")).strip()
            finding_id = f"F{len(verified_findings) + 1:03d}"

            verified_findings.append(
                {
                    "finding_id": finding_id,
                    "scanner_id": scanner_id,
                    "name": str(item.get("name", scanner_id)),
                    "url": str(item.get("url", "")),
                    "method": str(item.get("method", "")),
                    "vulnerability_type": scanner_id,
                    "parameters": params,
                    "severity": severity,
                    "evidence": str(item.get("result", "")),
                }
            )

        return verified_findings

    @staticmethod
    def _scenario_group_key(finding: dict[str, Any]) -> str:
        path_template = str(finding.get("path_template") or "").strip()
        if path_template:
            return path_template

        url = str(finding.get("url") or "")
        return urlsplit(url).path or url

    @staticmethod
    def _build_scenario_candidates(
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        groups: dict[str, list[dict[str, Any]]] = {}

        for finding in findings:
            key = VulnerabilityResultAnalyzer._scenario_group_key(finding)
            groups.setdefault(key, []).append(finding)

        candidates: list[dict[str, Any]] = []
        sorted_groups = sorted(
            groups.items(),
            key=lambda item: (
                -len({f.get("vulnerability_type") for f in item[1]}),
                -len(item[1]),
                item[0],
            ),
        )

        for group_key, group_findings in sorted_groups:
            candidate_id = f"C{len(candidates) + 1:03d}"
            candidates.append(
                {
                    "candidate_id": candidate_id,
                    "endpoint_group": group_key,
                    "finding_ids": [f["finding_id"] for f in group_findings],
                    "vulnerability_types": sorted(
                        {
                            str(f.get("vulnerability_type", ""))
                            for f in group_findings
                            if f.get("vulnerability_type")
                        }
                    ),
                    "endpoints": sorted(
                        {
                            str(f.get("url", ""))
                            for f in group_findings
                            if f.get("url")
                        }
                    ),
                    "methods": sorted(
                        {
                            str(f.get("method", ""))
                            for f in group_findings
                            if f.get("method")
                        }
                    ),
                }
            )

        return candidates

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        text = text.strip()
        if not text.startswith("```"):
            return text

        lines = text.splitlines()[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()

    def _call_ai(
        self,
        target_url: str,
        statistics: dict[str, Any],
        overall_risk: str,
        findings: list[dict[str, Any]],
        scenario_candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload = {
            "target_url": target_url,
            "overall_risk": overall_risk,
            "assessment_intro": self._assessment_intro(target_url, statistics),
            "statistics": statistics,
            "verified_findings": self._sanitize(findings),
            "scenario_candidates": scenario_candidates,
        }

        instructions = """
당신은 웹 애플리케이션 자동 취약점 진단 결과를 설명하는 보안 분석가이다.
입력의 verified_findings는 스캐너가 검증 완료한 사실 데이터이다.
새로운 사실을 추론하여 추가하지 말고, 주어진 사실을 설명하고 정리하는 역할만 수행한다.

절대 규칙:
1. 입력에 없는 취약점 유형을 새로 만들지 않는다.
2. 입력에 없는 URL, Endpoint, HTTP Method, Parameter를 새로 만들지 않는다.
3. 공격 성공 여부, 권한 획득, 데이터 탈취 등의 사실을 임의로 확정하지 않는다.
4. key_findings는 반드시 실제 finding_id를 참조한다.
5. 공격 시나리오는 scenario_candidates에 제시된 후보 안에서만 작성한다.
6. 서로 다른 candidate_id의 Finding을 하나의 공격 시나리오로 결합하지 않는다.
7. 공격 시나리오의 evidence_refs는 해당 candidate_id의 finding_ids 일부 또는 전부만 사용할 수 있다.
8. 공격 시나리오는 실제 공격 명령, Payload, 우회 절차 등 실행 가능한 공격 절차를 작성하지 않는다.
9. 개별 취약점은 검증되었지만 취약점 간 공격 체인은 검증된 것이 아니므로 scenario_status는 항상 possible로 작성한다.
10. 공격 시나리오를 뒷받침할 근거가 부족하면 시나리오를 만들지 않는다. 빈 배열은 정상 출력이다.
11. 통계와 overall_risk는 입력값을 그대로 사용하고 변경하거나 재계산하지 않는다.
12. 근거가 부족한 내용은 '추가 검증 필요'라고 명시한다.
13. 설명은 한국어로 작성하고 필요한 보안 용어는 영어 원어를 함께 사용한다.
14. Markdown을 사용하지 말고 유효한 JSON 객체 하나만 반환한다.
15. HIGH/CRITICAL은 심각도 분류이며, 그 등급만으로 시스템 장악이나 원격 코드 실행(RCE)이 가능하다고 쓰지 않는다. 입력 증거가 이를 직접 뒷받침할 때만 가능성과 확인 사실을 구분하여 설명한다.
16. 총평은 전문적인 모의해킹 보고서 문체로 작성한다. assessment_intro는 Python이 총평 앞에 붙일 확정 도입부이므로 overall_assessment 안에 반복하지 않는다.
"""

        schema_prompt = """
아래 구조를 정확히 지켜 JSON을 반환하라.

{
  "overall_assessment": "도입부에 이어지는 총평 본문. 총 진단 결과 요약, 주요 보안 위협 분석, 개선 및 조치 의견을 이 순서로 3개 문단, 총 6~9문장으로 작성. 문단은 JSON 문자열의 줄바꿈으로 구분하며 제목 없이 자연스럽게 연결",
  "key_findings": [
    {
      "finding_id": "F001",
      "summary": "해당 Finding을 한 문장으로 설명",
      "impact": "이 취약점으로 인해 발생할 수 있는 영향. 확인되지 않은 결과는 가능성으로 표현",
      "recommendation": "권장 조치",
      "validation_note": "추가 확인이 필요한 사항. 없으면 '없음'"
    }
  ],
  "attack_scenarios": [
    {
      "candidate_ref": "C001",
      "title": "가능한 공격 시나리오 제목",
      "scenario_status": "possible",
      "confidence": "high|medium|low",
      "evidence_refs": ["F001", "F002"],
      "scenario": "해당 Finding들만 근거로 가능한 공격 흐름을 고수준에서 설명",
      "potential_impact": "성립할 경우 예상 가능한 영향",
      "required_conditions": "이 공격 흐름이 실제 성립하는지 확인하기 위해 필요한 조건 또는 추가 검증"
    }
  ],
  "priority_actions": [
    {
      "priority": 1,
      "title": "우선 조치 제목",
      "reason": "우선 처리 이유",
      "related_finding_ids": ["F001"]
    }
  ]
}

추가 규칙:
- key_findings는 verified_findings에 존재하는 finding_id만 사용한다.
- priority_actions는 최대 5개까지만 작성한다.
- priority_actions.related_finding_ids도 verified_findings의 ID만 사용한다.
- attack_scenarios는 반드시 scenario_candidates의 candidate_id 하나를 candidate_ref로 지정한다.
- evidence_refs는 해당 candidate_ref의 finding_ids 안에서만 선택한다.
- 서로 다른 Endpoint 그룹을 임의로 연계하지 않는다.
- 공격 시나리오의 근거가 약하거나 단순 추측에 불과하면 attack_scenarios에 추가하지 않는다.
- vulnerability_analysis와 general_recommendations는 출력하지 않는다. 종합 위협 설명과 개선 의견은 overall_assessment에 통합한다.
- 총평 첫 문단은 statistics의 전체 점검 범위와 VULNERABLE/PASS/REVIEW/ERROR 현황을 요약하되, PASS를 안전 보장으로 설명하거나 REVIEW를 확정 취약점에 포함하지 않는다.
- 둘째 문단은 verified_findings의 핵심 위협과 예상 영향을 설명한다. 빈 목록이면 확인된 취약점이 없다고 쓰고 검사 한계를 설명한다.
- 셋째 문단은 확인된 취약점에 맞는 우선 조치, 검토 항목의 수동 확인, 조치 후 재진단 의견을 제시한다.
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

    @staticmethod
    def _validate_key_findings(
        ai_key_findings: Any,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not isinstance(ai_key_findings, list):
            return []

        finding_map = {f["finding_id"]: f for f in findings}
        validated: list[dict[str, Any]] = []
        seen: set[str] = set()

        for item in ai_key_findings:
            if not isinstance(item, dict):
                continue

            finding_id = item.get("finding_id")
            if finding_id not in finding_map or finding_id in seen:
                continue

            source = finding_map[finding_id]
            seen.add(finding_id)

            validated.append(
                {
                    "finding_id": finding_id,
                    "scanner_id": source.get("scanner_id", ""),
                    "name": source.get("name", ""),
                    "vulnerability_type": source.get("vulnerability_type", ""),
                    "severity": source.get("severity", "UNKNOWN"),
                    "url": source.get("url", ""),
                    "method": source.get("method", ""),
                    "parameters": source.get("parameters", []),
                    "evidence": source.get("evidence", ""),
                    "summary": str(item.get("summary", "")),
                    "impact": str(item.get("impact", "")),
                    "recommendation": str(item.get("recommendation", "")),
                    "validation_note": str(item.get("validation_note", "")),
                }
            )

        return validated

    @staticmethod
    def _validate_attack_scenarios(
        ai_scenarios: Any,
        findings: list[dict[str, Any]],
        candidates: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        if not isinstance(ai_scenarios, list):
            return [], 0

        finding_map = {f["finding_id"]: f for f in findings}
        candidate_map = {c["candidate_id"]: c for c in candidates}
        validated: list[dict[str, Any]] = []
        rejected = 0

        for scenario in ai_scenarios:
            if not isinstance(scenario, dict):
                rejected += 1
                continue

            candidate_ref = scenario.get("candidate_ref")
            candidate = candidate_map.get(candidate_ref)
            if not candidate:
                rejected += 1
                continue

            evidence_refs = scenario.get("evidence_refs")
            if not isinstance(evidence_refs, list) or not evidence_refs:
                rejected += 1
                continue

            evidence_refs = list(dict.fromkeys(str(ref) for ref in evidence_refs))
            allowed_refs = set(candidate.get("finding_ids", []))

            if any(ref not in allowed_refs or ref not in finding_map for ref in evidence_refs):
                rejected += 1
                continue

            evidence_findings = [finding_map[ref] for ref in evidence_refs]
            related_types = sorted(
                {
                    str(f.get("vulnerability_type", ""))
                    for f in evidence_findings
                    if f.get("vulnerability_type")
                }
            )
            related_endpoints = sorted(
                {
                    str(f.get("url", ""))
                    for f in evidence_findings
                    if f.get("url")
                }
            )

            confidence = str(scenario.get("confidence", "low")).lower()
            if confidence not in ALLOWED_CONFIDENCE:
                confidence = "low"

            validated.append(
                {
                    "candidate_ref": candidate_ref,
                    "title": str(scenario.get("title", "가능한 공격 시나리오")),
                    "scenario_status": "possible",
                    "confidence": confidence,
                    "evidence_refs": evidence_refs,
                    "related_vulnerability_types": related_types,
                    "related_endpoints": related_endpoints,
                    "scenario": str(scenario.get("scenario", "")),
                    "potential_impact": str(scenario.get("potential_impact", "")),
                    "required_conditions": str(scenario.get("required_conditions", "추가 검증 필요")),
                }
            )

        return validated, rejected

    @staticmethod
    def _validate_priority_actions(
        ai_actions: Any,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not isinstance(ai_actions, list):
            return []

        valid_ids = {f["finding_id"] for f in findings}
        validated: list[dict[str, Any]] = []

        for item in ai_actions[:5]:
            if not isinstance(item, dict):
                continue

            refs = item.get("related_finding_ids", [])
            if not isinstance(refs, list):
                continue

            refs = [str(ref) for ref in refs if str(ref) in valid_ids]
            refs = list(dict.fromkeys(refs))
            if not refs:
                continue

            validated.append(
                {
                    "priority": len(validated) + 1,
                    "title": str(item.get("title", "")),
                    "reason": str(item.get("reason", "")),
                    "related_finding_ids": refs,
                }
            )

        return validated

    def _validate_ai_analysis(
        self,
        ai_analysis: dict[str, Any],
        findings: list[dict[str, Any]],
        candidates: list[dict[str, Any]],
        overall_risk: str,
    ) -> tuple[dict[str, Any], dict[str, int]]:
        key_findings = self._validate_key_findings(
            ai_analysis.get("key_findings", []),
            findings,
        )
        attack_scenarios, rejected_scenarios = self._validate_attack_scenarios(
            ai_analysis.get("attack_scenarios", []),
            findings,
            candidates,
        )
        priority_actions = self._validate_priority_actions(
            ai_analysis.get("priority_actions", []),
            findings,
        )

        validated = {
            "overall_risk": overall_risk,
            "overall_assessment": str(ai_analysis.get("overall_assessment", "")),
            "key_findings": key_findings,
            "attack_scenarios": attack_scenarios,
            "priority_actions": priority_actions,
        }

        validation_stats = {
            "verified_findings_sent": len(findings),
            "scenario_candidates": len(candidates),
            "accepted_attack_scenarios": len(attack_scenarios),
            "rejected_attack_scenarios": rejected_scenarios,
        }
        return validated, validation_stats

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
            if (previous.get("source_hash") == source_hash
                    and previous.get("analysis_version") == ANALYSIS_VERSION
                    and previous.get("model") == self.model):
                print("동일한 스캔 결과가 이미 분석되어 있어 API를 호출하지 않습니다.")
                return previous

        statistics = self._build_statistics(scan_result)
        overall_risk = self._calculate_overall_risk(statistics)
        findings = self._extract_verified_findings(scan_result)
        candidates = self._build_scenario_candidates(findings)

        target_url = scan_result.get("target_url") or scan_result.get("target")
        if not target_url and scan_result.get("results"):
            first_url = scan_result["results"][0].get("url", "")
            parsed = urlsplit(first_url)
            target_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else first_url

        raw_ai_analysis = self._call_ai(
            target_url=target_url or "",
            statistics=statistics,
            overall_risk=overall_risk,
            findings=findings,
            scenario_candidates=candidates,
        )

        analysis, validation_stats = self._validate_ai_analysis(
            raw_ai_analysis,
            findings,
            candidates,
            overall_risk,
        )

        body = analysis["overall_assessment"].strip()
        intro = self._assessment_intro(target_url or "", statistics)
        analysis["overall_assessment"] = intro + ("\n\n" + body if body else "")

        output = {
            "analysis_version": ANALYSIS_VERSION,
            "source_hash": source_hash,
            "source_file": Path(input_path).name,
            "model": self.model,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "statistics": statistics,
            "analysis_validation": validation_stats,
            "analysis": analysis,
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
        default="output/analysis.json",
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
