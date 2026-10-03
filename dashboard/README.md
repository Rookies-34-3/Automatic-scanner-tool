# AI Vulnerability Analysis

통합 취약점 스캐너에서 생성된 결과 JSON을 입력으로 받아 OpenAI API를 통해 취약점 분석을 수행하고, Streamlit Dashboard에서 사용할 수 있는 분석 결과 JSON을 생성합니다.

## 1. 개요

전체 파이프라인은 다음과 같습니다.

```text
통합 Scanner
    ↓
scan_result.json
    ↓
ai_analyzer.py
    ↓
OpenAI API
    ↓
ai_analysis.json
    ↓
Streamlit Dashboard
```

`ai_analyzer.py`는 실제 취약점 탐지를 수행하지 않습니다.

취약점 탐지는 개별 Scanner가 담당하며, AI Analysis 모듈은 Scanner 결과를 기반으로 다음 작업을 수행합니다.

- 전체 진단 결과 분석
- 전체 위험도 산정
- 종합 총평 생성
- 주요 취약점 설명
- 취약점 영향 분석
- 권장 조치 생성
- 우선 조치 항목 생성
- 가능한 공격 시나리오 분석
- 취약점 유형별 분석

---

## 2. 주요 파일

```text
ai_analyzer.py
requirements_ai.txt
scan_result.json
ai_analysis.json
```

### `ai_analyzer.py`

통합 Scanner 결과를 분석하고 OpenAI API를 호출하여 `ai_analysis.json`을 생성합니다.

### `requirements_ai.txt`

필요한 Python 패키지 목록입니다.

### `scan_result.json`

통합 Scanner에서 생성된 원본 결과입니다.

### `ai_analysis.json`

AI Analysis 결과가 저장되는 파일입니다.

Streamlit Dashboard에서는 이 파일을 읽어 분석 결과를 출력합니다.

---

## 3. 설치

```bash
pip install -r requirements_ai.txt
```

OpenAI API Key를 환경변수로 설정합니다.

Linux / WSL:

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
```

모델명은 `ai_analyzer.py` 내부에서 직접 지정합니다.

```python
self.model = "gpt-6.1-sol"
```

---

## 4. 실행

기본 실행:

```bash
python ai_analyzer.py scan_result.json
```

실행 후 다음 파일이 생성됩니다.

```text
ai_analysis.json
```

출력 파일명을 직접 지정할 수도 있습니다.

```bash
python ai_analyzer.py scan_result.json \
    -o result/ai_analysis.json
```

동일한 Scan Result라도 AI 분석을 다시 수행하려면 다음 옵션을 사용합니다.

```bash
python ai_analyzer.py scan_result.json --force
```

---

## 5. 분석 대상

AI는 모든 Scanner 결과를 그대로 분석하지 않습니다.

다음 조건을 만족하는 결과만 실제 취약점 Finding으로 사용합니다.

```text
verdict == "vulnerable"
verified == true
```

예:

```json
{
  "vulnerability_type": "ssrf",
  "verdict": "vulnerable",
  "result": {
    "verified": true,
    "severity": "HIGH",
    "evidence": "..."
  }
}
```

`not_vulnerable`, `skipped`, `inconclusive` 등의 결과는 공격 시나리오의 근거로 사용하지 않습니다.

---

## 6. Finding ID

검증된 취약점에는 내부적으로 Finding ID가 부여됩니다.

```text
F001
F002
F003
...
```

예:

```json
{
  "finding_id": "F001",
  "vulnerability_type": "ssrf",
  "severity": "HIGH",
  "url": "http://example.com/pre-course/write",
  "method": "POST",
  "parameters": ["url"]
}
```

Finding ID는 AI가 원본에 존재하지 않는 취약점을 임의로 생성하는 것을 방지하기 위한 근거 식별자로 사용됩니다.

---

## 7. 공격 시나리오 분석

AI가 전체 취약점을 자유롭게 조합하여 공격 시나리오를 생성하지 않도록 제한합니다.

Python 코드가 먼저 관련성이 있는 Finding을 그룹으로 구성합니다.

```text
F001 ┐
     ├─ C001
F002 ┘

F003 ┐
     ├─ C002
F004 ┘
```

각 그룹에는 Candidate ID가 부여됩니다.

```text
C001
C002
...
```

AI는 지정된 Candidate 내부의 Finding만 사용하여 공격 시나리오를 설명할 수 있습니다.

예:

```json
{
  "candidate_ref": "C001",
  "evidence_refs": [
    "F001",
    "F002"
  ],
  "scenario_status": "possible",
  "confidence": "medium"
}
```

공격 시나리오는 실제 공격 성공을 의미하지 않습니다.

Scanner에서 각 취약점은 확인되었지만 취약점 간 연결 가능성까지 실제로 검증된 것은 아니므로 기본적으로 다음 상태를 사용합니다.

```text
possible
```

근거가 부족한 경우 공격 시나리오를 생성하지 않습니다.

```json
{
  "attack_scenarios": []
}
```

---

## 8. AI Hallucination 방지

AI가 원본 Scanner 결과에 없는 내용을 생성하지 못하도록 여러 검증 절차를 적용합니다.

### 입력 제한

AI에는 실제 검증된 Finding만 전달합니다.

```text
verdict = vulnerable
verified = true
```

### Finding Reference

AI가 생성하는 주요 분석 및 공격 시나리오는 기존 Finding ID를 참조합니다.

```json
{
  "evidence_refs": [
    "F001",
    "F003"
  ]
}
```

### Candidate 제한

공격 시나리오는 Python에서 생성한 Candidate 내부 Finding만 사용할 수 있습니다.

### AI 출력 재검증

AI 응답을 그대로 저장하지 않고 Python에서 다시 검증합니다.

검증 항목:

```text
Finding ID 존재 여부
Candidate ID 존재 여부
Candidate와 Finding 관계
Vulnerability Type
Endpoint
```

원본 Scanner 결과와 일치하지 않는 공격 시나리오는 제거됩니다.

---

## 9. 분석 결과 구조

생성되는 `ai_analysis.json`은 다음과 같은 구조를 가집니다.

```json
{
  "source_hash": "...",
  "source_file": "scan_result.json",
  "model": "gpt-6.1-sol",
  "generated_at": "...",

  "statistics": {
    "total_tasks": 59,
    "unique_endpoints": 25,
    "verified_vulnerable_count": 21,
    "verdict_counts": {},
    "vulnerable_type_counts": {},
    "severity_counts": {}
  },

  "analysis": {
    "overall_risk": "HIGH",

    "overall_assessment": "전체 취약점 진단 결과에 대한 종합적인 분석",

    "key_findings": [],

    "attack_scenarios": [],

    "priority_actions": [],

    "vulnerability_analysis": {
      "sqli": "",
      "xss": "",
      "ssrf": "",
      "authz": "",
      "fileio": ""
    },

    "general_recommendations": []
  }
}
```

---

## 10. 주요 분석 정보

### `overall_risk`

전체 진단 결과의 위험 수준입니다.

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

위험도는 실제 Scanner 결과의 Severity를 기반으로 결정합니다.

### `overall_assessment`

전체 스캔 결과에 대한 종합적인 총평입니다.

다음 내용을 포함합니다.

- 전체적인 보안 상태
- 주요 취약점 유형
- 위험성이 높은 영역
- 우선적으로 개선해야 할 부분

### `key_findings`

주요 취약점에 대한 상세 분석입니다.

```json
{
  "finding_id": "F001",
  "vulnerability_type": "ssrf",
  "severity": "HIGH",
  "url": "...",
  "method": "POST",
  "parameters": ["url"],
  "summary": "...",
  "impact": "...",
  "recommendation": "...",
  "validation_note": "..."
}
```

### `attack_scenarios`

확인된 취약점 간 연관성을 기반으로 가능한 공격 흐름을 설명합니다.

```json
{
  "candidate_ref": "C001",
  "title": "내부 서비스 접근 가능성",
  "scenario_status": "possible",
  "confidence": "medium",
  "evidence_refs": [
    "F001",
    "F002"
  ],
  "related_vulnerability_types": [
    "ssrf",
    "authz"
  ],
  "related_endpoints": [
    "/pre-course/write"
  ],
  "scenario": "...",
  "potential_impact": "...",
  "required_conditions": "추가 검증 필요"
}
```

### `priority_actions`

조치 우선순위를 제공합니다.

```json
{
  "priority": 1,
  "title": "SSRF 취약점 우선 조치",
  "reason": "...",
  "related_finding_ids": [
    "F001"
  ]
}
```

### `vulnerability_analysis`

취약점 종류별 종합 분석입니다.

현재 대상:

```text
SQL Injection
Cross-Site Scripting (XSS)
Server-Side Request Forgery (SSRF)
Authorization
File I/O
```

### `general_recommendations`

전체 시스템 관점의 보안 개선 권고사항입니다.

---

## 11. API 중복 호출 방지

Scan Result 전체를 대상으로 SHA-256 Hash를 생성합니다.

```text
scan_result.json
        ↓
SHA-256
        ↓
source_hash
```

AI 분석 결과에 다음과 같이 저장됩니다.

```json
{
  "source_hash": "..."
}
```

동일한 결과 파일을 다시 분석하는 경우 Hash를 비교합니다.

```text
현재 Scan Hash == 기존 source_hash
                ↓
        OpenAI API 호출 안 함
                ↓
        기존 ai_analysis.json 사용
```

따라서 Streamlit Dashboard를 새로고침하더라도 동일한 Scan Result에 대해 API가 반복 호출되는 것을 방지할 수 있습니다.

다시 분석해야 하는 경우:

```bash
python ai_analyzer.py scan_result.json --force
```

를 사용합니다.

---

## 12. 전체 처리 과정

```text
Integrated Scanner
        │
        ▼
scan_result.json
        │
        ▼
검증된 취약점 추출
        │
        ├─ Finding ID 생성
        │
        ├─ 통계 계산
        │
        └─ Scenario Candidate 생성
        │
        ▼
OpenAI API
        │
        ├─ 종합 총평
        ├─ 주요 취약점 분석
        ├─ 공격 시나리오 설명
        ├─ 우선 조치
        └─ 보안 권고
        │
        ▼
AI 결과 검증
        │
        ├─ Finding ID 검증
        ├─ Candidate 검증
        ├─ Endpoint 검증
        └─ Vulnerability Type 검증
        │
        ▼
ai_analysis.json
        │
        ▼
Streamlit Dashboard
```

## 13. 역할 분리

각 모듈의 역할은 다음과 같습니다.

```text
Sink Point Scanner
→ Crawling + Regex 기반 Endpoint 및 Parameter 수집

AI Orchestrator
→ 적절한 취약점 Scanner 선택 및 호출

Vulnerability Scanner
→ 실제 취약점 검증

AI Analyzer
→ Scanner 결과 분석 및 설명

Streamlit Dashboard
→ 결과 시각화
```

AI Analyzer는 취약점을 직접 탐지하지 않으며, 실제 Scanner가 생성한 결과를 기반으로 분석 및 설명을 수행합니다.