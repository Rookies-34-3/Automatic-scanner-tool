# Vulnerability Scan Dashboard

통합 취약점 스캐너 JSON 결과를 Streamlit에서 조회하고 OpenAI API로 분석하는 대시보드입니다.

## 설치

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## API Key 설정

Linux / WSL:

```bash
export OPENAI_API_KEY="YOUR_KEY"
```

PowerShell:

```powershell
$env:OPENAI_API_KEY="YOUR_KEY"
```

선택적으로 모델을 변경할 수 있습니다.

```bash
export OPENAI_MODEL="gpt-6-luna"
```

## 실행

```bash
streamlit run app.py
```

사이드바에서 `sample_scan_result.json` 형식의 통합 결과 JSON을 업로드합니다.

## 통합 결과 핵심 구조

```json
{
  "summary": {},
  "results": [
    {
      "url": "...",
      "method": "POST",
      "scanner": "ssrf",
      "status": "completed",
      "vulnerable": true,
      "findings": [
        {
          "type": "SSRF",
          "severity": "HIGH",
          "parameter": "url",
          "payload": "...",
          "evidence": "...",
          "description": "...",
          "recommendation": "..."
        }
      ]
    }
  ]
}
```

AI 분석에 전달하기 전에 쿠키, 토큰, 비밀번호, API Key 등 민감 필드는 자동으로 `[REDACTED]` 처리합니다.
