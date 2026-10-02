"""AI 검증(triage) 레이어 - OpenAI 기반.

1단계(고정 규칙) 가 찾은 '의심' 결과를, 스캐너가 수집한 사실을 근거로
AI 가 '진짜 취약점인지' 재판정한다. (AI 가 제안, 사실이 근거)

키는 환경변수 OPENAI_API_KEY 또는 프로젝트 루트의 .env 에서만 읽는다.
코드/설정 파일에는 절대 키를 넣지 않는다.
의존성 없이 requests 로 OpenAI Chat Completions API 를 호출한다.
키가 없거나 호출 실패 시 None 을 반환 → 원래(1단계) 판정을 그대로 둔다.
"""
import os
import json
import requests

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = (
    "너는 웹 '파일 업로드/다운로드' 취약점 결과를 검토하는 보안 전문가다. "
    "자동 스캐너의 1차 '의심' 결과와, 스캐너가 실제로 관찰한 '사실(observed_facts)'을 준다. "
    "오직 주어진 사실에만 근거해 판정하라. 사실에 없는 영향을 추측으로 지어내지 마라.\n"
    "\n"
    "기본 태도: 보수적으로 판정한다. 사실이 '실질적 공격 영향'을 분명히 보여줄 때만 "
    "VULNERABLE 로 올린다. 영향이 불확실하거나 완화요인이 있으면 과대평가하지 말고 "
    "POTENTIAL(수동확인 필요) 또는 SAFE 로 둔다. 1차 판정을 근거 없이 상향하지 마라.\n"
    "\n"
    "유형별 판단 기준:\n"
    "- 업로드(확장자/이중확장자/MIME/매직바이트/CRLF): 위험 파일이 '수락'된 것만으로는 "
    "HIGH 가 아니다. served_content_type 이 application/octet-stream 이고 "
    "served_inline=false(=attachment 강제)면 브라우저 실행·저장형 XSS 가 불가하므로 "
    "실질 위험이 낮다 → POTENTIAL/LOW. 서버가 그 파일을 '코드로 실행'하거나 "
    "'inline(text/html, image/svg+xml 등)으로 렌더'할 수 있다는 사실이 있을 때만 HIGH.\n"
    "- 파일명 경로조작/CRLF: stored_filename 이 정규화되어 경로구분자/제어문자가 제거됐으면 "
    "SAFE/LOW. 저장명에 실제로 남아있을 때만 위험.\n"
    "- 경로순회/LFI: 응답에 실제 시스템 파일 내용(root:x:0:0 등)이 나왔을 때만 VULNERABLE.\n"
    "- IDOR/권한/열거: '원래 접근하면 안 되는 자원인데 뚫렸는지'가 핵심. "
    "attacker_sees_download_link=true 등 공격자가 정상 UI 로 접근 가능하면 공유/공개 "
    "자원이므로 SAFE(IDOR 아님). 정상 UI 로 접근 불가한데 직접 ID/경로로 뚫렸을 때만 "
    "VULNERABLE. UI 가시성 정보가 사실에 없으면 단정하지 말고 POTENTIAL 로 둔다.\n"
    "\n"
    'JSON 으로만 답하라: {"verdict":"VULNERABLE|POTENTIAL|SAFE",'
    '"severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","reason":"한국어 한두 문장 근거(어떤 사실 때문인지 명시)"}'
)


def _load_env_key():
    """OPENAI_API_KEY: 환경변수 우선, 없으면 .env 파일에서 파싱."""
    key = os.environ.get("OPENAI_API_KEY")
    if key:
        return key.strip()
    # 프로젝트 루트(.env) 간단 파서 (python-dotenv 의존성 없이)
    for path in (".env", os.path.join(os.path.dirname(__file__), "..", ".env")):
        try:
            with open(path, encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if line.startswith("OPENAI_API_KEY") and "=" in line:
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            continue
    return None


def available(cfg=None):
    """AI 검증을 쓸 수 있는 상태인지(설정 on + 키 존재)."""
    ai_cfg = (cfg or {}).get("ai", {})
    if ai_cfg.get("enabled") is False:
        return False
    return bool(_load_env_key())


def judge_finding(finding: dict, cfg=None):
    """단일 finding 을 AI 로 재판정. 성공 시 {verdict,severity,reason}, 실패 시 None."""
    key = _load_env_key()
    if not key:
        return None
    model = (cfg or {}).get("ai", {}).get("model", DEFAULT_MODEL)

    # 관찰된 사실만 AI 에 전달. 내부 메모/설명성 키는 제외(AI 오판 방지).
    INTERNAL_KEYS = {"note", "payload_description", "source", "stage1_result",
                     "stage1_severity", "stage1_evidence", "ai_verdict",
                     "ai_severity", "ai_reason", "ai_changed", "ai_error"}
    observed = {k: v for k, v in (finding.get("details") or {}).items()
                if k not in INTERNAL_KEYS}
    facts = {
        "category": finding.get("category"),
        "target_url": finding.get("target_url"),
        "method": finding.get("method"),
        "payload": finding.get("payload"),
        "status_code": finding.get("status_code"),
        "stage1_result": finding.get("result"),
        "stage1_evidence": finding.get("evidence"),
        "observed_facts": observed,
    }
    user_msg = ("다음은 스캐너의 1차 판정과 관찰 사실이다. 진짜 취약점인지 판정하라:\n"
                + json.dumps(facts, ensure_ascii=False, indent=2))

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    try:
        r = requests.post(OPENAI_URL, json=body, timeout=30,
                          headers={"Authorization": f"Bearer {key}"})
        if r.status_code != 200:
            return {"error": f"OpenAI {r.status_code}: {r.text[:120]}"}
        content = r.json()["choices"][0]["message"]["content"]
        out = json.loads(content)
        verdict = str(out.get("verdict", "")).upper()
        if verdict not in ("VULNERABLE", "POTENTIAL", "SAFE"):
            return {"error": f"알 수 없는 verdict: {verdict}"}
        return {
            "verdict": verdict,
            "severity": str(out.get("severity", "INFO")).upper(),
            "reason": out.get("reason", ""),
        }
    except Exception as e:
        return {"error": f"AI 호출 오류: {e}"}
