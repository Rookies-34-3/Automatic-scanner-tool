import json

from openai import OpenAI

from config import OPENAI_API_KEY


client = OpenAI(
    api_key=OPENAI_API_KEY
)


def analyze_ssrf(data):

    prompt = f"""
당신은 웹 취약점 자동 진단 시스템의
보안 분석 AI입니다.

아래 SSRF Scanner가 수집한 데이터를 분석하세요.

[진단 데이터]

{json.dumps(
    data,
    ensure_ascii=False,
    indent=4
)}

판정 기준:

1. 정상적인 외부 URL 요청 결과와
   SSRF Verifier 테스트 결과를 함께 확인합니다.

2. SSRF Verifier의 verifier_evidence.received가
   true이고, path가 /check/<verification_id>로
   확인되면 대상 서버가 검증 서버에 실제로
   서버 측 요청을 보낸 명확한 증거로 봅니다.
   이 경우 VULNERABLE로 판단합니다.

3. verifier_evidence.received가 false이면
   HTTP 응답만으로 SSRF가 확인되지 않는 경우
   VULNERABLE로 판단하지 않습니다.

4. 단순히 HTTP 상태 코드가 200이라는
   이유만으로 VULNERABLE로 판단하지 않습니다.

5. 취약점 여부를 확인할 충분한 근거가 없으면
   N/A로 판단합니다.

6. 확인되지 않은 사실을 추측하지 않습니다.

다음 JSON 형식으로만 응답하세요.

{{
    "vuln": "VULNERABLE 또는 SAFE 또는 N/A",
    "result": "판정 근거"
}}
"""

    try:

        response = client.responses.create(
            model="gpt-5.6",
            input=prompt
        )

        result_text = response.output_text

        return json.loads(
            result_text
        )

    except Exception as e:

        return {
            "vuln": "N/A",
            "result":
                f"AI 분석 오류: {str(e)}"
        }