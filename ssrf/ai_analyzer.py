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

아래 SSRF Scanner가 수집한
HTTP 요청 및 응답 데이터를 분석하세요.

[진단 데이터]

{json.dumps(
    data,
    ensure_ascii=False,
    indent=2
)}

판정 기준:

1. 정상적인 외부 URL 요청 결과를
   기준으로 삼습니다.

2. 내부 테스트 URL 요청 결과와
   비교합니다.

3. 내부 테스트 서비스의 응답 내용이
   반환되었거나 서버가 내부 서비스에
   요청한 정황이 HTTP 응답에서 확인되면
   VULNERABLE로 판단합니다.

4. 단순히 HTTP 상태 코드가 200이라는
   이유만으로 SSRF라고 판단하지 않습니다.

5. HTTP 응답만으로 취약점을 확인할 수 없는
   경우 N/A로 판단합니다.

6. 확인되지 않은 사실을 추측해서
   VULNERABLE로 판단하지 않습니다.

다음 JSON 형식으로만 응답하세요.

{{
    "result":
        "VULNERABLE 또는 SAFE 또는 N/A",

    "severity":
        "HIGH 또는 MEDIUM 또는 LOW 또는 INFO",

    "evidence":
        "판정 근거",

    "reason":
        "상세 분석 내용"
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
            "result": "N/A",

            "severity": "INFO",

            "evidence":
                "AI 분석 중 오류가 발생했습니다.",

            "reason":
                str(e)
        }