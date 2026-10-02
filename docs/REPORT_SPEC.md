# ROOKIESCAN 보고서 형태

`report_writer.py`는 각 취약점 모듈의 결과를 다음 세 부분으로 정리한다.

## 1. 점검 요약

- 대상 URL
- 점검 시간
- 실행한 취약점 모듈
- 취약점, 확인 필요, 정상, 오류 건수

## 2. 취약점 상세

각 결과는 다음 값을 가진다.

```text
module
name
url
method
parameter
result
severity
evidence
remediation
```

## 3. 실행 정보

- Sink 탐색 결과
- 실행하지 못한 검사와 이유
- 모듈 실행 중 발생한 오류

기준 결과는 JSON으로 보관한다. Streamlit 화면과 HTML 보고서는 같은 JSON을 보기 좋게
표현한다. 비밀번호, 세션 쿠키, API 키는 보고서에 저장하지 않는다.
