"""Sink 결과를 바탕으로 module/의 취약점 함수를 function call로 선택할 모듈.

SQLi, XSS, File I/O 등의 함수를 tool로 등록하고 호출 결과를 수집할 예정이다.
구현은 다음 단계에서 추가한다.
"""

import json
import os
from copy import deepcopy
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from dotenv import load_dotenv
from openai import OpenAI


def get_openai_client() -> OpenAI:
    """프로젝트 루트의 .env에서 API 키를 읽어 OpenAI 클라이언트를 만든다."""
    # Streamlit을 재시작하지 않아도 .env에서 수정한 키를 읽는다.
    load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("프로젝트 루트의 .env 파일에 OPENAI_API_KEY를 입력하세요.")
    return OpenAI(api_key=api_key)


def prepare_sinks_for_openai(sinks: list[dict]) -> dict:
    """원본을 유지하고 같은 출처·메서드·경로 템플릿의 전달용 요약을 만든다."""
    if not isinstance(sinks, list):
        raise ValueError("Sink 수집 결과가 올바른 목록이 아닙니다. 수집을 다시 실행하세요.")
    groups = {}
    for endpoint in sinks:
        parts = urlsplit(endpoint["url"])
        base_url = f"{parts.scheme}://{parts.netloc}"
        method = endpoint["method"].upper()
        template = endpoint["endpoint_template"]
        tools = sorted({tool for candidate in endpoint.get("sink_candidates", [])
                        for tool in candidate.get("tools", [])})
        upload_file = parts.path.startswith("/uploads/") and not parts.path.endswith("/")
        if upload_file:
            directory = template.rsplit("/", 1)[0]
            extension = PurePosixPath(parts.path).suffix.lower()
            template = f"{directory}/{{filename}}{extension}"
        key = (base_url, method, template, tuple(tools) if upload_file else None)
        group = groups.setdefault(key, {
            "method": method, "path_template": template,
            "discovered_count": 0, "request_variants": {},
        })

        parameters = deepcopy(endpoint["parameters"])
        for parameter in parameters:
            if parameter.get("location") == "path":
                parameter.pop("value", None)
        shape = {
            "parameters": sorted(parameters, key=lambda item: json.dumps(item, sort_keys=True)),
            "candidate_tools": tools,
        }
        if endpoint.get("enctype"):
            shape["enctype"] = endpoint["enctype"]
        # 입력 형태와 후보 tool이 다른 요청은 구분한다.
        shape_key = json.dumps(shape, sort_keys=True, ensure_ascii=False)
        rank = (endpoint.get("crawl_state") != "visited", bool(endpoint.get("error")))
        variant = group["request_variants"].setdefault(shape_key, {
            **shape, "sample_url": endpoint["url"], "_sample_rank": rank,
        })
        group["discovered_count"] += 1
        if rank < variant["_sample_rank"]:
            variant.update(sample_url=endpoint["url"], _sample_rank=rank)

    for group in groups.values():
        group["request_variants"] = list(group["request_variants"].values())
        group["candidate_tools"] = sorted({
            tool for variant in group["request_variants"] for tool in variant["candidate_tools"]
        })
        for variant in group["request_variants"]:
            variant.pop("_sample_rank")
            if variant["candidate_tools"] == group["candidate_tools"]:
                variant.pop("candidate_tools")
    return {"candidate_status": "unverified", "groups": list(groups.values())}


if __name__ == "__main__":
    # 실행: python openai_module.py (.env의 키로 짧은 응답을 요청한다.)
    with get_openai_client().with_options(timeout=30, max_retries=0) as client:
        response = client.responses.create(
            model="gpt-6.1-sol",
            input="Reply with exactly OK.",
            reasoning={"effort": "low"},
            max_output_tokens=256,
            store=False,
        )
        print("모델:", response.model)
        print("응답:", response.output_text)
