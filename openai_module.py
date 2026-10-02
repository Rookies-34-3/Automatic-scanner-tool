"""Sink 결과를 바탕으로 module/의 취약점 함수를 function call로 선택할 모듈.

SQLi, XSS, File I/O 등의 함수를 tool로 등록하고 호출 결과를 수집할 예정이다.
구현은 다음 단계에서 추가한다.
"""

import json
from copy import deepcopy
from pathlib import PurePosixPath
from urllib.parse import urlsplit


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
    # 네트워크 없이 ID 집계, 입력 차이 보존, 원본 보존을 확인한다.
    base = "http://127.0.0.1:8080"
    sinks = [{"url": f"{base}/items/{item_id}", "method": "GET", "endpoint_template": "/items/{id}",
              "parameters": [{"name": "path_id_1", "location": "path", "value": str(item_id)}],
              "sink_candidates": [{"type": "idor", "tools": ["authz"], "verified": False}],
              "crawl_state": "not_visited" if item_id == 1 else "visited"}
             for item_id in range(1, 5)]
    secret = deepcopy(sinks[1])
    secret["url"] += "?secret=1"
    secret["parameters"].append({"name": "secret", "location": "query"})
    upload = deepcopy(sinks[1])
    upload.update(method="POST", enctype="multipart/form-data", crawl_state="discovered")
    upload["parameters"].append({"name": "file", "location": "form", "input_type": "file", "required": True})
    upload["parameters"].extend({"name": "action", "location": "form", "value": action}
                                for action in ("preview", "save"))
    patch = deepcopy(sinks[1])
    patch.update(method="PATCH", crawl_state="discovered")
    patch["parameters"].append({"name": "email", "location": "json"})
    other_origin = deepcopy(sinks[0])
    other_origin["url"] = other_origin["url"].replace(":8080", ":8081")
    sinks.extend([secret, upload, patch, other_origin])
    for path, tools in (("/uploads/2/pbl/a.txt", ["authz", "fileio"]),
                        ("/uploads/3/pbl/b.TXT", ["authz", "fileio"]),
                        ("/uploads/2/pbl/a.py", ["authz", "fileio"]),
                        ("/uploads/2/task/a.txt", ["authz", "fileio"]),
                        ("/uploads/2/pbl/", ["authz", "fileio"]),
                        ("/uploads/2/pbl/c.txt", ["fileio"])):
        sinks.append({"url": base + path, "method": "GET",
                      "endpoint_template": path.replace("/2/", "/{id}/").replace("/3/", "/{id}/"),
                      "parameters": [], "sink_candidates": [{"tools": tools, "verified": False}]})
    original = deepcopy(sinks)
    payload = prepare_sinks_for_openai(sinks)
    grouped = payload["groups"]
    assert payload["candidate_status"] == "unverified"
    assert len(grouped) == 9 and sum(group["discovered_count"] for group in grouped) == len(sinks)
    get_group = grouped[0]
    assert get_group["discovered_count"] == 5 and get_group["candidate_tools"] == ["authz"]
    assert len(get_group["request_variants"]) == 2
    plain, flagged = get_group["request_variants"]
    assert plain["sample_url"] == f"{base}/items/2" and flagged["sample_url"].endswith("?secret=1")
    assert "value" not in plain["parameters"][0] and any(p["name"] == "secret" for p in flagged["parameters"])
    upload_variant = grouped[1]["request_variants"][0]
    assert upload_variant["enctype"] == "multipart/form-data"
    assert {p.get("value") for p in upload_variant["parameters"] if p["name"] == "action"} == {"preview", "save"}
    assert any(p.get("input_type") == "file" and p["required"] for p in upload_variant["parameters"])
    assert grouped[2]["method"] == "PATCH" and sinks == original
    assert ":8081/" in grouped[3]["request_variants"][0]["sample_url"]
    assert grouped[4]["path_template"] == "/uploads/{id}/pbl/{filename}.txt" and grouped[4]["discovered_count"] == 2
    assert grouped[5]["path_template"].endswith("{filename}.py")
    assert grouped[6]["path_template"] == "/uploads/{id}/task/{filename}.txt"
    assert grouped[7]["path_template"] == "/uploads/{id}/pbl/"
    assert grouped[8]["candidate_tools"] == ["fileio"]
    assert all("sample_urls" not in g and all("samples" not in v for v in g["request_variants"]) for g in grouped)
    plain["parameters"][0]["name"] = "test"
    assert sinks == original
    assert prepare_sinks_for_openai([]) == {"candidate_status": "unverified", "groups": []}
    try:
        prepare_sinks_for_openai(None)
    except ValueError:
        pass
    else:
        raise AssertionError("None 수집 결과가 거부되지 않았습니다.")
    print("openai_module self-check passed")
