import socket
from urllib.parse import urlparse


DEFAULT_PORTS = [80]
DEFAULT_ALLOWED_PORTS = [80]
DEFAULT_TIMEOUT = 1.0


def _extract_host(url):
    """URL에서 호스트를 추출한다."""
    parsed = urlparse(url)

    if parsed.hostname:
        return parsed.hostname

    # scheme이 없는 입력도 지원
    parsed = urlparse(f"//{url}")
    return parsed.hostname


def _check_port(host, port, timeout):
    """TCP 연결을 시도하여 포트의 접근 가능 여부를 확인한다."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def run(url, method, parameters, cookie):
    """
    Port Scan

    기본 설정:
        검사 포트       : 80
        허용 포트       : 80
        연결 timeout    : 1초

    parameters로 검사 대상과 허용 포트를 변경할 수 있다.

    예:
        {
            "ports": [80, 8080],
            "allowed_ports": [80],
            "timeout": 1
        }
    """

    if parameters is None:
        parameters = {}

    if not isinstance(parameters, dict):
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "parameters는 객체(dict) 형태여야 합니다."
        }

    ports = parameters.get("ports", DEFAULT_PORTS)
    allowed_ports = parameters.get(
        "allowed_ports",
        DEFAULT_ALLOWED_PORTS
    )
    timeout = parameters.get("timeout", DEFAULT_TIMEOUT)

    if not isinstance(ports, list) or not ports:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "검사할 포트 목록(ports)이 지정되지 않았습니다."
        }

    if not isinstance(allowed_ports, list):
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "허용 포트 목록(allowed_ports)은 리스트여야 합니다."
        }

    try:
        timeout = float(timeout)

        if timeout <= 0:
            raise ValueError

    except (TypeError, ValueError):
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "timeout은 0보다 큰 숫자여야 합니다."
        }

    def normalize_ports(port_list):
        result = []

        for port in port_list:
            try:
                port = int(port)

                if not 1 <= port <= 65535:
                    raise ValueError

                result.append(port)

            except (TypeError, ValueError):
                return None

        return list(dict.fromkeys(result))

    normalized_ports = normalize_ports(ports)
    normalized_allowed_ports = normalize_ports(allowed_ports)

    if normalized_ports is None:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "잘못된 포트 번호가 포함되어 있습니다."
        }

    if normalized_allowed_ports is None:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "잘못된 허용 포트 번호가 포함되어 있습니다."
        }

    host = _extract_host(url)

    if not host:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "URL에서 호스트를 확인할 수 없습니다."
        }

    open_ports = []

    for port in normalized_ports:
        if _check_port(host, port, timeout):
            open_ports.append(port)

    unexpected_ports = [
        port
        for port in open_ports
        if port not in normalized_allowed_ports
    ]

    if unexpected_ports:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "VULNERABLE",
            "result": (
                f"접근 가능한 포트: {open_ports}. "
                f"허용되지 않은 포트가 확인되었습니다: "
                f"{unexpected_ports}"
            )
        }

    return {
        "url": url,
        "method": method,
        "parameters": parameters,
        "vuln": "SAFE",
        "result": (
            f"접근 가능한 포트: {open_ports}. "
            f"허용되지 않은 포트가 확인되었습니다: {unexpected_ports}"
)
    }