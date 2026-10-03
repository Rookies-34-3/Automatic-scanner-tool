import socket
from urllib.parse import urlparse


DEFAULT_PORTS = [80]
DEFAULT_ALLOWED_PORTS = [80]
DEFAULT_TIMEOUT = 1.0


def _extract_host(url):
    """URL에서 host를 추출한다."""
    parsed = urlparse(url)

    if parsed.hostname:
        return parsed.hostname

    parsed = urlparse(f"//{url}")
    return parsed.hostname


def _check_port(host, port, timeout):
    """TCP 연결을 시도하여 포트의 접근 가능 여부를 확인한다."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True

    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def _normalize_ports(port_list):
    """포트 목록을 검증하고 중복을 제거한다."""
    result = []

    if not isinstance(port_list, list):
        return None

    for port in port_list:
        try:
            port = int(port)

            if not 1 <= port <= 65535:
                return None

            result.append(port)

        except (TypeError, ValueError):
            return None

    return list(dict.fromkeys(result))


def run(url, method, parameters, cookie):
    """
    TCP Port Scan

    parameters:
        {
            "ports": [80],
            "allowed_ports": [80],
            "timeout": 1
        }

    반환:
        url
        method
        parameters
        vuln
        result
        status_code
        details
    """

    if parameters is None:
        parameters = {}

    if not isinstance(parameters, dict):
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "parameters는 객체(dict) 형태여야 합니다.",
            "status_code": None,
            "details": {
                "reason": "invalid_parameters"
            }
        }

    ports = parameters.get("ports", DEFAULT_PORTS)
    allowed_ports = parameters.get(
        "allowed_ports",
        DEFAULT_ALLOWED_PORTS
    )
    timeout = parameters.get(
        "timeout",
        DEFAULT_TIMEOUT
    )

    normalized_ports = _normalize_ports(ports)

    if not normalized_ports:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "검사할 포트 목록(ports)이 올바르지 않습니다.",
            "status_code": None,
            "details": {
                "reason": "invalid_ports",
                "ports": ports
            }
        }

    normalized_allowed_ports = _normalize_ports(
        allowed_ports
    )

    if normalized_allowed_ports is None:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "허용 포트 목록(allowed_ports)이 올바르지 않습니다.",
            "status_code": None,
            "details": {
                "reason": "invalid_allowed_ports",
                "allowed_ports": allowed_ports
            }
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
            "result": "timeout은 0보다 큰 숫자여야 합니다.",
            "status_code": None,
            "details": {
                "reason": "invalid_timeout",
                "timeout": timeout
            }
        }

    host = _extract_host(url)

    if not host:
        return {
            "url": url,
            "method": method,
            "parameters": parameters,
            "vuln": "N/A",
            "result": "URL에서 호스트를 확인할 수 없습니다.",
            "status_code": None,
            "details": {
                "reason": "invalid_host"
            }
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

    details = {
        "host": host,
        "scanned_ports": normalized_ports,
        "open_ports": open_ports,
        "allowed_ports": normalized_allowed_ports,
        "unexpected_ports": unexpected_ports,
        "timeout": timeout
    }

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
            ),
            "status_code": None,
            "details": details
        }

    return {
        "url": url,
        "method": method,
        "parameters": parameters,
        "vuln": "SAFE",
        "result": (
            f"접근 가능한 포트: {open_ports}. "
            f"허용되지 않은 포트가 확인되었습니다: "
            f"{unexpected_ports}"
        ),
        "status_code": None,
        "details": details
    }