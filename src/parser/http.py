import re

from scapy.layers.inet import TCP

_REQUEST = re.compile(rb"([A-Z][A-Z0-9!#$%&'*+.^_`|~-]*) ([^\x00-\x20]+) HTTP/(1\.[01])")
_RESPONSE = re.compile(rb"HTTP/(1\.[01]) ([1-5][0-9]{2})(?: ([^\r\n]*))?")


def parse_http(packet):
    try:
        if not packet.haslayer(TCP):
            return None
        payload = bytes(packet[TCP].payload)
        first_line, newline, remainder = payload.partition(b"\r\n")
        request = _REQUEST.fullmatch(first_line)
        response = _RESPONSE.fullmatch(first_line)
        if not newline or not (request or response):
            return None
        result = {"protocol": "HTTP", "headers": {}, "errors": []}
        if request:
            method, target, version = request.groups()
            result.update(type="request", method=method.decode("ascii"),
                          uri=target.decode("utf-8", errors="replace"),
                          version="HTTP/" + version.decode("ascii"))
        else:
            version, code, reason = response.groups()
            result.update(type="response", version="HTTP/" + version.decode("ascii"),
                          status_code=int(code), reason=(reason or b"").decode("latin-1"))
        head, separator, body = remainder.partition(b"\r\n\r\n")
        if remainder.startswith(b"\r\n"):
            head, separator, body = b"", b"\r\n", remainder[2:]
        result["headers_complete"] = bool(separator)
        if not separator:
            result["errors"].append("incomplete_headers")
        for line in head.split(b"\r\n"):
            if not line:
                continue
            name, colon, value = line.partition(b":")
            if not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                result["errors"].append("invalid_header")
                continue
            key = name.decode("ascii").lower()
            result["headers"].setdefault(key, []).append(value.strip().decode("latin-1"))
        result["body"] = body.decode("utf-8", errors="replace")
        result["body_length"] = len(body)
        lengths = result["headers"].get("content-length", [])
        if lengths:
            if any(not re.fullmatch(r"[0-9]+", value) for value in lengths) or len(set(lengths)) != 1:
                result["errors"].append("invalid_content_length")
            else:
                result["content_length"] = int(lengths[0])
                if len(body) < result["content_length"]:
                    result["errors"].append("incomplete_body")
        return result
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        return None
