import ipaddress
from datetime import datetime, timezone


def protocol(value):
    return value.strip().upper() if isinstance(value, str) else None


def address(value):
    if not isinstance(value, str):
        raise ValueError('invalid_ip')
    return str(ipaddress.ip_address(value.strip()))


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('invalid_timestamp')
    parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamp_missing_timezone')
    return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def domain(value):
    if not isinstance(value, str):
        raise ValueError('invalid_domain')
    return value.lower().rstrip('.') + '.'


def headers(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError('invalid_headers')
    result = {}
    for name, values in value.items():
        if not isinstance(name, str):
            raise ValueError('invalid_header_name')
        values = [values] if isinstance(values, str) else values
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            raise ValueError('invalid_header_values')
        result.setdefault(name.lower(), []).extend(values)
    return result
