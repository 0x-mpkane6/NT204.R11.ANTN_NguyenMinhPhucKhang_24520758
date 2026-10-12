import base64
import re
from urllib.parse import unquote_to_bytes


class DecodeError(ValueError):
    pass


def raw_bytes(value, limit):
    if not isinstance(value, str):
        raise DecodeError('missing_or_invalid_raw_base64')
    if len(value) > 4 * ((limit + 2) // 3):
        raise DecodeError('size_limit_exceeded')
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError('invalid_raw_base64') from exc
    if len(data) > limit:
        raise DecodeError('size_limit_exceeded')
    return data


def text(data, charset, errors):
    charset = (charset or 'utf-8').lower()
    aliases = {'utf8': 'utf-8', 'us-ascii': 'ascii'}
    charset = aliases.get(charset, charset)
    if charset not in ('ascii', 'utf-8'):
        raise DecodeError('unsupported_charset:' + charset)
    try:
        return data.decode(charset)
    except UnicodeDecodeError:
        errors.append('invalid_character_bytes:' + charset)
        return data.decode(charset, errors='replace')


def percent(data, errors, form=False):
    if re.search(rb'%(?![0-9a-fA-F]{2})', data):
        errors.append('invalid_percent_escape')
    return unquote_to_bytes(data.replace(b'+', b' ') if form else data)
