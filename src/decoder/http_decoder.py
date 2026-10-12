import html

from .common import DecodeError, percent, raw_bytes, text


def decode_http(application, limit, errors):
    decoded = {}
    if 'raw_uri_base64' in application:
        try:
            uri = raw_bytes(application['raw_uri_base64'], limit)
            decoded['uri'] = text(percent(uri, errors), 'utf-8', errors)
        except DecodeError as exc:
            errors.append(str(exc))
    content_type = (application.get('content_type') or '').lower()
    headers = application.get('headers') or {}
    if headers.get('transfer-encoding') or any(
        value.lower() != 'identity' for value in headers.get('content-encoding', [])
    ):
        errors.append('unsupported_http_body_encoding')
        return decoded
    if content_type != 'application/x-www-form-urlencoded' and not content_type.startswith('text/'):
        return decoded
    try:
        body = raw_bytes(application.get('raw_body_base64'), limit)
        charset = application.get('charset')
        if content_type == 'application/x-www-form-urlencoded':
            fields = []
            for field in body.split(b'&') if body else []:
                name, _, value = field.partition(b'=')
                fields.append({'name': text(percent(name, errors, True), charset, errors),
                               'value': text(percent(value, errors, True), charset, errors)})
            decoded['form_fields'] = fields
        else:
            decoded['body'] = text(body, charset, errors)
            decoded['html_text'] = html.unescape(decoded['body'])
        if application.get('errors') or application.get('headers_complete') is False:
            errors.append('incomplete_or_invalid_http_message')
    except DecodeError as exc:
        errors.append(str(exc))
    return decoded
