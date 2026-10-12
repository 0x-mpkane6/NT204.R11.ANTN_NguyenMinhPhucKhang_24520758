import base64
import quopri
import re

from .common import DecodeError, raw_bytes, text


def decode_smtp(application, limit, errors):
    mime = application.get('mime')
    if not mime:
        return {}
    decoded = {}
    try:
        if mime.get('status') == 'limit_exceeded':
            raise DecodeError('size_limit_exceeded')
        if (mime.get('content_type') or '').startswith('multipart/'):
            raise DecodeError('multipart_not_supported')
        body = raw_bytes(mime.get('raw_body_base64'), limit)
        encoding = (mime.get('content_transfer_encoding') or '7bit').lower()
        if encoding == 'base64':
            try:
                body = base64.b64decode(re.sub(rb'[\t\r\n ]', b'', body), validate=True)
            except ValueError as exc:
                raise DecodeError('invalid_mime_base64') from exc
        elif encoding == 'quoted-printable':
            if re.search(rb'=(?![0-9A-Fa-f]{2}|\r\n|\n)', body):
                errors.append('invalid_quoted_printable_escape')
            body = quopri.decodestring(body)
        elif encoding not in ('7bit', '8bit', 'binary'):
            raise DecodeError('unsupported_transfer_encoding:' + encoding)
        decoded['body_base64'] = base64.b64encode(body).decode('ascii')
        content_type = mime.get('content_type') or 'text/plain'
        if content_type.startswith('text/'):
            decoded['body'] = text(body, mime.get('charset') or 'ascii', errors)
        if mime.get('status') == 'partial' or mime.get('errors'):
            errors.append('incomplete_or_invalid_mime_message')
    except DecodeError as exc:
        errors.append(str(exc))
    return decoded
