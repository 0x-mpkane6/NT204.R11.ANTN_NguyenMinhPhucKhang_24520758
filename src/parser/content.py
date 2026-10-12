import base64
from email.message import Message


def raw_base64(data):
    return base64.b64encode(data).decode('ascii')


def content_metadata(headers):
    message = Message()
    for name in ('content-type', 'content-transfer-encoding'):
        for value in headers.get(name, []):
            message[name] = value
    return {
        'content_type': message.get_content_type() if headers.get('content-type') else None,
        'charset': message.get_content_charset(),
        'content_transfer_encoding': str(message.get('Content-Transfer-Encoding', '')).strip().lower() or None,
    }
