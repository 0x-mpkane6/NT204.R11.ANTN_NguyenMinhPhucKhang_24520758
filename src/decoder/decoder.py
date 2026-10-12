from copy import deepcopy

from .http_decoder import decode_http
from .smtp_decoder import decode_smtp


def decode_event(event, max_field_bytes=1048576):
    if not isinstance(max_field_bytes, int) or max_field_bytes <= 0:
        raise ValueError('max_field_bytes must be a positive integer')
    if not isinstance(event, dict):
        return {'decode_status': 'error', 'decode_errors': ['invalid_event'], 'decoded': {}}
    result = deepcopy(event)
    errors = []
    decoded = {}
    status = 'skipped'
    try:
        application = event.get('application') or {}
        protocol = application.get('protocol', '').upper()
        decoder = {'HTTP': decode_http, 'SMTP': decode_smtp}.get(protocol)
        if decoder:
            decoded = decoder(application, max_field_bytes, errors)
            status = 'success' if decoded else 'skipped'
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        errors.append('invalid_application_fields:' + type(exc).__name__)
    if errors:
        status = 'partial' if decoded else 'error'
    result.update(decoded=decoded, decode_status=status, decode_errors=list(dict.fromkeys(errors)))
    return result
