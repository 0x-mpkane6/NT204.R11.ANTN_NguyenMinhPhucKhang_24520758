import base64
import ipaddress
from copy import deepcopy
from datetime import datetime


def build_context(event, max_buffer_bytes=1048576):
    if type(max_buffer_bytes) is not int or max_buffer_bytes <= 0:
        raise ValueError('max_buffer_bytes must be a positive integer')
    context = {'context_status': 'invalid', 'context_errors': [], 'buffers': {},
               'payload_size': None, 'flow': None}
    errors = context['context_errors']
    try:
        if event.get('preprocess_status') == 'invalid' or event.get('processing_action') == 'drop':
            raise ValueError('rejected_by_preprocessor')
        data = event['normalized']
        network, transport = data['network'], data['transport']
        protocol = transport['protocol']
        if protocol not in ('TCP', 'UDP'):
            raise ValueError('unsupported_transport')
        context.update(packet_id=event.get('packet_id'), timestamp=data['timestamp'],
                       protocol=protocol, application_protocol=data.get('application', {}).get('protocol', 'UNKNOWN'),
                       tcp_flags=transport.get('flags') if protocol == 'TCP' else None)
        if datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')).tzinfo is None:
            raise ValueError('timestamp_missing_timezone')
        for side in ('src', 'dst'):
            context[side + '_ip'] = str(ipaddress.ip_address(network[side + '_ip']))
            port = transport[side + '_port']
            if type(port) is not int or not 0 <= port <= 65535:
                raise ValueError('invalid_port')
            context[side + '_port'] = port
        size = transport.get('payload_length')
        if type(size) is not int or size < 0:
            errors.append('missing_or_invalid_payload_length')
        else:
            context['payload_size'] = size
        raw = transport.get('raw_payload_base64')
        if not isinstance(raw, str):
            errors.append('missing_raw_payload')
        elif len(raw) > 4 * ((max_buffer_bytes + 2) // 3):
            errors.append('payload_buffer_limit')
        else:
            try:
                payload = base64.b64decode(raw, validate=True)
                if len(payload) > max_buffer_bytes:
                    errors.append('payload_buffer_limit')
                elif size != len(payload):
                    errors.append('payload_length_mismatch')
                else:
                    context['buffers']['payload'] = payload
            except (ValueError, UnicodeError):
                errors.append('invalid_payload_base64')
        decoded = event.get('decoded') or {}
        for field, name in (('uri', 'http.uri.decoded'), ('body', protocol.lower() + '.body.decoded')):
            if field == 'body':
                name = context['application_protocol'].lower() + '.body.decoded'
            value = decoded.get(field)
            if isinstance(value, str):
                encoded = value.encode('utf-8')
                if len(encoded) <= max_buffer_bytes:
                    context['buffers'][name] = encoded
                else:
                    errors.append('decoded_buffer_limit:' + name)
        flow = event.get('flow')
        if flow is not None and not isinstance(flow, dict):
            errors.append('invalid_flow_context')
        else:
            context['flow'] = deepcopy(flow)
        context['context_status'] = 'partial' if errors else 'valid'
    except (AttributeError, TypeError, KeyError, ValueError, OverflowError) as exc:
        errors.append('invalid_event:' + str(exc))
    return context
