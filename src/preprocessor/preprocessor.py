from copy import deepcopy

from . import normalizer
from .validator import integer, validate_transport


def preprocess_event(event, invalid_policy='keep', unsupported_policy='keep'):
    if invalid_policy not in ('keep', 'drop') or unsupported_policy not in ('keep', 'drop'):
        raise ValueError('Policies must be keep or drop')
    result = deepcopy(event) if isinstance(event, dict) else {}
    errors = [] if isinstance(event, dict) else ['invalid_event']
    partial = []
    normalized = {}
    for section in ('network', 'transport', 'application'):
        value = result.get(section)
        if value is None:
            value = {}
            partial.append(section + ':missing')
        elif not isinstance(value, dict):
            errors.append(section + ':invalid_type')
            value = {}
        normalized[section] = deepcopy(value)
    network, transport, application = (normalized[key] for key in ('network', 'transport', 'application'))
    for field in ('src_ip', 'dst_ip'):
        try:
            network[field] = normalizer.address(network.get(field))
        except ValueError:
            network[field] = None
            errors.append('network.' + field + ':invalid_or_missing')
    try:
        normalized['timestamp'] = normalizer.timestamp(result.get('timestamp'))
    except (ValueError, OverflowError):
        normalized['timestamp'] = None
        errors.append('timestamp:invalid_or_missing')
    if network.get('protocol') is not None and not integer(network['protocol'], 0, 255):
        errors.append('network.protocol:invalid')
    for field in ('length', 'ttl', 'id'):
        value = network.get(field)
        network.setdefault(field, None)
        if value is None:
            partial.append('network.' + field + ':missing')
        elif not integer(value, 0, 255 if field == 'ttl' else 65535):
            errors.append('network.' + field + ':invalid')
    transport['protocol'] = normalizer.protocol(transport.get('protocol')) or 'UNKNOWN'
    for field in ('src_port', 'dst_port'):
        transport.setdefault(field, None)
    validate_transport(network, transport, errors, partial)
    application['protocol'] = normalizer.protocol(application.get('protocol')) or 'UNKNOWN'
    unsupported = transport['protocol'] not in ('TCP', 'UDP') or application['protocol'] not in ('HTTP', 'DNS', 'SMTP')
    if application['protocol'] not in ('HTTP', 'DNS', 'SMTP'):
        partial.append('unsupported_application')
    if application['protocol'] in ('HTTP', 'SMTP') and transport['protocol'] != 'TCP':
        errors.append('application_transport_mismatch')
    if application['protocol'] == 'HTTP':
        try:
            application['headers'] = normalizer.headers(application.get('headers'))
        except ValueError as exc:
            application['headers'] = {}
            errors.append(str(exc))
        application.setdefault('uri', None)
        application.setdefault('body', None)
        uri = application['uri']
        if uri is not None and (not isinstance(uri, str) or any(ord(c) < 32 or ord(c) == 127 for c in uri)):
            errors.append('http.uri:invalid')
    if application['protocol'] == 'DNS':
        for section in ('questions', 'answers', 'authorities', 'additionals'):
            records = application.get(section)
            if records is None:
                records = []
                partial.append('dns.' + section + ':missing')
            if not isinstance(records, list):
                records = []
                errors.append('dns.' + section + ':invalid')
            application[section] = records
            for record in records:
                if not isinstance(record, dict):
                    errors.append('dns.record:invalid')
                    continue
                try:
                    record['name'] = normalizer.domain(record.get('name'))
                    if record.get('type') in (2, 5, 12) and isinstance(record.get('data'), str):
                        record['data'] = normalizer.domain(record['data'])
                except ValueError:
                    errors.append('dns.name:invalid')
    if application['protocol'] == 'SMTP':
        application.setdefault('mime', None)
        if application.get('entries') is None:
            application['entries'] = []
        if not isinstance(application['entries'], list):
            errors.append('smtp.entries:invalid')
            application['entries'] = []
    if result.get('decode_status') in ('error', 'partial'):
        partial.append('decoder:' + result['decode_status'])
    if application.get('errors') or application.get('headers_complete') is False:
        partial.append('application:incomplete_or_invalid')
    status = 'invalid' if errors else 'partial' if partial else 'valid'
    action = 'drop' if (errors and invalid_policy == 'drop') or (unsupported and unsupported_policy == 'drop') else 'keep'
    result.update(normalized=normalized, preprocess_status=status,
                  processing_action=action, reason=list(dict.fromkeys(errors + partial)))
    return result
