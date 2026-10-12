def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def validate_transport(network, transport, errors, partial):
    if transport['protocol'] not in ('TCP', 'UDP'):
        partial.append('unsupported_transport')
        return
    for field in ('src_port', 'dst_port'):
        if not integer(transport.get(field), 0, 65535):
            errors.append('transport.' + field + ':invalid_or_missing')
    expected = 6 if transport['protocol'] == 'TCP' else 17
    if network.get('protocol') is not None and network['protocol'] != expected:
        errors.append('transport_protocol_mismatch')
    if transport['protocol'] == 'TCP':
        flags = transport.get('flags')
        if flags is None:
            partial.append('transport.flags:missing')
        elif not isinstance(flags, str) or any(flag not in 'FSRPAUECN' for flag in flags):
            errors.append('transport.flags:invalid')
