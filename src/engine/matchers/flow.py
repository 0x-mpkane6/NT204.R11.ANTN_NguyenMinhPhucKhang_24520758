def match_flow(requirements, flow, allow_inferred):
    if not requirements:
        return True
    if not isinstance(flow, dict):
        return False
    for item in requirements:
        if item in ('to_server', 'to_client'):
            if flow.get('service_direction') != item:
                return False
        elif item == 'established':
            if flow.get('established') is not True:
                return False
            if not allow_inferred and flow.get('established_source') != 'observed_handshake':
                return False
        elif item == 'not_established':
            if flow.get('established') is not False:
                return False
        else:
            return False
    return True
