from copy import deepcopy


def generate_detection(rule, context, match):
    if match.status != 'MATCH' or not match.complete or match.sid != rule.sid:
        raise ValueError('Detection requires a complete MATCH for the same SID')
    flow = context.get('flow') or {}
    return {
        'event_type': 'detection',
        'timestamp': context['timestamp'],
        'packet_id': context.get('packet_id'),
        'sid': rule.sid,
        'rev': rule.rev,
        'msg': rule.msg,
        'priority': rule.priority,
        'classtype': rule.classtype,
        'src_ip': context['src_ip'],
        'dst_ip': context['dst_ip'],
        'src_port': context['src_port'],
        'dst_port': context['dst_port'],
        'protocol': context['protocol'].upper(),
        'application_protocol': context.get('application_protocol', 'UNKNOWN'),
        'flow_id': flow.get('flow_id'),
        'match_info': {'status': 'MATCH', 'contents': deepcopy(match.matched)},
        'rule_source': rule.source,
        'rule_line': rule.line_number,
    }
