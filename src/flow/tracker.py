import ipaddress
import math
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


class FlowTracker:
    def __init__(self, tcp_timeout=120, udp_timeout=30, max_flows=10000, emit=None):
        if any(not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or v <= 0
               for v in (tcp_timeout, udp_timeout)):
            raise ValueError('Timeouts must be finite positive seconds')
        if type(max_flows) is not int or max_flows <= 0:
            raise ValueError('max_flows must be a positive integer')
        self.timeouts = {'TCP': tcp_timeout, 'UDP': udp_timeout}
        self.max_flows = max_flows
        self.emit = emit
        self.active = {}
        self.watermark = float('-inf')

    def snapshot(self, flow):
        return deepcopy({k: v for k, v in flow.items() if not k.startswith('_')})

    def close(self, key, reason):
        flow = self.active[key]
        result = self.snapshot(flow)
        result['close_reason'] = reason
        if self.emit:
            self.emit(result)
        del self.active[key]
        return result

    def expire(self, now):
        if not math.isfinite(now):
            raise ValueError('Invalid expiration time')
        self.watermark = max(self.watermark, now)
        closed = []
        for key, flow in list(self.active.items()):
            if self.watermark - flow['_last'] >= self.timeouts[flow['protocol']]:
                closed.append(self.close(key, 'idle_timeout'))
        return closed

    def flush(self, reason='end_of_input'):
        return [self.close(key, reason) for key in list(self.active)]

    def track(self, event):
        result = deepcopy(event) if isinstance(event, dict) else {}
        try:
            if result.get('preprocess_status') == 'invalid' or result.get('processing_action') == 'drop':
                raise ValueError('event_rejected_by_preprocessor')
            normalized = result['normalized']
            network, transport = normalized['network'], normalized['transport']
            protocol = transport['protocol']
            if protocol not in self.timeouts:
                raise ValueError('unsupported_transport')
            endpoints = []
            for side in ('src', 'dst'):
                ip = str(ipaddress.ip_address(network[side + '_ip']))
                port = transport[side + '_port']
                if type(port) is not int or not 0 <= port <= 65535:
                    raise ValueError('invalid_port')
                endpoints.append((ip, port))
            stamp = datetime.fromisoformat(normalized['timestamp'].replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError('missing_timezone')
            now = stamp.timestamp()
            size = network.get('length')
            if type(size) is not int or size < 0:
                raise ValueError('missing_or_invalid_ip_length')
            payload_length = transport.get('payload_length', 0)
            if type(payload_length) is not int or payload_length < 0:
                raise ValueError('invalid_payload_length')
            flags = transport.get('flags') or ''
            if not isinstance(flags, str):
                raise ValueError('invalid_flags')
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
            result.update(track_status='skipped', track_reason=str(exc), flow=None)
            return result
        self.expire(now)
        if now < self.watermark - self.timeouts[protocol]:
            result.update(track_status='skipped', track_reason='late_packet_beyond_timeout', flow=None)
            return result
        key = (protocol, *sorted(endpoints))
        if key not in self.active:
            if len(self.active) >= self.max_flows:
                oldest = min(self.active, key=lambda item: self.active[item]['_last'])
                self.close(oldest, 'capacity_limit')
            self.active[key] = {
                'flow_id': uuid4().hex, 'protocol': protocol, 'application_protocol': 'UNKNOWN',
                'endpoint_a': {'ip': endpoints[0][0], 'port': endpoints[0][1]},
                'endpoint_b': {'ip': endpoints[1][0], 'port': endpoints[1][1]},
                'start_time': iso(now), 'last_seen': iso(now), 'duration': 0.0,
                'packet_count': 0, 'byte_count': 0,
                'forward_packet_count': 0, 'backward_packet_count': 0,
                'forward_byte_count': 0, 'backward_byte_count': 0,
                'SYN_count': 0, 'ACK_count': 0, 'FIN_count': 0, 'RST_count': 0,
                'state': 'NEW' if protocol == 'TCP' else 'ACTIVE',
                '_first': now, '_last': now, '_a': endpoints[0],
                '_syn': set(), '_synack': set(), '_fin': {}, '_finacked': set(),
            }
        flow = self.active[key]
        direction = 'forward' if endpoints[0] == flow['_a'] else 'backward'
        opposite = 'backward' if direction == 'forward' else 'forward'
        flow['_first'] = min(flow['_first'], now)
        flow['_last'] = max(flow['_last'], now)
        flow.update(start_time=iso(flow['_first']), last_seen=iso(flow['_last']),
                    duration=flow['_last'] - flow['_first'])
        flow['packet_count'] += 1
        flow['byte_count'] += size
        flow[direction + '_packet_count'] += 1
        flow[direction + '_byte_count'] += size
        app = normalized.get('application', {}).get('protocol', 'UNKNOWN')
        if app in ('HTTP', 'DNS', 'SMTP'):
            flow['application_protocol'] = app
        if protocol == 'TCP':
            for flag, name in [('S', 'SYN'), ('A', 'ACK'), ('F', 'FIN'), ('R', 'RST')]:
                flow[name + '_count'] += int(flag in flags)
            if 'R' in flags:
                flow['state'] = 'RESET'
            else:
                if 'S' in flags:
                    flow['_syn'].add(direction)
                    if 'A' in flags:
                        flow['_synack'].add(direction)
                    if flow['state'] == 'NEW':
                        flow['state'] = 'HANDSHAKE'
                if 'A' in flags and 'S' not in flags:
                    if opposite in flow['_synack'] and direction in flow['_syn']:
                        if flow['state'] in ('NEW', 'HANDSHAKE'):
                            flow['state'] = 'ESTABLISHED'
                    elif flow['state'] == 'NEW':
                        flow['state'] = 'ESTABLISHED'
                    fin_end = flow['_fin'].get(opposite)
                    ack = transport.get('ack')
                    if fin_end is not None and type(ack) is int and (ack - fin_end) % (2**32) < 2**31:
                        flow['_finacked'].add(opposite)
                if 'F' in flags:
                    seq = transport.get('seq')
                    end = (seq + payload_length + 1) % (2**32) if type(seq) is int else None
                    flow['_fin'].setdefault(direction, end)
                    flow['state'] = 'CLOSING'
                if len(flow['_fin']) == 2 and len(flow['_finacked']) == 2:
                    flow['state'] = 'CLOSED'
        result.update(track_status='tracked', track_reason=None,
                      flow={'flow_id': flow['flow_id'], 'direction': direction, 'state': flow['state']})
        if flow['state'] in ('CLOSED', 'RESET'):
            self.close(key, 'tcp_' + flow['state'].lower())
        return result
