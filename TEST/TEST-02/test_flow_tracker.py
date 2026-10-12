from datetime import datetime, timezone

import pytest

from src.flow import FlowTracker


def event(t=0, flags='A', reverse=False, protocol='TCP', port=80, seq=0, ack=0):
    a, b = ('10.0.0.1', 12345), ('10.0.0.2', port)
    if reverse:
        a, b = b, a
    return {'normalized': {
        'timestamp': datetime.fromtimestamp(t, timezone.utc).isoformat(),
        'network': {'src_ip': a[0], 'dst_ip': b[0], 'length': 40},
        'transport': {'protocol': protocol, 'src_port': a[1], 'dst_port': b[1], 'flags': flags, 'seq': seq, 'ack': ack},
        'application': {'protocol': 'DNS' if protocol == 'UDP' else 'UNKNOWN'}}}


def test_handshake_bidirectional_statistics():
    tracker = FlowTracker()
    first = tracker.track(event(0, 'S'))
    second = tracker.track(event(1, 'SA', True))
    last = tracker.track(event(2, 'A'))
    assert first['flow']['flow_id'] == second['flow']['flow_id'] == last['flow']['flow_id']
    assert second['flow']['direction'] == 'backward'
    assert last['flow']['state'] == 'ESTABLISHED'
    flow = tracker.flush()[0]
    assert (flow['packet_count'], flow['byte_count'], flow['duration']) == (3, 120, 2)
    assert (flow['forward_packet_count'], flow['backward_byte_count']) == (2, 40)
    assert (flow['SYN_count'], flow['ACK_count']) == (2, 2)


def test_fin_close_and_rst():
    records = []
    tracker = FlowTracker(emit=records.append)
    tracker.track(event(0))
    tracker.track(event(1, 'FA', seq=10))
    tracker.track(event(2, 'A', True, ack=11))
    tracker.track(event(3, 'FA', True, seq=20))
    assert tracker.track(event(4, 'A', ack=21))['flow']['state'] == 'CLOSED'
    assert not tracker.active
    old_id = records[0]['flow_id']
    assert tracker.track(event(5, 'R'))['flow']['state'] == 'RESET'
    assert records[-1]['flow_id'] != old_id


def test_udp_timeout_concurrency_capacity():
    records = []
    tracker = FlowTracker(udp_timeout=5, max_flows=2, emit=records.append)
    a = tracker.track(event(protocol='UDP'))
    b = tracker.track(event(1, reverse=True, protocol='UDP'))
    assert a['flow']['flow_id'] == b['flow']['flow_id']
    tracker.track(event(2, protocol='UDP', port=53))
    assert len(tracker.active) == 2
    tracker.track(event(3, protocol='UDP', port=54))
    assert records[0]['close_reason'] == 'capacity_limit'
    assert records[0]['packet_count'] == 2
    tracker.expire(8)
    assert not tracker.active
    assert records[-1]['close_reason'] == 'idle_timeout'


def test_tcp_timeout_reuse_and_out_of_order():
    tracker = FlowTracker(tcp_timeout=5)
    original = tracker.track(event(10))
    tracker.track(event(9))
    new = tracker.track(event(15))
    assert new['flow']['flow_id'] != original['flow']['flow_id']
    assert tracker.track(event(0))['track_status'] == 'skipped'


@pytest.mark.parametrize('data', [None, {}, {'normalized': None}, {'preprocess_status': 'invalid'}])
def test_bad_events(data):
    tracker = FlowTracker()
    assert tracker.track(data)['track_status'] == 'skipped'
    assert not tracker.active


@pytest.mark.parametrize('config', [{'tcp_timeout': 0}, {'udp_timeout': float('nan')}, {'max_flows': 0}])
def test_config(config):
    with pytest.raises(ValueError):
        FlowTracker(**config)


def test_dns_udp_query_response_pipeline():
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from src.parser.packet_parser import parse_packet
    from src.preprocessor import preprocess_event

    query = IP(bytes(IP(src='10.0.0.1', dst='8.8.8.8')/UDP(sport=12345, dport=53)/DNS(
        id=7, qd=DNSQR(qname='example.org'))))
    response = IP(bytes(IP(src='8.8.8.8', dst='10.0.0.1')/UDP(sport=53, dport=12345)/DNS(
        id=7, qr=1, qd=DNSQR(qname='example.org'),
        an=DNSRR(rrname='example.org', rdata='1.2.3.4'))))
    tracker = FlowTracker()
    results = []
    for index, packet in enumerate((query, response)):
        parsed = parse_packet(packet)
        parsed['timestamp'] = datetime.fromtimestamp(index, timezone.utc).isoformat()
        results.append(tracker.track(preprocess_event(parsed)))
    assert results[0]['flow']['flow_id'] == results[1]['flow']['flow_id']
    flow = tracker.flush()[0]
    assert flow['application_protocol'] == 'DNS'
    assert flow['packet_count'] == 2
    assert flow['byte_count'] == query.len + response.len
    assert flow['forward_packet_count'] == flow['backward_packet_count'] == 1
    assert flow['forward_byte_count'] == query.len
    assert flow['backward_byte_count'] == response.len
