from copy import deepcopy

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.parser.packet_parser import parse_packet
from src.preprocessor import preprocess_event
from src.flow import FlowTracker
from src.engine import build_context


def event(flags='A', reverse=False, payload=b'', udp=False):
    a, b = ('10.0.0.1', 12345), ('10.0.0.2', 80)
    if reverse:
        a, b = b, a
    layer = UDP(sport=a[1], dport=b[1]) if udp else TCP(sport=a[1], dport=b[1], flags=flags)
    packet = IP(bytes(IP(src=a[0], dst=b[0])/layer/Raw(payload)))
    result = parse_packet(packet)
    result['timestamp'] = '2026-11-02T00:00:00Z'
    return preprocess_event(result)


@pytest.mark.parametrize('udp', [False, True])
@pytest.mark.parametrize('payload', [b'', b'\x00\xffhello'])
def test_payload_roundtrip(udp, payload):
    data = event(payload=payload, udp=udp)
    original = deepcopy(data)
    result = build_context(data)
    assert result['context_status'] == 'valid'
    assert result['buffers']['payload'] == payload
    assert result['payload_size'] == len(payload)
    assert data == original


def test_roles_and_established_survive_closing():
    tracker = FlowTracker()
    assert tracker.track(event('S'))['flow']['established'] is False
    reverse = tracker.track(event('SA', True))['flow']
    assert reverse['service_direction'] == 'to_client'
    completed = tracker.track(event('A'))['flow']
    assert completed['established_source'] == 'observed_handshake'
    assert completed['established'] is True
    closing = tracker.track(event('FA'))['flow']
    assert closing['state'] == 'CLOSING' and closing['established'] is True
    context = build_context(tracker.track(event('A', True)))
    assert context['flow']['client']['port'] == 12345


def test_synack_first_and_midstream():
    tracker = FlowTracker()
    flow = tracker.track(event('SA', True))['flow']
    assert flow['direction'] == 'forward'
    assert flow['service_direction'] == 'to_client'
    midstream = FlowTracker().track(event())['flow']
    assert midstream['service_direction'] is None
    assert midstream['established_source'] == 'inferred_midstream'
    udp = FlowTracker().track(event(udp=True))['flow']
    assert udp['established'] is None


def test_missing_mismatch_and_limit():
    data = event(payload=b'abc')
    del data['normalized']['transport']['raw_payload_base64']
    assert 'payload' not in build_context(data)['buffers']
    data = event(payload=b'abc')
    data['normalized']['transport']['payload_length'] = 1
    assert 'payload_length_mismatch' in build_context(data)['context_errors']
    assert 'payload' not in build_context(event(payload=b'abc'), max_buffer_bytes=1)['buffers']
    assert build_context(None)['context_status'] == 'invalid'


def test_separate_decoded_buffers():
    data = event(payload=b'GET /%41 HTTP/1.1\r\n\r\n')
    data['decoded'] = {'uri': '/A'}
    context = build_context(data)
    assert context['buffers']['http.uri.decoded'] == b'/A'
    assert b'%41' in context['buffers']['payload']
