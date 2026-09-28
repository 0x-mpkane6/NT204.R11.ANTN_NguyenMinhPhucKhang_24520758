import json
from itertools import count

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.error import Scapy_Exception

import main
from src.capture import capture
from src.logging.jsonl_writer import JsonlWriter


@pytest.mark.parametrize('bad', [None, Raw(b'bad'), IP()/TCP(),
    IP(bytes(IP(proto=6)/Raw(b'\x00\x01'))),
    IP(bytes(IP(proto=17)/Raw(b'\x00\x01'))),
    IP()/UDP(dport=53)/Raw(b'\xff'*13),
    IP()/TCP()/Raw(b'GET / HTTP/1.1\r\n\r\n\xff')])
def test_bad_packet_does_not_block_next_packet(tmp_path, bad):
    path = tmp_path/'events.jsonl'
    with JsonlWriter(path) as writer:
        ids = count(1)
        main.handle_packet(bad, writer, ids)
        main.handle_packet(IP(src='10.1.2.3')/TCP(), writer, ids)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert events[-1]['network']['src_ip'] == '10.1.2.3'
    assert [e['packet_id'] for e in events] == list(range(1, len(events)+1))


def test_invalid_timestamp_is_skipped(tmp_path, capsys):
    packet = IP()/TCP()
    packet.time = float('nan')
    path = tmp_path/'events.jsonl'
    with JsonlWriter(path) as writer:
        main.handle_packet(packet, writer, count(1))
    assert path.read_text() == ''
    assert 'Skipping malformed packet' in capsys.readouterr().err


def test_parser_exception_is_reported(tmp_path, monkeypatch, capsys):
    def broken(packet):
        raise ValueError('bad header')
    monkeypatch.setattr(main, 'parse_packet', broken)
    with JsonlWriter(tmp_path/'events.jsonl') as writer:
        main.handle_packet(IP(), writer, count(1))
    assert 'bad header' in capsys.readouterr().err


def test_live_writer_failure_propagates(monkeypatch):
    monkeypatch.setattr(capture, 'get_if_list', lambda: ['test0'])
    def sniff(**kwargs):
        packet = IP()/TCP()
        kwargs['prn'](packet)
        assert kwargs['stop_filter'](packet)
    def handler(packet):
        raise OSError('disk full')
    monkeypatch.setattr(capture, 'sniff', sniff)
    with pytest.raises(OSError, match='disk full'):
        capture.capture_live('test0', handler)


def test_invalid_interface(monkeypatch):
    monkeypatch.setattr(capture, 'get_if_list', lambda: ['test0'])
    with pytest.raises(ValueError, match='Available interfaces: test0'):
        capture.capture_live('missing', lambda p: None)


@pytest.mark.parametrize('contents', [None, b'not a pcap', b'\xd4\xc3\xb2\xa1'])
def test_invalid_pcap(tmp_path, contents):
    path = tmp_path/'bad.pcap'
    if contents is not None:
        path.write_bytes(contents)
    with pytest.raises(Scapy_Exception, match='Cannot open PCAP'):
        capture.read_pcap(str(path), lambda p: None)
