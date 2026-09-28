import json
import struct
import sys
from decimal import Decimal
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap

import main


def test_real_pcap_to_jsonl(tmp_path, monkeypatch):
    packets = [IP()/TCP()/Raw(b'GET / HTTP/1.1\r\n\r\n'),
               IP()/UDP()/DNS(qd=DNSQR(qname='example.org')),
               IP()/TCP(dport=25)/Raw(b'EHLO example.org\r\n'),
               IP()/TCP(flags='A')]
    for packet in packets:
        packet.time = Decimal('1700000000.123456')
    source = tmp_path/'input.pcap'
    target = tmp_path/'events.jsonl'
    wrpcap(str(source), packets)
    monkeypatch.setattr(sys, 'argv', ['main.py', '--pcap', str(source), '--output', str(target)])
    main.main()
    events = [json.loads(line) for line in target.read_text().splitlines()]
    assert [e['application']['protocol'] for e in events] == ['HTTP', 'DNS', 'SMTP', 'UNKNOWN']
    assert [e['packet_id'] for e in events] == [1, 2, 3, 4]
    assert all(e['timestamp'] == '2023-11-14T22:13:20.123456Z' for e in events)


def test_truncated_packet_followed_by_valid_packet(tmp_path, monkeypatch):
    source = tmp_path/'truncated.pcap'
    target = tmp_path/'events.jsonl'
    damaged = bytes(IP()/TCP())[:22]
    valid = bytes(IP(src='10.2.3.4')/TCP())
    header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
    records = b''.join(struct.pack('<IIII', 1, 0, len(data), wirelen) + data
                       for data, wirelen in [(damaged, 40), (valid, len(valid))])
    source.write_bytes(header + records)
    monkeypatch.setattr(sys, 'argv', ['main.py', '--pcap', str(source), '--output', str(target)])
    main.main()
    events = [json.loads(line) for line in target.read_text().splitlines()]
    assert events[-1]['network']['src_ip'] == '10.2.3.4'


def test_default_output_separates_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(main, '__file__', str(tmp_path/'main.py'))
    monkeypatch.setattr(main, 'read_pcap', lambda path, handler: handler(IP()/TCP()))
    monkeypatch.setattr(sys, 'argv', ['main.py', '--pcap', 'mock.pcap'])
    main.main()
    first = list((tmp_path/'output').glob('events_*.jsonl'))
    assert len(first) == 1
    original = first[0].read_bytes()
    main.main()
    assert len(list((tmp_path/'output').glob('events_*.jsonl'))) == 2
    assert first[0].read_bytes() == original
