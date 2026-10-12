import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.parser.packet_parser import parse_packet


@pytest.mark.parametrize('flags', ['S', 'SA', 'A'])
def test_tcp_handshake(flags):
    packet = IP(bytes(IP(src='10.0.0.1', dst='10.0.0.2')/TCP(
        sport=12345, dport=80, flags=flags, seq=100, ack=200, window=4096)))
    event = parse_packet(packet)
    assert event['transport'] == dict(protocol='TCP', src_port=12345, dst_port=80,
                                     flags=flags, seq=100, ack=200, window=4096)
    assert event['application']['protocol'] == 'UNKNOWN'


def test_tcp_data():
    packet = IP(bytes(IP()/TCP(sport=12345, dport=80, flags='PA', seq=50)/Raw(
        b'POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc')))
    event = parse_packet(packet)
    assert event['transport']['flags'] == 'PA'
    assert event['transport']['seq'] == 50
    assert event['application']['body'] == 'abc'


def test_udp_and_ipv4():
    packet = IP(bytes(IP(src='10.0.0.1', dst='10.0.0.2', ttl=32, id=42)/UDP(
        sport=12345, dport=9000)/Raw(b'abc')))
    event = parse_packet(packet)
    assert event['network'] == dict(src_ip='10.0.0.1', dst_ip='10.0.0.2',
                                    ttl=32, protocol=17, id=42, length=31)
    assert event['transport'] == dict(protocol='UDP', src_port=12345, dst_port=9000,
                                      length=11, checksum=packet[UDP].chksum)
    assert packet[UDP].chksum is not None
    assert event['application']['protocol'] == 'UNKNOWN'
