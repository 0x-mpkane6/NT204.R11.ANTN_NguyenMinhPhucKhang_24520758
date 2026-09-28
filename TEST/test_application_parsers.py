import json
import random
import struct

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.parser.application_detector import detect_application
from src.parser.dns import parse_dns
from src.parser.http import parse_http
from src.parser.smtp import parse_smtp


def tcp(data, port=9000):
    return IP()/TCP(sport=12345, dport=port)/Raw(data)


@pytest.mark.parametrize("payload, expected", [
    (b"GET /index HTTP/1.1\r\nHost: example.org\r\n\r\n", "request"),
    (b"POST / HTTP/1.0\r\nContent-Length: 3\r\n\r\nabc", "request"),
    (b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n", "response"),
])
def test_http(payload, expected):
    packet = tcp(payload)
    result = parse_http(packet)
    assert result["type"] == expected
    assert result["headers_complete"]
    assert detect_application(packet) == "HTTP"
    json.dumps(result)
    if expected == "response":
        assert result["status_code"] == 200
        assert result["headers"]["set-cookie"] == ["a=1", "b=2"]
    if payload.startswith(b"POST"):
        assert result["body"] == "abc"


def test_http_incomplete_and_binary():
    result = parse_http(tcp(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n\xff"))
    assert "incomplete_body" in result["errors"]
    assert result["body_length"] == 1
    assert not parse_http(tcp(b"GET / HTTP/1.1\r\nHost: x"))["headers_complete"]
    assert parse_http(tcp(b"GET / HTTP/2.0\r\n\r\n")) is None


@pytest.mark.parametrize("over_tcp", [False, True])
def test_dns(over_tcp):
    message = DNS(id=42, qr=1, qd=DNSQR(qname="example.org"),
                  an=DNSRR(rrname="example.org", type="A", ttl=60, rdata="1.2.3.4"))
    data = bytes(message.compress())
    packet = tcp(struct.pack("!H", len(data)) + data) if over_tcp else IP()/UDP(dport=9000)/Raw(data)
    result = parse_dns(packet)
    assert result["id"] == 42
    assert result["questions"][0]["name"] == "example.org."
    assert result["answers"][0]["data"] == "1.2.3.4"
    assert detect_application(packet) == "DNS"
    json.dumps(result)


def test_dns_query_and_bad_pointer():
    packet = IP()/UDP()/DNS(qd=DNSQR(qname="example.org", qtype="AAAA"))
    assert parse_dns(packet)["questions"][0]["type_name"] == "AAAA"
    loop = struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    assert parse_dns(IP()/UDP()/Raw(loop)) is None
    data = bytes(packet[UDP].payload)
    for end in range(len(data)):
        assert parse_dns(IP()/UDP()/Raw(data[:end])) is None


@pytest.mark.parametrize("line, command", [
    (b"EHLO example.org", "EHLO"), (b"HELO example.org", "HELO"),
    (b"MAIL FROM:<a@example.org>", "MAIL FROM"),
    (b"RCPT TO:<b@example.org>", "RCPT TO"),
])
def test_smtp_commands(line, command):
    packet = tcp(line + b"\r\n")
    assert parse_smtp(packet)["entries"][0]["command"] == command
    assert detect_application(packet) == "SMTP"


def test_smtp_responses_and_ambiguity():
    packet = tcp(b"250-example.org\r\n250 SIZE 1000\r\n", port=25)
    entries = parse_smtp(packet)["entries"]
    assert [entry["status_code"] for entry in entries] == [250, 250]
    assert [entry["continuation"] for entry in entries] == [True, False]
    assert detect_application(packet) == "SMTP"
    assert detect_application(tcp(b"220 FTP server ready\r\n", port=21)) == "UNKNOWN"
    assert detect_application(tcp(b"220 host ESMTP ready\r\n")) == "SMTP"


@pytest.mark.parametrize("packet", [None, IP(), IP()/TCP(), tcp(b"garbage", 80),
                                   tcp(b"\x16\x03\x03\x00\x01\xff", 465)])
def test_unknown(packet):
    assert detect_application(packet) == "UNKNOWN"


def test_random_payloads_do_not_crash():
    rng = random.Random(42)
    for _ in range(300):
        data = rng.randbytes(rng.randrange(200))
        for packet in (tcp(data, 25), IP()/UDP(dport=53)/Raw(data)):
            assert detect_application(packet) in {"HTTP", "DNS", "SMTP", "UNKNOWN"}
            for parser in (parse_dns, parse_http, parse_smtp):
                json.dumps(parser(packet))


@pytest.mark.parametrize("packet, protocol, field, expected", [
    (tcp(b"GET / HTTP/1.1\r\n\r\n"), "HTTP", "method", "GET"),
    (IP()/UDP()/DNS(id=42, qd=DNSQR(qname="example.org")), "DNS", "id", 42),
    (tcp(b"EHLO example.org\r\n"), "SMTP", "type", "command"),
    (IP()/TCP(flags="A"), "UNKNOWN", "protocol", "UNKNOWN"),
    (IP(proto=99)/Raw(b"unsupported"), "UNKNOWN", "protocol", "UNKNOWN"),
])
def test_application_pipeline(packet, protocol, field, expected):
    from src.parser.packet_parser import parse_packet

    result = parse_packet(packet)
    assert result["application"]["protocol"] == protocol
    assert result["application"][field] == expected
    assert result["network"]["src_ip"] == packet[IP].src
    assert "transport" in result
    json.dumps(result)
