import base64
import json

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from src.parser.http import parse_http
from src.parser.smtp import parse_smtp
from src.parser.application_detector import detect_application


def test_http_preserves_bytes():
    payload = b'POST /%FF HTTP/1.1\r\nContent-Type: text/plain; charset="ascii"\r\n\r\n\xff'
    result = parse_http(IP()/TCP()/Raw(payload))
    assert base64.b64decode(result['raw_payload_base64']) == payload
    assert base64.b64decode(result['raw_body_base64']) == b'\xff'
    assert base64.b64decode(result['raw_uri_base64']) == b'/%FF'
    assert result['charset'] == 'ascii'
    json.dumps(result)


def test_mime_headers_and_encoded_body():
    for encoding, body in [(b'base64', b'aGVsbG8='), (b'quoted-printable', b'hello=20world')]:
        payload = (b'Content-Type: text/plain;\r\n charset="utf-8"\r\n'
                   b'Content-Transfer-Encoding: ' + encoding + b'\r\n\r\n' + body + b'\r\n.\r\n')
        packet = IP()/TCP(dport=25)/Raw(payload)
        result = parse_smtp(packet)
        mime = result['mime']
        assert mime['charset'] == 'utf-8'
        assert mime['content_transfer_encoding'] == encoding.decode()
        assert base64.b64decode(mime['raw_body_base64']) == body + b'\r\n'
        assert mime['status'] == 'complete'
        assert detect_application(packet) == 'SMTP'
        assert base64.b64decode(result['raw_payload_base64']) == payload
        json.dumps(result)


def test_data_dot_stuffing_and_limit():
    packet = IP()/TCP(dport=25)/Raw(b'DATA\r\nSubject: test\r\n\r\n..hello\r\n.\r\nQUIT\r\n')
    result = parse_smtp(packet)
    assert base64.b64decode(result['mime']['raw_body_base64']) == b'.hello\r\n'
    assert result['mime']['data_complete']
    assert parse_smtp(packet, max_message_bytes=4)['mime']['status'] == 'limit_exceeded'


def test_partial_and_explicit_data_context():
    packet = IP()/TCP(dport=9000)/Raw(b'Content-Type: text/plain\r\n\r\n\xff')
    assert parse_smtp(packet) is None
    result = parse_smtp(packet, data_mode=True)
    assert result['mime']['status'] == 'partial'
    assert base64.b64decode(result['mime']['raw_body_base64']) == b'\xff'
    incomplete = IP()/TCP(dport=25)/Raw(b'Content-Type: text/plain')
    assert not parse_smtp(incomplete)['mime']['headers_complete']
