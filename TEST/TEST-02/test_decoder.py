import base64
from copy import deepcopy

import pytest

from src.decoder import decode_event


def raw(data):
    return base64.b64encode(data).decode('ascii')


def test_url_preserves_raw_and_decodes_once():
    event = {'application': {'protocol': 'HTTP', 'raw_uri_base64': raw(b'/%27%20OR%201%3D1+%2520')}}
    original = deepcopy(event)
    result = decode_event(event)
    assert result['decoded']['uri'] == "/' OR 1=1+%20"
    assert event == original
    assert result['application'] == original['application']
    assert result['decode_status'] == 'success'


@pytest.mark.parametrize('kind,body,expected', [
    ('text/html', b'&lt;script&gt;', {'body': '&lt;script&gt;', 'html_text': '<script>'}),
    ('application/x-www-form-urlencoded', b'a=one+two&a=%2B&empty=',
     {'form_fields': [{'name': 'a', 'value': 'one two'}, {'name': 'a', 'value': '+'}, {'name': 'empty', 'value': ''}]}),
])
def test_http_text_and_form(kind, body, expected):
    result = decode_event({'application': {'protocol': 'HTTP', 'content_type': kind, 'raw_body_base64': raw(body)}})
    assert result['decoded'] == expected


@pytest.mark.parametrize('encoding,body', [('base64', b'aGVsbG8='), ('quoted-printable', b'he=6Clo')])
def test_mime_transfer(encoding, body):
    result = decode_event({'application': {'protocol': 'SMTP', 'mime': {
        'raw_body_base64': raw(body), 'content_transfer_encoding': encoding, 'charset': 'utf-8'}}})
    assert result['decoded']['body'] == 'hello'
    assert result['decode_status'] == 'success'


def test_invalid_utf8():
    result = decode_event({'application': {'protocol': 'HTTP', 'content_type': 'text/plain', 'raw_body_base64': raw(b'\xff')}})
    assert result['decode_status'] == 'partial'
    assert result['decoded']['body'] == '\ufffd'
    assert result['decode_errors']


@pytest.mark.parametrize('event', [None, {'application': []}, {'application': 'bad'},
    {'application': {'protocol': 'HTTP', 'raw_uri_base64': '!!!'}},
    {'application': {'protocol': 'SMTP', 'mime': {'raw_body_base64': raw(b'!'), 'content_transfer_encoding': 'base64'}}}])
def test_malformed(event):
    result = decode_event(event)
    assert result['decode_status'] in ('error', 'skipped')


def test_limit_and_unknown():
    result = decode_event({'application': {'protocol': 'HTTP', 'raw_uri_base64': raw(b'abcd')}}, max_field_bytes=2)
    assert result['decode_status'] == 'error'
    assert 'size_limit_exceeded' in result['decode_errors']
    assert decode_event({'application': {'protocol': 'DNS'}})['decode_status'] == 'skipped'
