import pytest
from src.engine import RuleMatcher, parse_rule


def rule(options=''):
    result = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1; rev:1; ' + options + ')')
    assert result.status == 'valid', result.reasons
    return result.rule


def context(payload=b'abc', **changes):
    result = dict(protocol='TCP', src_ip='10.0.0.1', dst_ip='10.0.0.2', src_port=12345,
                  dst_port=80, tcp_flags='PA', payload_size=len(payload), buffers={'payload': payload})
    result.update(changes)
    return result


@pytest.mark.parametrize('options,payload,expected', [
    ('content:"ABC";', b'abc', False), ('content:"ABC"; nocase;', b'abc', True),
    ('content:"bc"; offset:1; depth:2;', b'abc', True),
    ('content:"bc"; offset:2;', b'abc', False),
    ('content:"bc"; depth:2;', b'abc', False),
    ('content:"A"; content:"B"; distance:1; within:3;', b'AxxB', True),
    ('content:"A"; content:"B"; distance:1; within:2;', b'AxxB', False),
    ('content:"A"; content:"B"; distance:0; within:1;', b'AxxAB', True),
    ('content:"AB"; content:"BC"; distance:0; within:2;', b'ABC', False),
    ('content:"B"; content:"A";', b'AB', True),
    ('content:"|00 FF|";', b'\x00\xff', True),
    ('flags:PA; dsize:3;', b'abc', True),
    ('flags:A;', b'abc', False),
    ('dsize:2<>4;', b'abc', True), ('dsize:3<>5;', b'abc', False),
    ('dsize:>2;', b'abc', True), ('dsize:<3;', b'abc', False),
])
def test_conditions(options, payload, expected):
    result = RuleMatcher().match(rule(options), context(payload))
    assert (result.status == 'MATCH') == expected


def test_header_short_circuits_content():
    result = RuleMatcher().match(rule('content:"x";'), context(dst_port=81, buffers=None))
    assert result.reason == 'header_mismatch' and result.complete


def test_flow_observed_inferred_unknown():
    r = rule('flow:to_server,established;')
    flow = dict(service_direction='to_server', established=True, established_source='observed_handshake')
    assert RuleMatcher().match(r, context(flow=flow)).status == 'MATCH'
    flow['established_source'] = 'inferred_midstream'
    assert RuleMatcher().match(r, context(flow=flow)).status == 'NO_MATCH'
    assert RuleMatcher(allow_inferred_established=True).match(r, context(flow=flow)).status == 'MATCH'
    assert RuleMatcher().match(rule('flow:not_established;'), context(flow={'established': None})).status == 'NO_MATCH'
    assert RuleMatcher().match(rule('flow:not_established;'), context(flow={'established': False})).status == 'MATCH'


def test_evidence_and_limits():
    r = rule('content:"A"; content:"B"; within:1;')
    result = RuleMatcher().match(r, context(b'AxxAB'))
    assert [m['start'] for m in result.matched] == [3, 4]
    assert result.matched[0]['field'] == 'payload'
    assert not RuleMatcher(max_content_steps=1).match(r, context(b'AxxAB')).complete
    assert not RuleMatcher(max_buffer_bytes=1).match(r, context()).complete
    assert not RuleMatcher().match(r, context(buffers={})).complete


def test_decoded_buffer_and_malformed():
    r = rule('content:"/admin";')
    c = context(buffers={'http.uri.decoded': b'/admin'})
    assert RuleMatcher(buffer_name='http.uri.decoded').match(r, c).status == 'MATCH'
    assert not RuleMatcher().match(r, None).complete
