import pytest

from src.engine import parse_rule


def rule(options='', header='alert tcp any any -> 192.0.2.0/24 80:90'):
    return f'{header} (msg:"demo"; sid:100001; rev:1; {options})'


def test_header_and_metadata():
    result = parse_rule(rule('classtype:web-application-attack; priority:2;'), 'demo.rules', 3)
    assert result.status == 'valid'
    assert result.rule.header.dst_port == (80, 90)
    assert result.rule.header.dst_ip == '192.0.2.0/24'
    assert result.rule.header.src_port == (0, 65535)
    assert result.rule.sid == 100001 and result.rule.priority == 2
    assert result.rule.line_number == 3


def test_content_and_quoted_delimiters():
    result = parse_rule(rule(r'content:"a;\"b|00 FF|"; nocase; offset:2; depth:10; content:"end"; distance:0; within:8;'))
    assert result.status == 'valid', result.reasons
    a, b = result.rule.contents
    assert a.pattern == b'a;"b\x00\xff'
    assert a.nocase and a.offset == 2 and a.depth == 10
    assert b.distance == 0 and b.within == 8


@pytest.mark.parametrize('header', ['alert udp 192.0.2.1 53 <> any :1024', 'alert tcp any 1024: -> any any'])
def test_header_variants(header):
    assert parse_rule(rule(header=header)).status == 'valid'


@pytest.mark.parametrize('options', ['flags:SA; dsize:>10; flow:to_server,established;',
                                      'dsize:10<>100;', 'dsize:0;', 'flags:0;'])
def test_packet_and_flow_options(options):
    assert parse_rule(rule(options)).status == 'valid'


@pytest.mark.parametrize('options', ['pcre:"/a/";', 'content:!"bad";', 'flow:stateless;', 'flags:S+;'])
def test_unsupported(options):
    result = parse_rule(rule(options))
    assert result.status == 'unsupported'
    assert result.rule is None and result.reasons


@pytest.mark.parametrize('options', ['sid:2;', 'nocase;', 'content:"a"; distance:1;',
    'content:"abc"; depth:2;', 'content:"a"; offset:0; content:"b"; offset:0; distance:1;',
    'flow:to_server,to_client;', 'flow:established,not_established;', 'dsize:20<>10;',
    'content:"|GG|";', 'content:"unfinished;', 'content:"a"', 'priority:0;'])
def test_invalid(options):
    result = parse_rule(rule(options))
    assert result.status == 'invalid', result
    assert result.rule is None and result.reasons


@pytest.mark.parametrize('text', [None, '', 'alert tcp any any -> any any',
    'alert tcp bad-ip any -> any 80 (msg:"x"; sid:1; rev:1;)',
    'alert tcp any 65536 -> any 80 (msg:"x"; sid:1; rev:1;)',
    'alert udp any any -> any 53 (msg:"x"; sid:1; rev:1; flags:S;)'])
def test_malformed(text):
    assert parse_rule(text).status == 'invalid'


def test_batch_continues_and_requires_identification():
    results = [parse_rule(x) for x in ['bad', rule('pcre:"a";'), rule()]]
    assert [x.status for x in results] == ['invalid', 'unsupported', 'valid']
    assert parse_rule('alert tcp any any -> any any (sid:1;)').status == 'invalid'
