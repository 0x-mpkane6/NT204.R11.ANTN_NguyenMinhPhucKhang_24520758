import pytest

from src.engine import RuleRepository, load_rules, parse_rule


def rule(sid, header):
    result = parse_rule(f'alert {header} (msg:"test"; sid:{sid}; rev:1;)')
    assert result.status == 'valid', result.reasons
    return result.rule


def context(reverse=False, protocol='TCP', dport=80):
    a, b = ('10.0.0.1', 40000), ('192.0.2.1', dport)
    if reverse:
        a, b = b, a
    return dict(protocol=protocol, src_ip=a[0], src_port=a[1], dst_ip=b[0], dst_port=b[1])


def ids(repository, event):
    return [r.sid for r in repository.candidates(event)]


def test_protocol_exact_range_any_cidr():
    repo = RuleRepository([
        rule(1, 'tcp any any -> 192.0.2.0/24 80'),
        rule(2, 'tcp any any -> any 79:81'),
        rule(3, 'tcp any any -> any any'),
        rule(4, 'udp any any -> any 80'),
        rule(5, 'tcp any any -> 198.51.100.0/24 80'),
    ])
    assert ids(repo, context()) == [1, 2, 3]
    assert ids(repo, context(protocol='UDP')) == [4]
    assert ids(repo, context(dport=79)) == [2, 3]
    assert ids(repo, context(dport=81)) == [2, 3]
    assert ids(repo, context(dport=82)) == [3]


def test_bidirectional_and_source_port():
    repo = RuleRepository([
        rule(1, 'tcp 10.0.0.1 40000 <> 192.0.2.1 80'),
        rule(2, 'tcp 10.0.0.1 40000 -> 192.0.2.1 80'),
        rule(3, 'tcp any any <> any any'),
        rule(4, 'tcp any 40001 -> any 80'),
    ])
    assert ids(repo, context()) == [1, 2, 3]
    assert ids(repo, context(reverse=True)) == [1, 3]


def test_index_prunes_unrelated_ports():
    repo = RuleRepository(rule(i, f'tcp any any -> any {i}') for i in range(1, 501))
    assert ids(repo, context()) == [80]
    assert repo.last_query['header_checks'] == 1
    assert repo.last_query['indexed_rules'] == 500


def test_snapshot_and_duplicate():
    original = rule(1, 'tcp any any -> any 80')
    repo = RuleRepository([original])
    original.sid = 99
    found = repo.candidates(context())
    found[0].sid = 100
    assert ids(repo, context()) == [1]
    with pytest.raises(ValueError, match='Duplicate'):
        repo.add(rule(1, 'udp any any -> any 53'))
    assert len(repo) == 1


@pytest.mark.parametrize('event', [None, {}, {'context_status': 'invalid'},
    context(protocol='ICMP'), dict(context(), dst_port=True), dict(context(), src_ip='bad')])
def test_invalid_context(event):
    repo = RuleRepository([rule(1, 'tcp any any -> any any')])
    assert repo.candidates(event) == []
    assert repo.last_query['reason']


def test_loader_integration(tmp_path):
    path = tmp_path/'sample.rules'
    path.write_text('alert tcp any any -> any 80 (msg:"x"; sid:1; rev:1;)\ninvalid')
    report = load_rules([path])
    assert ids(RuleRepository(report.rules), context()) == [1]
