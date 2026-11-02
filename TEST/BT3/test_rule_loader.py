import pytest

from src.engine import RuleFile, load_rules


def rule(sid, options='', msg='demo'):
    return f'alert tcp any any -> any 80 (msg:"{msg}"; sid:{sid}; rev:1; {options})'


def test_comments_blank_and_source(tmp_path):
    path = tmp_path/'sample.rules'
    path.write_text('\ufeff# comment\n\n' + rule(1, msg='tag # inside') + ' # outside\n', encoding='utf-8')
    report = load_rules(path)
    assert len(report.results) == len(report.rules) == 1
    assert report.rules[0].msg == 'tag # inside'
    assert report.rules[0].line_number == 3
    assert report.rules[0].source == str(path)


def test_bad_rule_does_not_stop_other_files(tmp_path):
    first, second = tmp_path/'one.rules', tmp_path/'two.rules'
    first.write_bytes(('broken\n' + rule(2, 'pcre:"/x/";') + '\n').encode() + b'\xff\n')
    second.write_text(rule(3))
    report = load_rules([first, tmp_path/'missing.rules', second])
    assert [r.sid for r in report.rules] == [3]
    assert report.counts['invalid'] == 2
    assert report.counts['unsupported'] == 1
    assert report.counts['file_errors'] == 1


def test_enable_disable_and_duplicate(tmp_path):
    path = tmp_path/'sample.rules'
    path.write_text('\n'.join(rule(sid) for sid in (1, 2, 3, 3)))
    report = load_rules([RuleFile(tmp_path/'absent.rules', False), path],
                        enabled_sids={2, 3}, disabled_sids={2})
    assert [r.sid for r in report.rules] == [3]
    assert report.counts['disabled_files'] == 1
    assert report.counts['disabled_rules'] == 2
    assert report.counts['duplicates'] == 1
    assert report.counts['file_errors'] == 0
    assert not load_rules([path], enabled_sids=[]).rules


def test_escaped_quote_hash_and_semicolon(tmp_path):
    path = tmp_path/'sample.rules'
    path.write_text(rule(1, msg=r'a\"#;b') + ' # tail')
    assert load_rules([path]).rules[0].msg == 'a"#;b'


@pytest.mark.parametrize('sid', [-1, True, '1'])
def test_bad_config(sid):
    with pytest.raises(ValueError):
        load_rules([], disabled_sids=[sid])
