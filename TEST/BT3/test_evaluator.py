import base64
import json
from copy import deepcopy

from src.engine import EvaluationEngine, RuleRepository, RuleMatcher, parse_rule, generate_detection, MatchResult, build_context
import pytest


def rule(sid, options=''):
    return parse_rule(f'alert tcp any any -> any 80 (msg:"demo"; sid:{sid}; rev:1; {options})').rule


def event(payload=b'GET /admin'):
    return {'packet_id': 1, 'normalized': {
        'timestamp': '2026-11-02T00:00:00Z',
        'network': {'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2'},
        'transport': {'protocol': 'TCP', 'src_port': 12345, 'dst_port': 80, 'flags': 'PA',
                      'payload_length': len(payload), 'raw_payload_base64': base64.b64encode(payload).decode()},
        'application': {'protocol': 'HTTP'}}, 'flow': {'flow_id': 'F123'}}


def test_multiple_matches_and_detection_schema():
    engine = EvaluationEngine(RuleRepository([rule(1, 'content:"GET";'), rule(2, 'content:"admin"; priority:1; classtype:web-application-attack;'), rule(3, 'content:"absent";')]))
    data = event()
    original = deepcopy(data)
    result = engine.evaluate(data)
    assert result.status == 'complete'
    assert [d['sid'] for d in result.detections] == [1, 2]
    assert result.candidate_count == result.evaluated_count == 3
    d = result.detections[1]
    assert d['flow_id'] == 'F123' and d['packet_id'] == 1
    assert (d['rev'], d['msg'], d['priority'], d['classtype']) == (1, 'demo', 1, 'web-application-attack')
    assert (d['src_ip'], d['dst_ip'], d['src_port'], d['dst_port'], d['protocol']) == ('10.0.0.1', '10.0.0.2', 12345, 80, 'TCP')
    assert d['application_protocol'] == 'HTTP' and d['timestamp'] == original['normalized']['timestamp']
    assert d['match_info']['contents'][0]['start'] == 5
    json.dumps(result.detections)
    assert data == original
    assert engine.stats['matches'] == 2
    assert engine.stats['rules_evaluated'] == 3


def test_invalid_no_candidates_and_stats_snapshot():
    engine = EvaluationEngine(RuleRepository([rule(1)]))
    assert engine.evaluate(None).status == 'invalid'
    data = event()
    data['normalized']['transport']['dst_port'] = 81
    result = engine.evaluate(data)
    assert result.status == 'complete' and not result.detections
    stats = engine.stats
    stats['matches'] = 99
    assert engine.stats['matches'] == 0
    assert engine.stats['events_received'] == 2
    assert engine.stats['invalid_events'] == 1
    assert engine.stats['events_evaluated'] == 1


def test_incomplete_does_not_stop_header_only_rule():
    engine = EvaluationEngine(RuleRepository([rule(1, 'content:"GET";'), rule(2)]),
                              matcher=RuleMatcher(max_buffer_bytes=1))
    result = engine.evaluate(event())
    assert result.status == 'partial'
    assert [d['sid'] for d in result.detections] == [2]
    assert engine.stats['incomplete_rules'] == 1


def test_exception_isolated_to_rule():
    class BrokenMatcher(RuleMatcher):
        def match(self, rule, context):
            if rule.sid == 1:
                raise RuntimeError('test failure')
            return super().match(rule, context)
    engine = EvaluationEngine(RuleRepository([rule(1), rule(2)]), BrokenMatcher())
    assert [d['sid'] for d in engine.evaluate(event()).detections] == [2]
    assert engine.stats['rule_errors'] == 1


def test_generator_guard_and_optional_fields():
    r, ctx = rule(1), build_context(event())
    with pytest.raises(ValueError):
        generate_detection(r, ctx, MatchResult('NO_MATCH', 1))
    with pytest.raises(ValueError):
        generate_detection(r, ctx, MatchResult('MATCH', 2))
    ctx['flow'] = None
    d = generate_detection(r, ctx, MatchResult('MATCH', 1))
    assert d['flow_id'] is None and d['priority'] is None
    assert d['match_info']['contents'] == []
