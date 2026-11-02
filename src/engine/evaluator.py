import json
from copy import deepcopy
from dataclasses import dataclass, field

from .context import build_context
from .detection import generate_detection
from .matcher import RuleMatcher


@dataclass
class EvaluationResult:
    status: str
    detections: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    candidate_count: int = 0
    evaluated_count: int = 0


class EvaluationEngine:
    def __init__(self, repository, matcher=None, max_buffer_bytes=1048576):
        if type(max_buffer_bytes) is not int or max_buffer_bytes <= 0:
            raise ValueError('max_buffer_bytes must be a positive integer')
        self.repository = repository
        self.matcher = matcher if matcher is not None else RuleMatcher(max_buffer_bytes=max_buffer_bytes)
        self.max_buffer_bytes = max_buffer_bytes
        self._stats = dict(events_received=0, events_evaluated=0, invalid_events=0,
                           candidate_rules=0, rules_evaluated=0, matches=0,
                           incomplete_rules=0, rule_errors=0)

    @property
    def stats(self):
        return deepcopy(self._stats)

    def evaluate(self, event):
        self._stats['events_received'] += 1
        context = build_context(event, max_buffer_bytes=self.max_buffer_bytes)
        if context['context_status'] == 'invalid':
            self._stats['invalid_events'] += 1
            return EvaluationResult('invalid', diagnostics=[{
                'stage': 'context', 'reasons': context['context_errors']}])
        candidates = self.repository.candidates(context)
        query_reason = self.repository.last_query.get('reason')
        if query_reason is not None:
            self._stats['invalid_events'] += 1
            return EvaluationResult('invalid', diagnostics=[{'stage': 'repository', 'reason': query_reason}])
        self._stats['events_evaluated'] += 1
        self._stats['candidate_rules'] += len(candidates)
        result = EvaluationResult('complete', candidate_count=len(candidates))
        if context['context_status'] == 'partial':
            result.status = 'partial'
            result.diagnostics.append({'stage': 'context', 'reasons': context['context_errors']})
        for rule in candidates:
            result.evaluated_count += 1
            self._stats['rules_evaluated'] += 1
            try:
                match = self.matcher.match(rule, context)
                if not match.complete:
                    result.status = 'partial'
                    self._stats['incomplete_rules'] += 1
                    result.diagnostics.append({'stage': 'matching', 'sid': rule.sid, 'reason': match.reason})
                    continue
                if match.status == 'NO_MATCH':
                    continue
                if match.status != 'MATCH':
                    raise ValueError('Unexpected match status')
                detection = generate_detection(rule, context, match)
                json.dumps(detection, allow_nan=False)
                result.detections.append(detection)
                self._stats['matches'] += 1
            except Exception as exc:
                result.status = 'partial'
                self._stats['rule_errors'] += 1
                result.diagnostics.append({'stage': 'rule_evaluation', 'sid': rule.sid,
                                           'reason': type(exc).__name__ + ': ' + str(exc)})
        return result
