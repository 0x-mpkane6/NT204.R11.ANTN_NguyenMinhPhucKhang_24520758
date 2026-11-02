from dataclasses import dataclass, field

from .matchers.header import match_header
from .matchers.flow import match_flow
from .matchers.packet import match_packet
from .matchers.content import match_content, ContentLimit


@dataclass
class MatchResult:
    status: str
    sid: int | None
    reason: str | None = None
    matched: list[dict] = field(default_factory=list)
    complete: bool = True


class RuleMatcher:
    def __init__(self, buffer_name='payload', allow_inferred_established=False,
                 max_buffer_bytes=1048576, max_content_steps=100000):
        if not isinstance(buffer_name, str) or not buffer_name:
            raise ValueError('buffer_name must be nonempty')
        if type(allow_inferred_established) is not bool:
            raise ValueError('allow_inferred_established must be boolean')
        if any(type(v) is not int or v <= 0 for v in (max_buffer_bytes, max_content_steps)):
            raise ValueError('Limits must be positive integers')
        self.buffer_name = buffer_name
        self.allow_inferred_established = allow_inferred_established
        self.max_buffer_bytes = max_buffer_bytes
        self.max_content_steps = max_content_steps

    def match(self, rule, context):
        sid = getattr(rule, 'sid', None)
        try:
            if context.get('context_status') == 'invalid':
                return MatchResult('NO_MATCH', sid, 'invalid_context', complete=False)
            if not match_header(rule.header, context):
                return MatchResult('NO_MATCH', sid, 'header_mismatch')
            if not match_flow(rule.flow, context.get('flow'), self.allow_inferred_established):
                return MatchResult('NO_MATCH', sid, 'flow_mismatch_or_unknown')
            if not match_packet(rule, context):
                return MatchResult('NO_MATCH', sid, 'packet_mismatch_or_missing')
            matched = []
            if rule.contents:
                payload = context.get('buffers', {}).get(self.buffer_name)
                if not isinstance(payload, bytes):
                    return MatchResult('NO_MATCH', sid, 'missing_content_buffer', complete=False)
                if len(payload) > self.max_buffer_bytes:
                    return MatchResult('NO_MATCH', sid, 'buffer_size_limit', complete=False)
                matched = match_content(rule.contents, payload, self.max_content_steps)
                if matched is None:
                    return MatchResult('NO_MATCH', sid, 'content_mismatch')
                matched = [dict(item, field=self.buffer_name) for item in matched]
            return MatchResult('MATCH', sid, matched=matched)
        except ContentLimit as exc:
            return MatchResult('NO_MATCH', sid, str(exc), complete=False)
        except (AttributeError, TypeError, KeyError, ValueError, IndexError) as exc:
            return MatchResult('NO_MATCH', sid, 'invalid_input:' + type(exc).__name__, complete=False)
