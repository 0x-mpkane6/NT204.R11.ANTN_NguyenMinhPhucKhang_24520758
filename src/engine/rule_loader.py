from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Rule, RuleParseResult
from .rule_parser import parse_rule


@dataclass(frozen=True)
class RuleFile:
    path: str | Path
    enabled: bool = True


@dataclass
class RuleLoadReport:
    rules: list[Rule] = field(default_factory=list)
    results: list[RuleParseResult] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)

    @property
    def counts(self):
        return {
            'loaded': len(self.rules),
            'invalid': sum(r.status == 'invalid' for r in self.results),
            'unsupported': sum(r.status == 'unsupported' for r in self.results),
            'disabled_rules': sum(d['status'] == 'disabled_rule' for d in self.diagnostics),
            'disabled_files': sum(d['status'] == 'disabled_file' for d in self.diagnostics),
            'file_errors': sum(d['status'] == 'file_error' for d in self.diagnostics),
            'duplicates': sum(d['status'] == 'duplicate_sid' for d in self.diagnostics),
        }


def strip_comment(line):
    quoted = escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\' and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == '#' and not quoted:
            return line[:index]
    return line


def load_rules(files: Iterable[RuleFile | str | Path], *, disabled_sids=(), enabled_sids=None):
    if isinstance(files, (str, Path)):
        files = [files]
    disabled = set(disabled_sids)
    enabled = None if enabled_sids is None else set(enabled_sids)
    if any(type(sid) is not int or sid <= 0 for sid in disabled | (enabled or set())):
        raise ValueError('SID filters must contain positive integers')
    report = RuleLoadReport()
    seen = set()

    def diagnostic(status, source, line_number=None, reasons=None, sid=None):
        report.diagnostics.append(dict(status=status, source=source,
                                       line_number=line_number, reasons=reasons or [], sid=sid))

    for item in files:
        spec = item if isinstance(item, RuleFile) else RuleFile(item)
        if type(spec.enabled) is not bool:
            raise ValueError('RuleFile.enabled must be boolean')
        path = Path(spec.path)
        source = str(path)
        if not spec.enabled:
            diagnostic('disabled_file', source)
            continue
        try:
            with path.open('rb') as stream:
                for line_number, raw in enumerate(stream, 1):
                    try:
                        text = raw.decode('utf-8-sig' if line_number == 1 else 'utf-8')
                    except UnicodeDecodeError:
                        result = RuleParseResult('invalid', ['Invalid UTF-8 rule line'],
                                                 source=source, line_number=line_number)
                    else:
                        text = strip_comment(text).strip()
                        if not text:
                            continue
                        result = parse_rule(text, source=source, line_number=line_number)
                    report.results.append(result)
                    if result.status != 'valid':
                        diagnostic(result.status, source, line_number, result.reasons)
                        continue
                    rule = result.rule
                    if rule.sid in disabled or (enabled is not None and rule.sid not in enabled):
                        diagnostic('disabled_rule', source, line_number, sid=rule.sid)
                    elif rule.sid in seen:
                        diagnostic('duplicate_sid', source, line_number,
                                   ['First enabled valid rule with this SID wins'], rule.sid)
                    else:
                        seen.add(rule.sid)
                        report.rules.append(rule)
        except OSError as exc:
            diagnostic('file_error', source, reasons=[str(exc)])
    return report
