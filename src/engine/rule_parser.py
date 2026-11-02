import re

from .models import ContentCondition, Rule, RuleHeader, RuleParseResult
from .rule_validator import UnsupportedRule, address, number, port, validate


def split_options(text):
    quoted = escaped = False
    start = 0
    options = []
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == '\\' and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ';' and not quoted:
            option = text[start:index].strip()
            if option:
                options.append(option)
            start = index + 1
    if quoted or escaped:
        raise ValueError('Unterminated quoted string')
    if text[start:].strip():
        raise ValueError('Options must end with semicolon')
    return options


def quoted(value, binary=False):
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ValueError('Expected quoted string')
    value = value[1:-1]
    result = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == '\\':
            index += 1
            if index == len(value):
                raise ValueError('Incomplete escape')
            if value[index] not in '\\";:|':
                raise UnsupportedRule('Unsupported escape: \\' + value[index])
            result.extend(value[index].encode('utf-8'))
        elif char == '"':
            raise ValueError('Unescaped quote')
        elif char == '|' and binary:
            end = value.find('|', index + 1)
            if end < 0:
                raise ValueError('Unterminated hex block')
            block = value[index + 1:end].strip()
            if not re.fullmatch(r'[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*', block):
                raise ValueError('Invalid hex content')
            result.extend(bytes.fromhex(block))
            index = end
        else:
            result.extend(char.encode('utf-8'))
        index += 1
    return bytes(result) if binary else result.decode('utf-8')


def parse_rule(text, source=None, line_number=None):
    try:
        if not isinstance(text, str):
            raise ValueError('Rule must be text')
        match = re.fullmatch(r'\s*([^()]+?)\s*\((.*)\)\s*', text, re.S)
        if not match:
            raise ValueError('Expected header followed by parenthesized options')
        fields = match[1].split()
        if len(fields) != 7:
            raise ValueError('Header must contain seven fields')
        action, protocol, src, sport, direction, dst, dport = fields
        if action != 'alert':
            raise UnsupportedRule('Unsupported action: ' + action)
        if protocol not in ('tcp', 'udp', 'ip', 'any'):
            raise UnsupportedRule('Unsupported protocol: ' + protocol)
        if direction not in ('->', '<>'):
            raise UnsupportedRule('Unsupported direction: ' + direction)
        header = RuleHeader(action, protocol, address(src), port(sport), direction, address(dst), port(dport))
        values, contents = {}, []
        seen_modifiers = set()
        for option in split_options(match[2]):
            key, colon, value = option.partition(':')
            key, value = key.strip(), value.strip()
            if key == 'content':
                if value.startswith('!'):
                    raise UnsupportedRule('Negated content is unsupported')
                pattern = quoted(value, binary=True)
                if not pattern:
                    raise ValueError('Empty content')
                contents.append(ContentCondition(pattern))
                seen_modifiers = set()
            elif key in ('nocase', 'offset', 'depth', 'distance', 'within'):
                if not contents:
                    raise ValueError(key + ' requires preceding content')
                if key in seen_modifiers:
                    raise ValueError('Duplicate modifier: ' + key)
                seen_modifiers.add(key)
                if key == 'nocase':
                    if colon:
                        raise ValueError('nocase takes no argument')
                    contents[-1].nocase = True
                else:
                    setattr(contents[-1], key, number(value, minimum=1 if key in ('depth', 'within') else 0))
            else:
                if key not in ('msg', 'sid', 'rev', 'flow', 'flags', 'dsize', 'classtype', 'priority'):
                    raise UnsupportedRule('Unsupported keyword: ' + key)
                if key in values:
                    raise ValueError('Duplicate option: ' + key)
                if not colon or not value:
                    raise ValueError('Missing option value: ' + key)
                if key == 'msg':
                    values[key] = quoted(value)
                elif key in ('sid', 'rev', 'priority'):
                    values[key] = number(value, minimum=1)
                elif key == 'flow':
                    items = tuple(item.strip() for item in value.split(','))
                    if len(set(items)) != len(items):
                        raise ValueError('Duplicate flow option')
                    if any(item not in ('to_server', 'to_client', 'established', 'not_established') for item in items):
                        raise UnsupportedRule('Unsupported flow option')
                    values[key] = items
                elif key == 'flags':
                    if any(char in value for char in '+*! ,'):
                        raise UnsupportedRule('Flag masks/modifiers are unsupported')
                    if not re.fullmatch(r'[FSRPAUEC]+|0', value) or len(set(value)) != len(value):
                        raise ValueError('Invalid TCP flags')
                    values[key] = value
                elif key == 'dsize':
                    expr = re.fullmatch(r'([<>]?)([0-9]+)(?:\s*<>\s*([0-9]+))?', value)
                    if not expr:
                        raise ValueError('Invalid dsize expression')
                    op, low, high = expr.groups()
                    low = number(low, maximum=65535)
                    high = number(high, maximum=65535) if high else None
                    if high is not None and (op or low >= high):
                        raise ValueError('Invalid dsize range')
                    values[key] = ('range' if high is not None else op or '=', low, high)
                else:
                    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
                        raise ValueError('Invalid classtype')
                    values[key] = value
        missing = {'msg', 'sid', 'rev'} - values.keys()
        if missing:
            raise ValueError('Missing required options: ' + ', '.join(sorted(missing)))
        rule = Rule(header=header, contents=contents, source=source, line_number=line_number, raw=text, **values)
        validate(rule)
        return RuleParseResult('valid', [], rule, source, line_number)
    except UnsupportedRule as exc:
        return RuleParseResult('unsupported', [str(exc)], source=source, line_number=line_number)
    except (ValueError, TypeError, OverflowError) as exc:
        return RuleParseResult('invalid', [str(exc)], source=source, line_number=line_number)
