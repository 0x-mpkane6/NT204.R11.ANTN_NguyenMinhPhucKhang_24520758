import ipaddress
import re


class UnsupportedRule(ValueError):
    pass


def address(value):
    if value == 'any':
        return value
    if value.startswith(('$', '!', '[')):
        raise UnsupportedRule('Address variables, negation and lists are unsupported')
    network = ipaddress.ip_network(value, strict=False)
    if network.version != 4:
        raise UnsupportedRule('Only IPv4 addresses are supported')
    return str(network)


def number(value, minimum=0, maximum=2147483647):
    if not re.fullmatch(r'[0-9]+', value):
        raise ValueError('Expected unsigned integer: ' + value)
    result = int(value)
    if not minimum <= result <= maximum:
        raise ValueError('Integer out of range: ' + value)
    return result


def port(value):
    if value == 'any':
        return (0, 65535)
    if value.startswith(('$', '!', '[')):
        raise UnsupportedRule('Port variables, negation and lists are unsupported')
    if ':' in value:
        parts = value.split(':')
        if len(parts) != 2:
            raise ValueError('Invalid port range')
        low = number(parts[0], maximum=65535) if parts[0] else 0
        high = number(parts[1], maximum=65535) if parts[1] else 65535
        if low > high:
            raise ValueError('Reversed port range')
        return low, high
    value = number(value, maximum=65535)
    return value, value


def validate(rule):
    for index, content in enumerate(rule.contents):
        relative = content.distance is not None or content.within is not None
        if relative and index == 0:
            raise ValueError('Relative content requires a preceding content')
        if relative and (content.offset is not None or content.depth is not None):
            raise ValueError('Cannot combine absolute and relative content modifiers')
        for value in (content.depth, content.within):
            if value is not None and value < len(content.pattern):
                raise ValueError('Content window smaller than pattern')
    if {'to_server', 'to_client'} <= set(rule.flow):
        raise ValueError('Conflicting flow directions')
    if {'established', 'not_established'} <= set(rule.flow):
        raise ValueError('Conflicting flow states')
    if rule.flags is not None and rule.header.protocol != 'tcp':
        raise ValueError('flags requires TCP')
    if set(rule.flow) & {'established', 'not_established'} and rule.header.protocol != 'tcp':
        raise ValueError('TCP connection state requires TCP')
