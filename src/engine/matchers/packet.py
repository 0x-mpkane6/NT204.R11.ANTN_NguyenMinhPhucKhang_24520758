def match_packet(rule, context):
    if rule.flags is not None:
        flags = context.get('tcp_flags')
        if not isinstance(flags, str) or context.get('protocol', '').lower() != 'tcp':
            return False
        if set(flags.replace('0', '')) != set(rule.flags.replace('0', '')):
            return False
    if rule.dsize is not None:
        size = context.get('payload_size')
        if type(size) is not int or size < 0:
            return False
        op, low, high = rule.dsize
        if op == '=':
            return size == low
        if op == '>':
            return size > low
        if op == '<':
            return size < low
        if op == 'range':
            return low < size < high
        return False
    return True
