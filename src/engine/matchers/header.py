import ipaddress


def match_header(header, context):
    if context['protocol'].lower() != header.protocol:
        return False
    src, dst = (ipaddress.IPv4Address(context[key]) for key in ('src_ip', 'dst_ip'))
    sport, dport = context['src_port'], context['dst_port']
    if any(type(p) is not int or not 0 <= p <= 65535 for p in (sport, dport)):
        return False
    def direction(a, b, ap, bp):
        return ((header.src_ip == 'any' or a in ipaddress.IPv4Network(header.src_ip)) and
                (header.dst_ip == 'any' or b in ipaddress.IPv4Network(header.dst_ip)) and
                header.src_port[0] <= ap <= header.src_port[1] and
                header.dst_port[0] <= bp <= header.dst_port[1])
    return direction(src, dst, sport, dport) or (header.direction == '<>' and direction(dst, src, dport, sport))
