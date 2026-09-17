from .ipv4 import parse_ipv4


def parse_packet(packet):
    result = {}

    ipv4 = parse_ipv4(packet)

    if ipv4 is not None:
        result["network"] = ipv4

    return result