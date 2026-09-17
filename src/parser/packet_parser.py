from scapy.layers.inet import TCP, UDP

from .ipv4 import parse_ipv4
from .tcp import parse_tcp
from .udp import parse_udp


def parse_packet(packet):
    result = {}

    ipv4 = parse_ipv4(packet)

    if ipv4 is None:
        return None

    result["network"] = ipv4

    if packet.haslayer(TCP):
        result["transport"] = {
            "protocol": "TCP",
            **parse_tcp(packet)
        }

    elif packet.haslayer(UDP):
        result["transport"] = {
            "protocol": "UDP",
            **parse_udp(packet)
        }

    else:
        result["transport"] = None

    return result