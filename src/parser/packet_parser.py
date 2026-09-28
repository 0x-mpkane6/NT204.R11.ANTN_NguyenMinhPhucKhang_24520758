from scapy.layers.inet import TCP, UDP

from .application_detector import detect_application
from .dns import parse_dns
from .http import parse_http
from .ipv4 import parse_ipv4
from .smtp import parse_smtp
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

    protocol = detect_application(packet)
    parser = {"HTTP": parse_http, "DNS": parse_dns, "SMTP": parse_smtp}.get(protocol)
    application = parser(packet) if parser is not None else None
    result["application"] = application or {"protocol": "UNKNOWN"}

    return result
