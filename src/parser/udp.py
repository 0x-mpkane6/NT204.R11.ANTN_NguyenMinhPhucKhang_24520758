from scapy.layers.inet import UDP

from .content import raw_base64


def parse_udp(packet):
    if not packet.haslayer(UDP):
        return None

    udp = packet[UDP]

    payload = bytes(udp.payload)

    return {
        "payload_length": len(payload),
        "raw_payload_base64": raw_base64(payload),
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "length": udp.len,
        "checksum": udp.chksum,
    }