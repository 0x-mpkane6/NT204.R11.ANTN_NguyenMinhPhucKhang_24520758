from scapy.layers.inet import TCP

from .content import raw_base64


def parse_tcp(packet):
    if not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]

    payload = bytes(tcp.payload)

    return {
        "payload_length": len(payload),
        "raw_payload_base64": raw_base64(payload),
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "seq": tcp.seq,
        "ack": tcp.ack,
        "flags": str(tcp.flags),
        "window": tcp.window,
    }