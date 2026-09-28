from scapy.layers.inet import TCP


def parse_tcp(packet):
    if not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]

    return {
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "seq": tcp.seq,
        "ack": tcp.ack,
        "flags": str(tcp.flags),
        "window": tcp.window,
    }