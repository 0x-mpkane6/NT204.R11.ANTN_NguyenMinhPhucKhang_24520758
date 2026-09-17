from scapy.layers.inet import UDP


def parse_udp(packet):
    if not packet.haslayer(UDP):
        return None

    udp = packet[UDP]

    return {
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "length": udp.len,
        "checksum": udp.chksum,
    }