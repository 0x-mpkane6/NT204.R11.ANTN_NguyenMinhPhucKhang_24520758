from scapy.layers.inet import IP


def parse_ipv4(packet):
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    return {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "ttl": ip.ttl,
        "protocol": ip.proto,
        "id": ip.id,
        "length": ip.len,
    }