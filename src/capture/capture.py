from scapy.all import sniff, PcapReader, get_if_list


def capture_live(interface, handler):
    interfaces = get_if_list()
    if interface not in interfaces:
        raise ValueError(
            f"Interface '{interface}' not found. Available interfaces: {', '.join(interfaces)}"
        )
    sniff(
        iface=interface,
        prn=handler,
        store=False
    )


def read_pcap(path, handler):
    with PcapReader(path) as reader:
        for packet in reader:
            handler(packet)
