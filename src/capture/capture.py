from scapy.all import sniff, PcapReader


def capture_live(interface, handler):
    sniff(
        iface=interface,
        prn=handler,
        store=False
    )


def read_pcap(path, handler):
    with PcapReader(path) as reader:
        for packet in reader:
            handler(packet)