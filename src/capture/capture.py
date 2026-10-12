from scapy.all import sniff, PcapReader, get_if_list
from scapy.error import Scapy_Exception


def capture_live(interface, handler, on_idle=None):
    interfaces = get_if_list()
    if interface not in interfaces:
        raise ValueError(
            f"Interface '{interface}' not found. Available interfaces: {', '.join(interfaces)}"
        )
    failures = []

    def dispatch(packet):
        try:
            handler(packet)
        except Exception as exc:
            failures.append(exc)

    while True:
        options = {'timeout': 1} if on_idle else {}
        sniff(
            iface=interface, prn=dispatch,
            stop_filter=lambda packet: bool(failures), store=False, **options
        )
        if failures or on_idle is None:
            break
        on_idle()

    if failures:
        raise failures[0]

def read_pcap(path, handler):
    try:
        reader = PcapReader(path)
    except Exception as exc:
        raise Scapy_Exception(f"Cannot open PCAP '{path}': {exc}") from exc
    with reader:
        packets = iter(reader)
        while True:
            try:
                packet = next(packets)
            except StopIteration:
                break
            except Exception as exc:
                raise Scapy_Exception(f"Cannot continue reading PCAP '{path}': {exc}") from exc
            handler(packet)
