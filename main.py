import argparse

from src.capture.capture import capture_live, read_pcap
from src.parser.packet_parser import parse_packet

def handle_packet(packet):
    # print(packet.summary()) smoke test
    parsed = parse_packet(packet)
    print(parsed)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--interface", type=str)
    parser.add_argument("--pcap", type=str)

    args = parser.parse_args()

    if args.interface:
        capture_live(args.interface, handle_packet)

    elif args.pcap:
        read_pcap(args.pcap, handle_packet)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()