import argparse

from src.capture.capture import capture_live, read_pcap


def handle_packet(packet):
    # Smoke test hiện tại
    print(packet.summary())

    # TODO:
    # Sau này thay bằng:
    # event = parse_packet(packet)
    # logger.write(event)


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