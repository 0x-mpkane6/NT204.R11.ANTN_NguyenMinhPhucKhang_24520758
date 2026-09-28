import argparse
import json
import sys

from scapy.error import Scapy_Exception
from datetime import datetime, timezone
from functools import partial
from itertools import count
from pathlib import Path

from src.logging.jsonl_writer import JsonlWriter
from src.capture.capture import capture_live, read_pcap
from src.parser.packet_parser import parse_packet


def handle_packet(packet, writer, packet_ids):
    try:
        parsed = parse_packet(packet)
        if parsed is None:
            return
        parsed["timestamp"] = datetime.fromtimestamp(
            float(packet.time), tz=timezone.utc
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")
        json.dumps(parsed, ensure_ascii=False, allow_nan=False)
    except Exception as exc:
        print(f"Skipping malformed packet: {type(exc).__name__}: {exc}", file=sys.stderr)
        return
    parsed["packet_id"] = next(packet_ids)
    writer.write(parsed)
    print(f"\n{'=' * 64}\nPacket #{parsed['packet_id']} | {parsed['timestamp']}")
    print(json.dumps(parsed, ensure_ascii=False, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", type=str)
    source.add_argument("--pcap", type=str)
    parser.add_argument(
        "--output", type=Path,
        help="Output file (default: output/events_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl)",
    )
    args = parser.parse_args()
    if args.output is None:
        started_at = datetime.now().astimezone().strftime("%H-%M-%S-%f_%d-%m-%Y")
        args.output = Path(__file__).resolve().parent / "output" / f"events_{started_at}.jsonl"

    try:
        with JsonlWriter(args.output) as writer:
            print(f"Source: {args.interface or args.pcap}")
            print(f"JSONL output: {writer.path.resolve()}", flush=True)
            handler = partial(handle_packet, writer=writer, packet_ids=count(1))
            if args.interface:
                capture_live(args.interface, handler)
            else:
                read_pcap(args.pcap, handler)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, EOFError, Scapy_Exception) as exc:
        parser.exit(1, f"Capture/logging error: {exc}\n")


if __name__ == "__main__":
    main()
