import argparse
import json
import sys

from scapy.error import Scapy_Exception
from scapy.layers.inet import TCP
from datetime import datetime, timezone
from functools import partial
from itertools import count
from pathlib import Path

from src.logging.jsonl_writer import JsonlWriter
from src.capture.capture import capture_live, read_pcap
from src.parser.packet_parser import parse_packet
from src.decoder import decode_event
from src.preprocessor import preprocess_event
from src.flow import FlowTracker
import time


def handle_packet(packet, writer, packet_ids, tracker=None):
    try:
        parsed = parse_packet(packet)
        if parsed is None:
            return
        parsed["timestamp"] = datetime.fromtimestamp(
            float(packet.time), tz=timezone.utc
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")
        if packet.haslayer(TCP):
            parsed["transport"]["payload_length"] = len(bytes(packet[TCP].payload))
        parsed = decode_event(parsed)
        parsed = preprocess_event(parsed)
        if parsed["processing_action"] == "drop":
            return
        json.dumps(parsed, ensure_ascii=False, allow_nan=False)
    except Exception as exc:
        print(f"Skipping malformed packet: {type(exc).__name__}: {exc}", file=sys.stderr)
        return
    if tracker is not None:
        parsed = tracker.track(parsed)
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
    parser.add_argument('--flow-output', type=Path)
    parser.add_argument('--tcp-timeout', type=float, default=120)
    parser.add_argument('--udp-timeout', type=float, default=30)
    parser.add_argument('--max-flows', type=int, default=10000)
    args = parser.parse_args()
    if args.output is None:
        started_at = datetime.now().astimezone().strftime("%H-%M-%S-%f_%d-%m-%Y")
        args.output = Path(__file__).resolve().parent / "output" / f"events_{started_at}.jsonl"

    flow_path = args.flow_output or args.output.with_name('flows_' + args.output.stem.removeprefix('events_') + '.jsonl')
    if flow_path.resolve() == args.output.resolve():
        parser.error('Event and flow output paths must differ')
    try:
        tracker = FlowTracker(args.tcp_timeout, args.udp_timeout, args.max_flows)
        with JsonlWriter(args.output) as writer, JsonlWriter(flow_path) as flow_writer:
            tracker.emit = flow_writer.write
            print(f"Source: {args.interface or args.pcap}")
            print(f"JSONL output: {writer.path.resolve()}", flush=True)
            print(f"Flow output: {flow_writer.path.resolve()}", flush=True)
            handler = partial(handle_packet, writer=writer, packet_ids=count(1), tracker=tracker)
            reason = 'end_of_input'
            try:
                if args.interface:
                    capture_live(args.interface, handler, on_idle=lambda: tracker.expire(time.time()))
                else:
                    read_pcap(args.pcap, handler)
            except KeyboardInterrupt:
                reason = 'interrupted'
                raise
            except Exception:
                reason = 'capture_error'
                raise
            finally:
                tracker.flush(reason)

    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, EOFError, Scapy_Exception) as exc:
        parser.exit(1, f"Capture/logging error: {exc}\n")


if __name__ == "__main__":
    main()
