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
from src.decoder import decode_event
from src.preprocessor import preprocess_event
from src.flow import FlowTracker
from src.engine import RuleFile, load_rules, RuleRepository, RuleMatcher, EvaluationEngine
import time


def handle_packet(packet, writer, packet_ids, tracker=None, engine=None, detection_writer=None):
    try:
        parsed = parse_packet(packet)
        if parsed is None:
            return
        parsed["timestamp"] = datetime.fromtimestamp(
            float(packet.time), tz=timezone.utc
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")
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
    if engine is not None:
        evaluation = engine.evaluate(parsed)
        parsed['evaluation'] = {'status': evaluation.status,
                                'candidate_count': evaluation.candidate_count,
                                'evaluated_count': evaluation.evaluated_count,
                                'detection_count': len(evaluation.detections),
                                'diagnostics': evaluation.diagnostics}
        for detection in evaluation.detections:
            detection_writer.write(detection)
            print(f"[DETECTION] sid={detection['sid']} packet={parsed['packet_id']} {detection['msg']}", flush=True)
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
    parser.add_argument('--rules', type=Path, action='append', help='Rule file; repeat for multiple files')
    parser.add_argument('--disable-rule-file', type=Path, action='append', default=[])
    parser.add_argument('--disable-sid', type=int, action='append', default=[])
    parser.add_argument('--enable-sid', type=int, action='append', help='SID allowlist; repeat to allow more')
    parser.add_argument('--detection-output', type=Path)
    parser.add_argument('--allow-inferred-established', action='store_true')
    args = parser.parse_args()
    if args.output is None:
        started_at = datetime.now().astimezone().strftime("%H-%M-%S-%f_%d-%m-%Y")
        args.output = Path(__file__).resolve().parent / "output" / f"events_{started_at}.jsonl"

    flow_path = args.flow_output or args.output.with_name('flows_' + args.output.stem.removeprefix('events_') + '.jsonl')
    detection_path = args.detection_output or args.output.with_name('detections_' + args.output.stem.removeprefix('events_') + '.jsonl')
    rule_paths = args.rules if args.rules is not None else [Path(__file__).resolve().parent / 'rules' / 'local.rules']
    output_paths = [args.output.resolve(), flow_path.resolve(), detection_path.resolve()]
    if len(set(output_paths)) != 3:
        parser.error('Event, flow and detection output paths must differ')
    inputs = {p.resolve() for p in rule_paths}
    if args.pcap:
        inputs.add(Path(args.pcap).resolve())
    if inputs.intersection(output_paths):
        parser.error('Output path must not overwrite an input file')
    try:
        tracker = FlowTracker(args.tcp_timeout, args.udp_timeout, args.max_flows)
        disabled_files = {p.resolve() for p in args.disable_rule_file}
        report = load_rules([RuleFile(p, p.resolve() not in disabled_files) for p in rule_paths],
                            disabled_sids=args.disable_sid, enabled_sids=args.enable_sid)
        print('Rule loading: ' + json.dumps(report.counts), flush=True)
        for diagnostic in report.diagnostics:
            print('Rule diagnostic: ' + json.dumps(diagnostic), file=sys.stderr)
        if not report.rules:
            print('WARNING: No active rules; no detections will be generated.', file=sys.stderr)
        engine = EvaluationEngine(RuleRepository(report.rules),
                                  RuleMatcher(allow_inferred_established=args.allow_inferred_established))
        with JsonlWriter(args.output) as writer, JsonlWriter(flow_path) as flow_writer, JsonlWriter(detection_path) as detection_writer:
            tracker.emit = flow_writer.write
            print(f"Source: {args.interface or args.pcap}")
            print(f"JSONL output: {writer.path.resolve()}", flush=True)
            print(f"Flow output: {flow_writer.path.resolve()}", flush=True)
            print(f"Detection output: {detection_writer.path.resolve()}", flush=True)
            handler = partial(handle_packet, writer=writer, packet_ids=count(1), tracker=tracker,
                              engine=engine, detection_writer=detection_writer)
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
                print('Engine statistics: ' + json.dumps(engine.stats), flush=True)

    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, EOFError, Scapy_Exception) as exc:
        parser.exit(1, f"Capture/logging error: {exc}\n")


if __name__ == "__main__":
    main()
