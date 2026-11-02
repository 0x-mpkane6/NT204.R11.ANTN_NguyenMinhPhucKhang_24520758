import json
import subprocess
import sys
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap


ROOT = Path(__file__).resolve().parents[2]


def test_cli_pcap_multiple_detection_and_disable(tmp_path):
    pcap = tmp_path/'input.pcap'
    wrpcap(str(pcap), [Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=12345, dport=80, flags='PA')/Raw(b'GET /../ HTTP/1.1\r\n\r\n')])
    rules = tmp_path/'local.rules'
    rules.write_text('broken rule\n' + '\n'.join(
        f'alert tcp any any -> any 80 (msg:"test"; content:"GET"; sid:{sid}; rev:1;)'
        for sid in (1, 2, 3)))
    paths = [tmp_path/name for name in ('events.jsonl', 'flows.jsonl', 'detections.jsonl')]
    command = [sys.executable, '-B', str(ROOT/'main.py'), '--pcap', str(pcap), '--rules', str(rules),
               '--disable-sid', '3', '--output', str(paths[0]), '--flow-output', str(paths[1]),
               '--detection-output', str(paths[2])]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    detections = [json.loads(line) for line in paths[2].read_text().splitlines()]
    assert [d['sid'] for d in detections] == [1, 2]
    event = json.loads(paths[0].read_text().splitlines()[0])
    assert event['evaluation']['detection_count'] == 2
    assert all(d['flow_id'] == event['flow']['flow_id'] for d in detections)
    assert 'invalid' in result.stderr and 'Engine statistics' in result.stdout


def test_live_callback_uses_engine(tmp_path, monkeypatch):
    import main
    rules = tmp_path/'sample.rules'
    rules.write_text('alert tcp any any -> any 80 (msg:"live"; sid:1; rev:1;)')
    def capture(interface, handler, on_idle=None):
        handler(IP(bytes(IP()/TCP(dport=80))))
    monkeypatch.setattr(main, 'capture_live', capture)
    monkeypatch.setattr(sys, 'argv', ['main.py', '--interface', 'fake', '--rules', str(rules),
                                     '--output', str(tmp_path/'events.jsonl')])
    main.main()
    assert json.loads((tmp_path/'detections_events.jsonl').read_text())['sid'] == 1
