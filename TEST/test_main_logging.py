import json
import sys

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

import main


@pytest.mark.parametrize("source", ["--interface", "--pcap"])
def test_capture_writes_events(tmp_path, monkeypatch, source):
    path = tmp_path / "output" / "events.jsonl"
    packet = IP()/TCP()/Raw(b"GET / HTTP/1.1\r\n\r\n")
    packet.time = 0

    def capture(value, handler):
        assert value == "test-source"
        handler(Raw(b"unsupported"))
        handler(packet)
        handler(packet)

    monkeypatch.setattr(main, "capture_live", capture)
    monkeypatch.setattr(main, "read_pcap", capture)
    monkeypatch.setattr(sys, "argv", ["main.py", source, "test-source", "--output", str(path)])
    main.main()
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [event["packet_id"] for event in events] == [1, 2]
    assert all(event["timestamp"] == "1970-01-01T00:00:00.000000Z" for event in events)
    assert all(event["application"]["protocol"] == "HTTP" for event in events)
