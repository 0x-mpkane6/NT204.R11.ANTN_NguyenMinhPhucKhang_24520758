import json

import pytest

from src.logging.jsonl_writer import JsonlWriter


def test_write_events_and_skip_none(tmp_path):
    path = tmp_path / "logs" / "events.jsonl"
    events = [{"packet_id": 1, "message": "Tiếng Việt\nxuống dòng"},
              {"packet_id": 2, "application": {"protocol": "UNKNOWN"}}]
    with JsonlWriter(path) as writer:
        writer.write(None)
        for event in events:
            writer.write(event)
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert [json.loads(line) for line in lines] == events


def test_append_preserves_existing_events(tmp_path):
    path = tmp_path / "events.jsonl"
    for ident in (1, 2):
        with JsonlWriter(path) as writer:
            writer.write({"packet_id": ident})
    assert [json.loads(line)["packet_id"] for line in path.read_text().splitlines()] == [1, 2]


@pytest.mark.parametrize("event", [[], {"bad": object()}, {"bad": float("nan")}])
def test_invalid_event_does_not_add_a_line(tmp_path, event):
    path = tmp_path / "events.jsonl"
    with JsonlWriter(path) as writer:
        with pytest.raises((TypeError, ValueError)):
            writer.write(event)
        writer.write({"packet_id": 1})
    assert path.read_text().splitlines() == ['{"packet_id": 1}']


def test_context_closes_on_error(tmp_path):
    with pytest.raises(RuntimeError):
        with JsonlWriter(tmp_path / "events.jsonl") as writer:
            writer.write({"packet_id": 1})
            raise RuntimeError("capture failed")
    with pytest.raises(ValueError, match="closed"):
        writer.write({"packet_id": 2})
    writer.close()
