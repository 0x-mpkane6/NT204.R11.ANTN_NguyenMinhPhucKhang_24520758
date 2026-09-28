import json
from pathlib import Path


class JsonlWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a", encoding="utf-8", newline="\n")

    def write(self, event):
        if self._file.closed:
            raise ValueError("Cannot write to a closed JSONL writer")
        if event is None:
            return
        if not isinstance(event, dict):
            raise TypeError("Event must be a dictionary or None")

        line = json.dumps(event, ensure_ascii=False, allow_nan=False)
        self._file.write(line + "\n")
        self._file.flush()

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
