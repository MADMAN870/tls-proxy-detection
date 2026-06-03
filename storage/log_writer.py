import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


class TrafficLogger:
    def __init__(self, log_dir: str = "/data/traffic"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._current_file: Optional[Path] = None
        self._file_handle = None

    def _ensure_file(self):
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = self.log_dir / f"traffic-{date_str}.log"
        if path != self._current_file:
            if self._file_handle:
                self._file_handle.close()
            self._current_file = path
            self._file_handle = open(path, "a")

    def write(self, record: dict):
        self._ensure_file()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **record,
        }
        self._file_handle.write(json.dumps(entry) + "\n")
        self._file_handle.flush()

    def close(self):
        if self._file_handle:
            self._file_handle.close()
