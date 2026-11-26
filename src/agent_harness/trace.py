"""Append-only JSONL trace of every step, and summary metrics for monitoring."""

import json
import threading
import time
from pathlib import Path


class Trace:
    def __init__(self, path: str | Path | None = None):
        self.events: list[dict] = []
        self.path = Path(path) if path else None
        self._lock = threading.Lock()

    def log(self, kind: str, **data) -> None:
        event = {"t": round(time.time(), 3), "kind": kind, **data}
        with self._lock:
            self.events.append(event)
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    def summary(self) -> dict:
        kinds = [e["kind"] for e in self.events]
        start = self.events[0]["t"] if self.events else 0
        return {
            "model_calls": kinds.count("model"),
            "tool_calls": kinds.count("tool"),
            "tool_errors": kinds.count("tool_error"),
            "blocked": kinds.count("blocked"),
            "tokens": sum(e.get("tokens", 0) for e in self.events if e["kind"] == "model"),
            "seconds": round((self.events[-1]["t"] - start) if self.events else 0, 3),
        }
