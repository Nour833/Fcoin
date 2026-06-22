"""Durable, hash-chained transaction journals."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from fcoin.errors import ValidationError


GENESIS = "0" * 64


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Journal:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        result: list[dict[str, Any]] = []
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValidationError("Journal event is not an object.")
                    result.append(value)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Could not read journal {self.path}: {exc}") from exc
        return result

    def verify(self) -> None:
        previous = GENESIS
        for index, event in enumerate(self.events()):
            claimed_hash = event.get("event_hash")
            content = {key: value for key, value in event.items() if key != "event_hash"}
            if content.get("previous_hash") != previous:
                raise ValidationError(f"Journal chain breaks at event {index}.")
            calculated = hashlib.sha256(_canonical(content)).hexdigest()
            if claimed_hash != calculated:
                raise ValidationError(f"Journal hash is invalid at event {index}.")
            previous = calculated

    def append(self, event_type: str, **payload: Any) -> dict[str, Any]:
        existing = self.events()
        self.verify()
        previous = existing[-1]["event_hash"] if existing else GENESIS
        content = {
            "sequence": len(existing),
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event_type,
            "previous_hash": previous,
            **payload,
        }
        event = {**content, "event_hash": hashlib.sha256(_canonical(content)).hexdigest()}
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "a", encoding="utf-8", closefd=False) as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        self.path.chmod(0o600)
        return event
