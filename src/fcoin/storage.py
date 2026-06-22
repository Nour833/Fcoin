"""Secure immutable session storage."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
from typing import Any

from fcoin.dump import CardImage
from fcoin.errors import ValidationError


def default_home() -> Path:
    override = os.environ.get("FCOIN_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".local" / "share" / "fcoin").resolve()


def _secure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _secure_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


class Session:
    def __init__(self, path: Path):
        self.path = path.resolve()

    @property
    def id(self) -> str:
        return self.path.name

    @property
    def metadata_path(self) -> Path:
        return self.path / "metadata.json"

    def metadata(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Invalid session metadata in {self.path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValidationError("Session metadata must be a JSON object.")
        return raw

    def update_metadata(self, **updates: Any) -> None:
        metadata = self.metadata()
        metadata.update(updates)
        _secure_json(self.metadata_path, metadata)

    def image(self, name: str = "before.mfd") -> CardImage:
        return CardImage.from_file(self.path / name)

    def secure_path(self, name: str) -> Path:
        if "/" in name or name in {".", ".."}:
            raise ValidationError("Session filenames must be simple relative names.")
        return self.path / name


class SessionStore:
    def __init__(self, home: str | Path | None = None):
        self.home = Path(home).expanduser().resolve() if home else default_home()
        self.sessions = self.home / "sessions"

    def create(
        self,
        first: CardImage,
        second: CardImage | None = None,
        *,
        source: str,
        acquisition_log: str = "",
    ) -> Session:
        _secure_directory(self.sessions)
        if second is not None and first.data != second.data:
            raise ValidationError(
                "Independent card reads differ. No trusted snapshot was created."
            )
        uid = first.manufacturer.uid_hex
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        safe_uid = re.sub(r"[^A-F0-9]", "", uid)[:16] or "UNKNOWN"
        session_path = _secure_directory(self.sessions / f"{timestamp}-{safe_uid}")
        session = Session(session_path)
        first.write_secure(session.secure_path("before.mfd"))
        if second is not None:
            second.write_secure(session.secure_path("confirmation.mfd"))
        metadata = {
            "schema_version": 1,
            "session_id": session.id,
            "created_at": datetime.now(tz=UTC).isoformat(),
            "source": source,
            "card_type": first.geometry.name,
            "byte_size": len(first.data),
            "uid": uid,
            "sha256": first.sha256,
            "double_read_verified": second is not None,
            "status": "snapshot",
        }
        _secure_json(session.metadata_path, metadata)
        if acquisition_log:
            log_path = session.secure_path("acquisition.log")
            log_path.write_text(acquisition_log, encoding="utf-8")
            log_path.chmod(0o600)
        return session

    def get(self, session_id: str) -> Session:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", session_id):
            raise ValidationError("Invalid session identifier.")
        path = self.sessions / session_id
        if not path.is_dir():
            raise ValidationError(f"Session {session_id!r} does not exist.")
        return Session(path)

    def list(self) -> tuple[Session, ...]:
        if not self.sessions.is_dir():
            return ()
        return tuple(
            Session(path)
            for path in sorted(self.sessions.iterdir(), reverse=True)
            if path.is_dir() and (path / "metadata.json").is_file()
        )
