"""Session persistence utilities for memory-enabled conversations."""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from src.config.settings import Settings


class SessionManager:
    """Load and save conversational sessions as JSON."""

    def __init__(self, session_dir: Optional[Path] = None):
        self.session_dir = Path(session_dir or Settings.SESSIONS_DIR)
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def _session_path(self, session_id: str) -> Path:
        safe_id = "".join(ch for ch in session_id if ch.isalnum() or ch in {"-", "_"})
        return self.session_dir / f"{safe_id}.json"

    @staticmethod
    def _validate_session_id(session_id: str) -> None:
        if not session_id or not session_id.strip():
            raise ValueError("session_id must be non-empty")
        for ch in session_id:
            if not (ch.isalnum() or ch in {"-", "_"}):
                raise ValueError(f"session_id contains invalid character: {ch!r}")

    def save_session(self, session_id: str, payload: Dict[str, Any]):
        """Persist session payload to disk using a temp file and atomic replace."""
        self._validate_session_id(session_id)
        self.prune_expired_sessions()
        session_file = self._session_path(session_id)
        data = {
            "session_id": session_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        fd, tmp_path = tempfile.mkstemp(
            dir=self.session_dir, prefix=".session_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            os.replace(tmp_path, session_file)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load_session(self, session_id: str) -> Dict[str, Any]:
        """Read previously saved session payload."""
        self._validate_session_id(session_id)
        session_file = self._session_path(session_id)
        if not session_file.exists():
            return {}
        try:
            with open(session_file, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except json.JSONDecodeError:
            corrupt_path = session_file.with_name(session_file.stem + ".corrupt.json")
            try:
                session_file.rename(corrupt_path)
            except OSError:
                pass
            return {}

    def prune_expired_sessions(self):
        """Delete expired session files based on retention policy."""
        retention_seconds = max(1, Settings.SESSION_RETENTION_DAYS) * 24 * 60 * 60
        now = datetime.now(timezone.utc)
        for session_file in self.session_dir.glob("*.json"):
            if session_file.name.endswith(".corrupt.json"):
                continue
            try:
                with open(session_file, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                updated_at = data.get("updated_at")
                if not updated_at:
                    continue
                updated_time = datetime.fromisoformat(str(updated_at))
                age_seconds = (now - updated_time).total_seconds()
                if age_seconds > retention_seconds:
                    session_file.unlink(missing_ok=True)
            except Exception:
                continue
