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

    def save_session(self, session_id: str, payload: Dict[str, Any]) -> None:
        """Persist session payload atomically (write-temp-then-rename)."""
        self.prune_expired_sessions()
        session_file = self._session_path(session_id)
        data = {
            "session_id": session_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        # Write to a sibling temp file first, then atomically replace.
        fd, tmp_path = tempfile.mkstemp(
            dir=self.session_dir, prefix=f".{session_id}_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            os.replace(tmp_path, session_file)  # atomic on POSIX, best-effort on Windows
        except Exception:
            # Clean up the temp file if anything went wrong.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load_session(self, session_id: str) -> Dict[str, Any]:
        """Read previously saved session payload. Returns {} on missing or corrupt file."""
        session_file = self._session_path(session_id)
        if not session_file.exists():
            return {}
        try:
            with open(session_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("Session file root is not a JSON object")
            return data
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            # Back up the corrupt file for post-mortem, then return clean state.
            corrupt_path = session_file.with_suffix(".corrupt.json")
            try:
                session_file.rename(corrupt_path)
            except OSError:
                pass
            return {}

    def prune_expired_sessions(self) -> None:
        """Delete expired session files based on retention policy."""
        retention_seconds = max(1, Settings.SESSION_RETENTION_DAYS) * 24 * 60 * 60
        now = datetime.now(timezone.utc)
        for session_file in self.session_dir.glob("*.json"):
            # Never prune corrupt-backup files automatically.
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