"""Session persistence utilities for memory-enabled conversations."""

import json
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

    def save_session(self, session_id: str, payload: Dict[str, Any]):
        """Persist session payload to disk."""
        self.prune_expired_sessions()
        session_file = self._session_path(session_id)
        data = {
            "session_id": session_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        with open(session_file, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def load_session(self, session_id: str) -> Dict[str, Any]:
        """Read previously saved session payload."""
        session_file = self._session_path(session_id)
        if not session_file.exists():
            return {}
        with open(session_file, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def prune_expired_sessions(self):
        """Delete expired session files based on retention policy."""
        retention_seconds = max(1, Settings.SESSION_RETENTION_DAYS) * 24 * 60 * 60
        now = datetime.now(timezone.utc)
        for session_file in self.session_dir.glob("*.json"):
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
                # Keep best-effort cleanup non-fatal for runtime paths.
                continue

