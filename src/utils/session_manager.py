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

