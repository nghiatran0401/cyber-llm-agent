import json
import re
from typing import Any, Dict


def strip_markdown_fences(text: str) -> str:
    """Remove leading/trailing markdown code fences from a model response."""
    cleaned = re.sub(r"^```json", "", text.strip())
    cleaned = re.sub(r"^```", "", cleaned)
    cleaned = re.sub(r"```$", "", cleaned)
    return cleaned.strip()


def parse_json_response(raw: str) -> Dict[str, Any]:
    """
    Parse a JSON response from the model after stripping markdown fences.

    Raises json.JSONDecodeError if parsing fails.
    """
    cleaned = strip_markdown_fences(raw)
    return json.loads(cleaned)

