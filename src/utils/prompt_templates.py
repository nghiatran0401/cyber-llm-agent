"""Prompt template loader helpers."""

from __future__ import annotations

from functools import lru_cache

from src.utils.prompt_manager import PromptManager

_PROMPT_MANAGER = PromptManager()


@lru_cache(maxsize=128)
def load_prompt_template(name: str) -> str:
    """Load prompt template from prompts/."""
    return _PROMPT_MANAGER.load_prompt(name)


def render_prompt_template(name: str, **kwargs) -> str:
    """Render prompt template using str.format placeholders."""
    template = load_prompt_template(name)
    return template.format(**kwargs)
