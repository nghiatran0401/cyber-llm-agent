import os
from typing import Any

from openai import OpenAI

from ..config import get_settings


def get_llm_client() -> OpenAI:
    """
    Return an OpenRouter-backed OpenAI client instance.
    """
    settings = get_settings()
    api_key = settings.openrouter_api_key or os.getenv("OPENROUTER_API_KEY", "")
    return OpenAI(api_key=api_key, base_url=settings.openrouter_base_url)


def create_chat_completion(messages: list[dict[str, Any]], model: str | None = None):
    """
    Convenience wrapper to create a chat completion.
    """
    settings = get_settings()
    client = get_llm_client()
    return client.chat.completions.create(
        model=model or settings.mitre_model,
        messages=messages,
    )

