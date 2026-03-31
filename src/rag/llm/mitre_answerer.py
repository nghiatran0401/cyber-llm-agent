import json
from typing import List

from ..data_models import MITRETechniqueResponse, RetrievedContext
from .client import create_chat_completion
from .prompts import MITRE_SYSTEM_PROMPT
from .utils import parse_json_response


def build_context_text(contexts: List[RetrievedContext]) -> str:
    context = ""
    for i, ctx in enumerate(contexts, start=1):
        source = ctx.metadata.get("source")
        context += f"""
SOURCE {i}
File: {source}

{ctx.document}
"""
    return context


def answer_mitre_query(user_query: str, contexts: List[RetrievedContext]) -> MITRETechniqueResponse:
    """
    Use the LLM to answer a MITRE query given retrieved contexts.
    """
    if not contexts:
        return MITRETechniqueResponse(
            technique_id="",
            technique_name="",
            tactic="",
            description="",
            detection="",
            mitigations="",
            error="No relevant MITRE information found.",
        )

    context_text = build_context_text(contexts)
    system_prompt = f"{MITRE_SYSTEM_PROMPT}\n\nSOURCES:\n{context_text}"

    response = create_chat_completion(
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Extract structured MITRE information for: {user_query}",
            },
        ]
    )

    raw_output = response.choices[0].message.content or ""

    try:
        parsed = parse_json_response(raw_output)
    except json.JSONDecodeError:
        # One retry with an explicit instruction to fix JSON.
        retry = create_chat_completion(
            messages=[
                {"role": "system", "content": "You previously returned invalid JSON. Return ONLY valid JSON now."},
                {"role": "user", "content": raw_output},
            ]
        )
        retry_raw = retry.choices[0].message.content or ""
        try:
            parsed = parse_json_response(retry_raw)
        except json.JSONDecodeError:
            return MITRETechniqueResponse(
                technique_id="",
                technique_name="",
                tactic="",
                description="",
                detection="",
                mitigations="",
                error="Model did not return valid JSON after retry",
            )

    return MITRETechniqueResponse(
        technique_id=parsed.get("technique_id", ""),
        technique_name=parsed.get("technique_name", ""),
        tactic=parsed.get("tactic", ""),
        description=parsed.get("description", ""),
        detection=parsed.get("detection", ""),
        mitigations=parsed.get("mitigations", ""),
    )

