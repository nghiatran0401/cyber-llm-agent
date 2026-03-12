import json
import re
from dataclasses import dataclass, field
from typing import List

from ..logging_config import setup_logging
from ..llm.client import create_chat_completion
from ..llm.utils import strip_markdown_fences


logger = setup_logging()


@dataclass
class RewrittenQuery:
    normalized_question: str
    sub_questions: List[str] = field(default_factory=list)
    key_phrases: List[str] = field(default_factory=list)
    technique_ids: List[str] = field(default_factory=list)


REWRITER_SYSTEM_PROMPT = """
You are a query rewriting assistant for a cybersecurity RAG system using MITRE ATT&CK
and CTI data.

Given a raw user input (which may be a short question or a noisy log snippet),
you will:
- Normalize it into a concise question about attacker behaviour or techniques.
- Optionally break it into 1-3 focused sub-questions.
- Extract 3-10 key phrases for retrieval (e.g., process names, ATT&CK concepts).
- Extract any explicit MITRE technique IDs mentioned (e.g., T1047).

Return ONLY JSON in this exact format:
{
  "normalized_question": "",
  "sub_questions": [],
  "key_phrases": [],
  "technique_ids": []
}
"""


def rewrite_query(raw_input: str) -> RewrittenQuery:
    """
    Use an LLM to rewrite and enrich the user query for retrieval.
    """
    response = create_chat_completion(
        messages=[
            {"role": "system", "content": REWRITER_SYSTEM_PROMPT},
            {"role": "user", "content": raw_input},
        ]
    )

    raw_output = response.choices[0].message.content or ""
    cleaned = strip_markdown_fences(raw_output)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("Query rewriter returned invalid JSON, falling back.")
        # Fallback: basic heuristic extraction
        technique_ids = re.findall(r"\\bT\\d{4}\\b", raw_input)
        return RewrittenQuery(
            normalized_question=raw_input.strip(),
            sub_questions=[],
            key_phrases=[],
            technique_ids=technique_ids,
        )

    return RewrittenQuery(
        normalized_question=data.get("normalized_question", raw_input).strip(),
        sub_questions=list(data.get("sub_questions", [])),
        key_phrases=list(data.get("key_phrases", [])),
        technique_ids=list(data.get("technique_ids", [])),
    )


