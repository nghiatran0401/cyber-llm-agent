from typing import List
import os
import re
from pathlib import Path

from langchain_community.document_loaders import TextLoader
from langchain_core.documents import Document

from ..config import get_settings


def _extract_ids_from_path(path: str) -> dict:
    """
    Infer technique_id and technique_name from a MITRE markdown filename.

    Example: T1047_Windows_Management_Instrumentation.md
    """
    filename = os.path.basename(path)
    name_no_ext, _ = os.path.splitext(filename)

    match = re.match(r"(T\d{4})(?:[_-](.*))?", name_no_ext)
    if not match:
        return {"technique_id": "", "technique_name": ""}

    technique_id = match.group(1)
    raw_name = match.group(2) or ""
    technique_name = raw_name.replace("_", " ").replace("-", " ").strip()

    return {"technique_id": technique_id, "technique_name": technique_name}


def load_mitre_documents() -> List[Document]:
    """
    Load all MITRE markdown documents from the configured data directory and
    normalize basic metadata (technique_id, technique_name).
    """
    settings = get_settings()

    data_dir = Path(settings.data_path)
    md_files = sorted(data_dir.glob("*.md"))

    docs: List[Document] = []
    for path in md_files:
        # TextLoader avoids the `unstructured` dependency path used by many
        # other loader implementations.
        loader = TextLoader(str(path), encoding="utf-8")
        loaded = loader.load()
        for doc in loaded:
            # Ensure `source` metadata is consistent for downstream provenance.
            doc.metadata.setdefault("source", str(path))
            docs.append(doc)

    for doc in docs:
        source = doc.metadata.get("source") or doc.metadata.get("file_path")
        if source:
            ids = _extract_ids_from_path(source)
            doc.metadata.update(ids)

    return docs

