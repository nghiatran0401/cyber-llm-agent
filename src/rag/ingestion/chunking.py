from typing import List

from langchain_core.documents import Document
from langchain_text_splitters import (
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)


def split_mitre_documents(documents: List[Document]) -> List[Document]:
    """
    Split MITRE markdown documents into smaller, retriever-friendly chunks.

    Step 1: split on markdown headers to respect MITRE structure.
    Step 2: apply a token/character-based splitter for final chunk size
            control while preserving metadata.
    """
    headers_to_split_on = [
        ("#", "Technique"),
        ("##", "Section"),
    ]

    header_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=headers_to_split_on
    )

    # Approximate token-based splitting using characters; langchain will use
    # tiktoken if available.
    chunk_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1500,
        chunk_overlap=200,
        separators=["\n\n", "\n", ". ", " "],
    )

    chunks: List[Document] = []
    for doc in documents:
        header_docs = header_splitter.split_text(doc.page_content)
        for h_doc in header_docs:
            # Carry over original metadata and enrich with header info where present.
            h_doc.metadata["source"] = doc.metadata.get("source", "")
            for key in ("technique_id", "technique_name"):
                if key in doc.metadata:
                    h_doc.metadata[key] = doc.metadata[key]

            # Now apply secondary splitter, preserving metadata.
            sub_docs = chunk_splitter.split_documents([h_doc])
            for sub in sub_docs:
                sub.metadata.update(h_doc.metadata)
            chunks.extend(sub_docs)

    return chunks

