"""
Core package for the MITRE-based RAG and CTI assistant.

This package provides a structured interface for:
- configuration management
- ingestion and indexing of MITRE markdown data into ChromaDB
- retrieval over the indexed data
- LLM-based reasoning to produce structured answers
- agent-style routing between MITRE RAG and OTX CTI tools
"""

from .config import Settings, get_settings

__all__ = ["Settings", "get_settings"]

