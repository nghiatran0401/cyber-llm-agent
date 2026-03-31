# MITRE ATT&CK markdown (optional, local Chroma RAG)

This directory is used when **`RAG_VECTOR_BACKEND=chroma`**. Add MITRE technique
markdown files (for example `T1047_Windows_Management_Instrumentation.md`) here, then
build the index:

```bash
python3 scripts/rag_build_index.py
```

The repository does not ship the full MITRE corpus (hundreds of files) to keep the
clone small. Populate from your own export, or cherry-pick files from the
`feat/rag` branch history if you need the bundled set.

Default Pinecone RAG (`RAG_VECTOR_BACKEND=pinecone`) uses **`data/knowledge/`** instead.
