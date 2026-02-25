"""RAG helpers with Pinecone scalable retrieval."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from langchain_core.tools import Tool
from langchain_community.document_loaders import DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec

from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

_ALLOWED_SUFFIXES = {".txt", ".md", ".log", ".json", ".jsonl"}

def _get_pinecone_client() -> Pinecone:
    if not Settings.PINECONE_API_KEY:
        raise ValueError("PINECONE_API_KEY is not set.")
    return Pinecone(api_key=Settings.PINECONE_API_KEY)


def ingest_knowledge_base() -> str:
    """Index files under knowledge directory into Pinecone using LangChain."""
    if not Settings.ENABLE_RAG:
        return "RAG is disabled."
    
    logger.info("Starting knowledge base ingestion to Pinecone...")
    
    pc = _get_pinecone_client()
    index_name = Settings.PINECONE_INDEX_NAME
    
    # Check if index exists, map to serverless if needed
    existing_indexes = [index_info["name"] for index_info in pc.list_indexes()]
    if index_name not in existing_indexes:
        logger.info(f"Creating Pinecone index '{index_name}'...")
        pc.create_index(
            name=index_name,
            dimension=1536, # OpenAI embedding dimensions
            metric="cosine",
            spec=ServerlessSpec(
                cloud="aws",
                region="us-east-1"
            )
        )
    
    # Load documents
    loader = DirectoryLoader(str(Settings.KNOWLEDGE_DIR), glob="**/*.*", show_progress=True)
    raw_docs = loader.load()
    
    # Filter by allowed suffixes manually since DirectoryLoader supports few globs
    docs = [doc for doc in raw_docs if Path(doc.metadata.get("source", "")).suffix.lower() in _ALLOWED_SUFFIXES]
    
    if not docs:
        logger.info("No valid documents found for ingestion.")
        return "No valid documents found in data/knowledge."

    # Split documents
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        add_start_index=True,
    )
    chunks = text_splitter.split_documents(docs)
    
    # Embed and upload to Pinecone
    embeddings = OpenAIEmbeddings(openai_api_key=Settings.OPENAI_API_KEY)
    
    logger.info(f"Uploading {len(chunks)} chunks to Pinecone index '{index_name}'...")
    PineconeVectorStore.from_documents(
        chunks, 
        embeddings, 
        index_name=index_name
    )
    
    msg = f"RAG index refreshed using Pinecone. Processed {len(docs)} documents into {len(chunks)} chunks."
    logger.info(msg)
    return msg


def retrieve_security_context(query: str) -> str:
    """Retrieve top local knowledge snippets with Pinecone semantic search."""
    clean_query = (query or "").strip()
    if not clean_query:
        return "No retrieval performed because query is empty."
        
    if not Settings.ENABLE_RAG:
        return "RAG is disabled."

    try:
        embeddings = OpenAIEmbeddings(openai_api_key=Settings.OPENAI_API_KEY)
        vectorstore = PineconeVectorStore(
            index_name=Settings.PINECONE_INDEX_NAME, 
            embedding=embeddings
        )
        
        # Use LangChain Retriever
        retriever = vectorstore.as_retriever(search_kwargs={"k": Settings.RAG_MAX_RESULTS})
        docs = retriever.invoke(clean_query)
        
        if not docs:
            return "No relevant context found in remote knowledge base."

        lines = ["Retrieved Context (mode=pinecone_semantic):"]
        citations = []
        for i, doc in enumerate(docs):
            source = doc.metadata.get("source", "unknown")
            # Relativize source path if possible
            if str(Settings.BASE_DIR) in source:
                source = str(Path(source).relative_to(Settings.BASE_DIR))
                
            lines.append(f"- Match {i+1} [source={source}]: {doc.page_content}")
            citations.append(source)
            
        lines.append("Citations:")
        for citation in sorted(set(citations)):
            lines.append(f"- {citation}")
            
        return "\n".join(lines)
        
    except Exception as e:
        logger.error(f"Error during Pinecone retrieval: {str(e)}", exc_info=True)
        return f"Retrieval failed due to an error: {str(e)}"


rag_ingest = Tool(
    name="RAGIngest",
    func=ingest_knowledge_base,
    description=(
        "Indexes local knowledge files under data/knowledge into the Pinecone Vector Database. "
        "Call this after adding or updating docs to make them searchable."
    ),
)

rag_retriever = Tool(
    name="RAGRetriever",
    func=retrieve_security_context,
    description=(
        "Retrieves highly relevant semantic context from the Pinecone vector database. "
        "Input should be a threat question, log snippet, or IOC statement."
    ),
)
