from src.rag.retrieval.vector_store import get_mitre_collection


def verify_index() -> None:
    collection = get_mitre_collection()

    print(f"Total documents: {collection.count()}")
    print(f"Embedding function: {type(collection._embedding_function).__name__}")
    model_name = getattr(collection._embedding_function, "_model_name", "N/A")
    print(f"Model: {model_name}")

    result = collection.get(ids=["ID0"], include=["embeddings", "documents"])
    if result["documents"]:
        print(f"Document: {result['documents'][0][:100]}...")
    if result["embeddings"].any():
        print(f"Embedding dimensions: {len(result['embeddings'][0])}")
        print(f"First 5 values: {result['embeddings'][0][:5]}")


if __name__ == "__main__":
    verify_index()

