from chromadb import PersistentClient
from chromadb.api.models.Collection import Collection
from chromadb.utils import embedding_functions

from ..config import get_settings


def get_mitre_collection() -> Collection:
    """
    Return the Chroma collection used for MITRE ATT&CK data.
    """
    settings = get_settings()

    sentence_ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=settings.embedding_model
    )

    client = PersistentClient(path=settings.chroma_path)
    collection = client.get_or_create_collection(
        name=settings.chroma_collection,
        embedding_function=sentence_ef,
    )
    return collection

