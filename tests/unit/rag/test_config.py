from src.rag.config import get_settings


def test_settings_defaults():
    settings = get_settings()
    assert settings.data_path
    assert settings.chroma_path
    assert settings.chroma_collection
    assert settings.embedding_model

