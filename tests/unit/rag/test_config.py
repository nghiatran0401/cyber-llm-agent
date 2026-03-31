from src.rag.config import get_settings, reset_rag_config_cache


def test_settings_defaults():
    reset_rag_config_cache()
    settings = get_settings()
    assert settings.data_path
    assert settings.chroma_path
    assert settings.chroma_collection
    assert settings.embedding_model

