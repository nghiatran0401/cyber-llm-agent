"""Unit tests for prompt loading and version listing."""

from pathlib import Path

import pytest

from src.utils.prompt_manager import PromptManager


def test_load_prompt_reads_security_analysis_v2():
    manager = PromptManager()
    text = manager.load_prompt("security_analysis_v2.txt")
    assert "security" in text.lower() or len(text) > 0


def test_load_prompt_missing_file():
    manager = PromptManager()
    with pytest.raises(FileNotFoundError):
        manager.load_prompt("nonexistent_prompt_xyz.txt")


def test_list_prompt_versions_includes_known_files():
    manager = PromptManager()
    names = manager.list_prompt_versions(prefix="security_analysis_")
    assert "security_analysis_v2.txt" in names


def test_prompt_dir_override(tmp_path: Path):
    p = tmp_path / "custom.txt"
    p.write_text("hello", encoding="utf-8")
    manager = PromptManager(prompt_dir=tmp_path)
    assert manager.load_prompt("custom.txt") == "hello"
