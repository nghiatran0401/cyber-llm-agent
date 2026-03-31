from src.rag.agents.ioc_extractor import extract_iocs


def test_extract_iocs_from_log_snippet():
    text = "Failed login from 192.168.1.10 to host, file hash=ABCDEF" + ("0" * 58) + " domain evil.example.com"
    iocs = extract_iocs(text)
    assert "192.168.1.10" in iocs.ipv4
    assert any(len(h) == 64 for h in iocs.hashes)
    assert "evil.example.com" in iocs.domains

