from src.rag.agents.router import detect_input_type


def test_detect_input_type_ip():
    assert detect_input_type("Connection from 10.0.0.1") == "ip"


def test_detect_input_type_hash():
    assert detect_input_type("Malicious hash:" + "a" * 32) == "hash"


def test_detect_input_type_technique():
    assert detect_input_type("Related to T1047") == "technique"


def test_detect_input_type_log():
    assert detect_input_type("User logged in successfully") == "log"

