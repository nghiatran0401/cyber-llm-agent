import re


def detect_input_type(user_input: str) -> str:
    """
    Classify the user input into a coarse type.

    Mirrors the original `utils.detect_input_type` behaviour.
    """
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
    technique_pattern = r"\bT\d{4}\b"

    if re.search(ip_pattern, user_input):
        return "ip"
    if re.search(hash_pattern, user_input):
        return "hash"
    if re.search(technique_pattern, user_input):
        return "technique"
    return "log"


