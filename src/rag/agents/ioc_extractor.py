import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class ExtractedIOCs:
    ipv4: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)


# Conservative patterns: we prefer fewer false positives.
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9-]{1,63}\.)+(?:[A-Za-z]{2,63})\b")


def _dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def extract_iocs(text: str) -> ExtractedIOCs:
    """
    Extract indicators (IPv4, file hashes, domains) from an arbitrary text blob.
    """
    ips = _dedupe_keep_order(_IPV4_RE.findall(text))
    hashes = _dedupe_keep_order([h.lower() for h in _HASH_RE.findall(text)])

    # Domain extraction can be noisy; remove obvious false positives.
    domains_raw = _DOMAIN_RE.findall(text)
    domains: List[str] = []
    for d in domains_raw:
        dl = d.lower()
        if dl.endswith(".local"):
            continue
        if dl in {"example.com", "localhost"}:
            continue
        domains.append(dl)
    domains = _dedupe_keep_order(domains)

    return ExtractedIOCs(ipv4=ips, hashes=hashes, domains=domains)

