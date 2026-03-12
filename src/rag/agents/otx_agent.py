from typing import Dict, List, Any

from ..logging_config import setup_logging
from ..config import get_settings
from .ioc_extractor import extract_iocs

logger = setup_logging()


def run_otx_agent(indicator: str, indicator_type: str) -> Dict[str, object]:
    """
    Thin wrapper around the existing `query_otx` function.

    This keeps the public interface consistent with other agents.
    """
    try:
        from ..otx_tool import query_otx  # local import to avoid cycles
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to import otx_tool: %s", exc)
        return {"error": f"Failed to import otx_tool: {exc}"}

    return query_otx(indicator, indicator_type)


def run_otx_from_text(text: str) -> Dict[str, Any]:
    """
    Preprocess arbitrary text (e.g., log snippet), extract IOCs, and query OTX
    only for the extracted indicators.
    """
    settings = get_settings()
    extracted = extract_iocs(text)

    results: Dict[str, List[Dict[str, object]]] = {"ipv4": [], "hashes": [], "domains": []}

    ips = extracted.ipv4[: settings.max_otx_iocs]
    hashes = extracted.hashes[: settings.max_otx_iocs]
    domains = extracted.domains[: settings.max_otx_iocs]

    for ip in ips:
        results["ipv4"].append(run_otx_agent(ip, "IPv4"))
    for h in hashes:
        results["hashes"].append(run_otx_agent(h, "file"))
    for d in domains:
        results["domains"].append(run_otx_agent(d, "domain"))

    return {
        "extracted": {
            "ipv4": extracted.ipv4,
            "hashes": extracted.hashes,
            "domains": extracted.domains,
        },
        "otx_results": results,
        "limits": {"max_otx_iocs": settings.max_otx_iocs},
    }

