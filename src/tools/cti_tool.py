"""CTI Tool: fetches Cyber Threat Intelligence from AlienVault OTX."""

import re
import time
from typing import Any
from urllib.parse import quote

import requests
from langchain_core.tools import Tool

from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)
_IOC_PATTERN = re.compile(r"^ioc:(ip|domain|hostname|url|hash):(.+)$", re.IGNORECASE)


# ─── Internal helpers ──────────────────────────────────────────────────────────

def _sanitize_text(text: str) -> str:
    """Strip control characters and normalize whitespace for safe model context."""
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", str(text))
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


def _truncate_text(text: str, max_chars: int) -> str:
    """Bound CTI output length to avoid token blowups."""
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars - 3].rstrip()}..."


def _format_cti_report(
    source: str,
    query: str,
    summary: str,
    observations: list[str],
    actions: list[str],
    confidence: str,
) -> str:
    """Render a consistent CTI output schema for the agent."""
    report = (
        f"Source: {source}\n"
        f"Query: {query}\n"
        f"Summary: {summary}\n"
        "Top Observations:\n"
        f"{chr(10).join(f'- {item}' for item in observations)}\n"
        "Recommended Actions:\n"
        f"{chr(10).join(f'- {item}' for item in actions)}\n"
        f"Confidence: {confidence}"
    )
    return _truncate_text(_sanitize_text(report), Settings.CTI_MAX_RESPONSE_CHARS)


def _otx_request(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform OTX GET with retry/backoff."""
    url = f"{Settings.OTX_BASE_URL}{path}"
    headers = {"X-OTX-API-KEY": Settings.OTX_API_KEY}
    attempts = Settings.CTI_MAX_RETRIES + 1
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            response = requests.get(url, params=params, headers=headers, timeout=Settings.CTI_REQUEST_TIMEOUT_SECONDS)
            if response.status_code == 200:
                return response.json()
            if response.status_code in {429, 500, 502, 503, 504}:
                last_error = RuntimeError(f"Transient OTX error {response.status_code}")
            else:
                raise RuntimeError(f"OTX request failed with status {response.status_code}")
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = exc
        except requests.RequestException as exc:
            last_error = exc
            break
        except ValueError as exc:
            last_error = exc
            break

        if attempt < attempts - 1 and Settings.CTI_RETRY_BACKOFF_SECONDS > 0:
            time.sleep(Settings.CTI_RETRY_BACKOFF_SECONDS * (attempt + 1))

    raise RuntimeError("OTX request failed after retries.") from last_error


def _query_otx_threat_type(threat_type: str) -> str:
    """Search OTX pulses by threat keyword."""
    payload = _otx_request("/search/pulses", params={"query": threat_type, "limit": Settings.CTI_TOP_RESULTS})
    results = payload.get("results") or []
    if not isinstance(results, list) or not results:
        return _format_cti_report(
            source="AlienVault OTX", query=threat_type,
            summary=f"No OTX pulse results found for '{threat_type}'.",
            observations=["The query returned zero matching pulses."],
            actions=["Try a broader threat keyword or known malware family name.", "Pivot to IOC lookup if specific indicators are available."],
            confidence="Low",
        )

    observations: list[str] = []
    for pulse in results[: Settings.CTI_TOP_RESULTS]:
        if not isinstance(pulse, dict):
            continue
        name = _sanitize_text(pulse.get("name") or "Unnamed pulse")
        tags = pulse.get("tags") or []
        tags_text = ", ".join(str(t) for t in tags[:3]) if isinstance(tags, list) else "n/a"
        indicators = pulse.get("indicators") or []
        observations.append(f"{name} (tags: {tags_text}; indicators: {len(indicators) if isinstance(indicators, list) else 0})")

    if not observations:
        observations.append("Pulse data returned but no parsable entries were available.")

    return _format_cti_report(
        source="AlienVault OTX", query=threat_type,
        summary=f"Found {len(results)} pulse result(s) for '{threat_type}'.",
        observations=observations,
        actions=["Validate matched indicators against internal telemetry before blocking.", "Prioritize high-confidence indicators seen across multiple pulses.", "Schedule periodic refresh because pulse activity changes quickly."],
        confidence="Medium",
    )


def _query_otx_ioc(ioc_type: str, indicator: str) -> str:
    """Query OTX general indicator context for IP/domain/url/hash/etc."""
    otx_type_map = {"ip": "IPv4", "domain": "domain", "hostname": "hostname", "url": "url", "hash": "file"}
    safe_indicator = quote(indicator, safe="")
    payload = _otx_request(f"/indicators/{otx_type_map[ioc_type]}/{safe_indicator}/general")

    pulse_info = payload.get("pulse_info") if isinstance(payload, dict) else {}
    pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
    pulse_count = len(pulses) if isinstance(pulses, list) else 0
    reputation = payload.get("reputation", "unknown")
    related_type = payload.get("type", otx_type_map[ioc_type])

    observations: list[str] = [
        f"Indicator type: {related_type}",
        f"Associated pulses: {pulse_count}",
        f"Reputation: {reputation}",
    ]
    if isinstance(pulses, list) and pulses:
        pulse_names = [_sanitize_text(item.get("name", "Unnamed pulse")) for item in pulses[:Settings.CTI_TOP_RESULTS] if isinstance(item, dict)]
        if pulse_names:
            observations.append(f"Example pulses: {', '.join(pulse_names)}")

    return _format_cti_report(
        source="AlienVault OTX",
        query=f"ioc:{ioc_type}:{indicator}",
        summary=(f"OTX returned context for IOC '{indicator}' with {pulse_count} linked pulse(s)." if pulse_count > 0 else f"OTX returned IOC metadata for '{indicator}' but no linked pulses."),
        observations=observations,
        actions=["Cross-check indicator sightings with SIEM/EDR before enforcement.", "If confirmed malicious, block at DNS, firewall, and endpoint controls.", "Track related IOCs from linked pulses for wider containment."],
        confidence="High" if pulse_count > 0 else "Low",
    )


def _fallback_cti_report(query: str) -> str:
    """Return deterministic fallback when live CTI is unavailable."""
    return _format_cti_report(
        source="CTI Fallback", query=query,
        summary="Live CTI feed is temporarily unavailable.",
        observations=["External CTI query failed or timed out.", "No live OTX data could be safely returned in this attempt."],
        actions=["Proceed with local evidence-first investigation using available logs.", "Retry CTI lookup shortly after verifying OTX API status and credentials."],
        confidence="Low",
    )


def _parse_cti_query(raw_query: str) -> tuple[str, str]:
    """Parse CTI input into ('threat'|'ioc', query_payload)."""
    query = raw_query.strip()
    match = _IOC_PATTERN.match(query)
    if not match:
        if query.lower().startswith("ioc:"):
            raise ValueError("Invalid IOC format. Use 'ioc:<type>:<value>' with type in {ip,domain,hostname,url,hash}.")
        return ("threat", query)
    ioc_type = match.group(1).lower()
    indicator = match.group(2).strip()
    if not indicator:
        raise ValueError("IOC query is missing indicator value.")
    return ("ioc", f"{ioc_type}:{indicator}")


# ─── Public function ────────────────────────────────────────────────────────────

def fetch_cti_intelligence(threat_type: str) -> str:
    """Fetch Cyber Threat Intelligence from AlienVault OTX.

    Supports:
    - Threat-type queries (e.g. "ransomware", "phishing")
    - IOC queries: "ioc:<type>:<value>" where type ∈ {ip, domain, hostname, url, hash}

    Returns:
        Normalized CTI report string with summary, observations, and actions.
    """
    if not threat_type or not threat_type.strip():
        return "Error: Threat type cannot be empty."

    try:
        query_mode, parsed_query = _parse_cti_query(threat_type)
    except ValueError as exc:
        logger.warning("Invalid CTI query format.")
        return f"Error: {exc}"

    if Settings.CTI_PROVIDER != "otx":
        return "Error: Unsupported CTI provider. Only 'otx' is supported."

    try:
        if query_mode == "ioc":
            ioc_type, indicator = parsed_query.split(":", 1)
            result = _query_otx_ioc(ioc_type=ioc_type, indicator=indicator)
        else:
            result = _query_otx_threat_type(parsed_query)
        logger.info("CTI fetch completed with provider=otx.")
        return result
    except Exception:
        logger.warning("CTI fetch failed for provider=otx.")
        return _fallback_cti_report(threat_type.strip())


cti_fetch = Tool(
    name="CTIFetch",
    func=fetch_cti_intelligence,
    description=(
        "Fetches Cyber Threat Intelligence reports from AlienVault OTX. "
        "Input can be a threat type (e.g., 'ransomware', 'ddos') or IOC format "
        "('ioc:ip:1.2.3.4', 'ioc:domain:example.com', 'ioc:url:https://bad.example', "
        "'ioc:hash:<sha256>'). Returns normalized intelligence with summary and actions."
    ),
)
