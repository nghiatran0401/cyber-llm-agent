"""CTI Tool: AlienVault OTX (pulse search + indicator lookup)."""

import re
import time
from time import perf_counter
from typing import Any
from urllib.parse import quote

import requests
from langchain_core.tools import Tool

from src.config.settings import Settings
from src.utils.logger import setup_logger

from ._tool_envelope import build_tool_result, serialize_tool_result

logger = setup_logger(__name__)
_IOC = re.compile(r"^ioc:(ip|domain|hostname|url|hash):(.+)$", re.IGNORECASE)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
CTI_REQUEST_TIMEOUT_SECONDS = 10
CTI_MAX_RETRIES = 2
CTI_RETRY_BACKOFF_SECONDS = 0.5
CTI_MAX_RESPONSE_CHARS = 3000
CTI_TOP_RESULTS = 5

_OTX_TYPE = {"ip": "IPv4", "domain": "domain", "hostname": "hostname", "url": "url", "hash": "file"}


def _clean(text: str, max_chars: int) -> str:
    """Drop control bytes and cap length for model context."""
    s = re.sub(r"[\x00-\x10\x13-\x1f\x7f]", "", str(text))
    s = " ".join(s.split())
    if len(s) <= max_chars:
        return s
    return f"{s[: max_chars - 3].rstrip()}..."


def _otx_get(path: str, params: dict[str, Any] | None = None) -> tuple[dict[str, Any], int]:
    url = f"{OTX_BASE_URL}{path}"
    headers = {"X-OTX-API-KEY": Settings.OTX_API_KEY}
    attempts = CTI_MAX_RETRIES + 1
    retries_used = 0
    last_err: Exception | None = None

    for attempt in range(attempts):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=CTI_REQUEST_TIMEOUT_SECONDS)
            if r.status_code == 200:
                return r.json(), retries_used
            if r.status_code in {429, 500, 502, 503, 504}:
                last_err = RuntimeError(f"OTX HTTP {r.status_code}")
            else:
                raise RuntimeError(f"OTX HTTP {r.status_code}")
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_err = exc
        except (requests.RequestException, ValueError) as exc:
            last_err = exc
            break

        n = attempt + 1
        retries_used = n
        if attempt < attempts - 1 and CTI_RETRY_BACKOFF_SECONDS > 0:
            time.sleep(CTI_RETRY_BACKOFF_SECONDS * n)

    raise RuntimeError("OTX request failed after retries.") from last_err


def _format_pulses(query: str, payload: dict[str, Any]) -> str:
    results = payload.get("results") or []
    if not isinstance(results, list) or not results:
        body = f"Summary: No OTX pulse results found for '{query}'."
        return _clean(f"Source: AlienVault OTX\nQuery: {query}\n{body}", CTI_MAX_RESPONSE_CHARS)

    lines: list[str] = []
    for p in results[:CTI_TOP_RESULTS]:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "Unnamed pulse")
        tags = p.get("tags") or []
        tags_txt = ", ".join(str(t) for t in tags[:3]) if isinstance(tags, list) else "n/a"
        ind = p.get("indicators") or []
        n_ind = len(ind) if isinstance(ind, list) else 0
        lines.append(f"- {name} (tags: {tags_txt}; indicators: {n_ind})")

    summary = f"Summary: Found {len(results)} pulse result(s) for '{query}'."
    body = summary + ("\n" + "\n".join(lines) if lines else "")
    return _clean(f"Source: AlienVault OTX\nQuery: {query}\n{body}", CTI_MAX_RESPONSE_CHARS)


def _format_ioc(ioc_type: str, indicator: str, payload: dict[str, Any]) -> str:
    q = f"ioc:{ioc_type}:{indicator}"
    pulse_info = payload.get("pulse_info") if isinstance(payload, dict) else {}
    pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
    n = len(pulses) if isinstance(pulses, list) else 0
    rep = payload.get("reputation", "unknown")
    typ = payload.get("type", _OTX_TYPE[ioc_type])
    parts = [
        "Source: AlienVault OTX",
        f"Query: {q}",
        f"Summary: type={typ} reputation={rep}",
        f"Associated pulses: {n}",
    ]
    if isinstance(pulses, list) and pulses:
        names = [str(x.get("name", "Unnamed pulse")) for x in pulses[:CTI_TOP_RESULTS] if isinstance(x, dict)]
        if names:
            parts.append("Example pulses: " + ", ".join(names))
    return _clean("\n".join(parts), CTI_MAX_RESPONSE_CHARS)


def _fallback(query: str) -> str:
    msg = (
        f"Source: CTI Fallback\nQuery: {query}\n"
        "Summary: Live CTI is temporarily unavailable."
    )
    return _clean(msg, CTI_MAX_RESPONSE_CHARS)


def _parse_query(raw: str) -> tuple[str, str]:
    q = raw.strip()
    m = _IOC.match(q)
    if not m:
        if q.lower().startswith("ioc:"):
            raise ValueError(
                "Invalid IOC format. Use 'ioc:<type>:<value>' with type in {ip,domain,hostname,url,hash}."
            )
        return ("threat", q)
    ioc_type, indicator = m.group(1).lower(), m.group(2).strip()
    if not indicator:
        raise ValueError("IOC query is missing indicator value.")
    return ("ioc", f"{ioc_type}:{indicator}")


def fetch_cti_intelligence(threat_type: str) -> str:
    """OTX: keyword pulse search or ``ioc:<type>:<value>`` indicator lookup. Returns ToolResult JSON."""
    start = perf_counter()

    if not threat_type or not threat_type.strip():
        ms = int((perf_counter() - start) * 1000)
        return serialize_tool_result(build_tool_result(
            ok=False, tool="CTIFetch", error="Threat type cannot be empty.",
            error_type="empty_query", duration_ms=ms, input_val=threat_type or "",
        ))

    try:
        mode, parsed = _parse_query(threat_type)
    except ValueError as exc:
        ms = int((perf_counter() - start) * 1000)
        logger.warning("Invalid CTI query format.")
        return serialize_tool_result(build_tool_result(
            ok=False, tool="CTIFetch", error=str(exc),
            error_type="invalid_ioc_format", duration_ms=ms, input_val=threat_type,
        ))

    try:
        if mode == "ioc":
            ioc_type, indicator = parsed.split(":", 1)
            path = f"/indicators/{_OTX_TYPE[ioc_type]}/{quote(indicator, safe='')}/general"
            payload, retries_used = _otx_get(path)
            report = _format_ioc(ioc_type, indicator, payload)
        else:
            payload, retries_used = _otx_get("/search/pulses", {"query": parsed, "limit": CTI_TOP_RESULTS})
            report = _format_pulses(parsed, payload)

        ms = int((perf_counter() - start) * 1000)
        logger.info("CTI fetch completed (retries=%d, duration=%dms).", retries_used, ms)
        return serialize_tool_result(build_tool_result(
            ok=True, tool="CTIFetch", data=report,
            duration_ms=ms, retries=retries_used, input_val=threat_type,
        ))
    except Exception:
        ms = int((perf_counter() - start) * 1000)
        logger.warning("CTI fetch failed (duration=%dms); using fallback.", ms)
        return serialize_tool_result(build_tool_result(
            ok=True, tool="CTIFetch", data=_fallback(threat_type.strip()),
            duration_ms=ms, retries=CTI_MAX_RETRIES, input_val=threat_type,
        ))


cti_fetch = Tool(
    name="CTIFetch",
    func=fetch_cti_intelligence,
    description=(
        "Fetches Cyber Threat Intelligence from AlienVault OTX. "
        "Input: threat keyword (e.g. 'ransomware') or IOC 'ioc:ip:1.2.3.4', "
        "'ioc:domain:example.com', 'ioc:url:https://...', 'ioc:hash:<sha256>'."
    ),
)
