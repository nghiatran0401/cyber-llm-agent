import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


def query_otx(indicator, indicator_type):
  try:
    headers = {
      "X-OTX-API-KEY": OTX_API_KEY
    }

    # Map our types to OTX URL format
    type_map = {
      "IPv4": "IPv4",
      "domain": "domain",
      "file": "file"
    }

    mapped_type = type_map.get(indicator_type)

    if not mapped_type:
      return {"error": "Unsupported indicator type"}

    # Get general info
    full_url = f"{BASE_URL}/{mapped_type}/{indicator}"
    response = requests.get(full_url, headers=headers, timeout=15)
    data = response.json()

    pulse_info = data.get("pulse_info", {})
    general_data = data.get("general", {})
    pulses = pulse_info.get("pulses", [])

    malware_families = []
    tags = []

    for pulse in pulses:
      for mf in pulse.get("malware_families", []):
        if isinstance(mf, dict):
          malware_families.append(mf.get("display_name"))
        else:
          malware_families.append(mf)

      for tag in pulse.get("tags", []):
        tags.append(tag)

    # Limit the output size
    MAX_ITEMS = 15

    unique_families = list(set(filter(None, malware_families)))
    unique_tags = list(set(filter(None, tags)))

    return {
      "indicator": indicator,
      "type": indicator_type,
      "reputation": general_data.get("reputation", "Unknown"),
      "pulse_count": pulse_info.get("count", 0),
      "malware_families_sample": unique_families[:MAX_ITEMS],
      "total_malware_families": len(unique_families),
      "tags_sample": unique_tags[:MAX_ITEMS],
      "total_tags": len(unique_tags)
    }

  except Exception as e:
    return {
      "error": str(e)
    }