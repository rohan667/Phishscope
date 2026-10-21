"""Optional read-only VirusTotal lookups; files and message bodies are never uploaded."""
import base64
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


def enrich_report(report, api_key=None, timeout=8):
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        raise ValueError("Set VT_API_KEY in your environment before using --enrich.")
    results = []
    indicators = [("file_hash", value) for value in report["iocs"]["attachment_sha256"]]
    raw_urls = [value.replace("hxxps://", "https://").replace("hxxp://", "http://")
                .replace("[.]", ".").replace("[@]", "@") for value in report["iocs"]["urls"]]
    indicators += [("url", value) for value in raw_urls]
    for kind, value in indicators[:10]:
        if kind == "file_hash":
            endpoint = "https://www.virustotal.com/api/v3/files/" + quote(value, safe="")
        else:
            encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            endpoint = "https://www.virustotal.com/api/v3/urls/" + quote(encoded, safe="")
        request = Request(endpoint, headers={"x-apikey": api_key, "Accept": "application/json"})
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read(1_000_000).decode("utf-8"))
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results.append({"type": kind, "indicator": value, "stats": stats})
        except HTTPError as exc:
            results.append({"type": kind, "indicator": value, "error": f"VirusTotal HTTP {exc.code}"})
        except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            results.append({"type": kind, "indicator": value, "error": str(exc)[:200]})
    report["virustotal_enrichment"] = results
    return report
