"""Markdown and JSON report rendering."""
import json


def as_json(reports):
    return json.dumps(reports[0] if len(reports) == 1 else reports, indent=2, ensure_ascii=False)


def as_markdown(report):
    lines = [f"# PhishScope report: {report['filename']}", "",
             f"**Verdict:** {report['verdict']}  ",
             f"**Risk score:** {report['score']}/100  ",
             f"**Subject:** {report['subject']}",
             f"**From:** {report['from']}", "", "## Findings", ""]
    if report["findings"]:
        lines += ["| Rule | Points | Detail | ATT&CK |", "|---|---:|---|---|"]
        for item in report["findings"]:
            detail = item["detail"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {item['rule']} | +{item['points']} | {detail} | {item['attack_id']} |")
    else:
        lines.append("No configured rules matched. This does not prove the email is safe.")
    lines += ["", "## Defanged indicators", "", "### URLs"]
    lines += [f"- {value}" for value in report["iocs"]["urls"]] or ["- None found"]
    lines += ["", "### Domains"]
    lines += [f"- {value}" for value in report["iocs"]["domains"]] or ["- None found"]
    lines += ["", "### Attachment SHA-256"]
    lines += [f"- {value}" for value in report["iocs"]["attachment_sha256"]] or ["- None found"]
    lines += ["", "## Suggested response actions", ""]
    lines += [f"- {action}" for action in report["response_actions"]]
    lines += ["", "> PhishScope is a rule-based triage aid, not a production verdict. Validate alerts with trusted security controls."]
    if report.get("virustotal_enrichment"):
        lines += ["", "## Optional VirusTotal lookup results", ""]
        for item in report["virustotal_enrichment"]:
            lines.append(f"- {item['type']}: {item.get('stats', item.get('error', 'No result'))}")
    return "\n".join(lines)
