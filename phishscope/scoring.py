"""Readable rule-based scoring. Each rule contributes points at most once."""
import ipaddress
import re
from urllib.parse import urlparse

ATTACK = {
    "risky-attachment": ("T1566.001", "Spearphishing Attachment"),
    "double-extension": ("T1036.007", "Double File Extension"),
    "link-text-mismatch": ("T1566.002", "Spearphishing Link"),
    "ip-url": ("T1566.002", "Spearphishing Link"),
    "url-shortener": ("T1566.002", "Spearphishing Link"),
    "punycode-domain": ("T1566.002", "Spearphishing Link"),
    "risky-tld": ("T1566.002", "Spearphishing Link"),
    "brand-spoof": ("T1656", "Impersonation"),
    "replyto-mismatch": ("T1656", "Impersonation"),
    "returnpath-mismatch": ("T1656", "Impersonation"),
    "spf-fail": ("T1672", "Email Spoofing"),
    "dkim-fail": ("T1672", "Email Spoofing"),
    "dmarc-fail": ("T1672", "Email Spoofing"),
}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".bat", ".cmd", ".ps1", ".lnk", ".iso", ".img", ".msi"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "support", "country", "gq", "tk"}
BRANDS = ("paypal", "microsoft", "apple", "amazon", "google", "netflix", "facebook", "instagram", "dropbox", "chase", "bank of america")
URGENCY = ("urgent", "immediately", "within 24 hours", "account will be closed", "final warning", "action required", "suspended")
CREDENTIALS = ("verify your password", "confirm your password", "sign in to verify", "enter your password", "reset your password", "verify your account", "payment details")


def defang(value):
    value = str(value or "")
    value = re.sub(r"(?i)https://", "hxxps://", value)
    value = re.sub(r"(?i)http://", "hxxp://", value)
    value = value.replace("@", "[@]")
    return re.sub(r"\.(?=[A-Za-z0-9-])", "[.]", value)


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def registrable(domain):
    labels = domain.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def make_rule(rule_id, points, detail, evidence):
    technique = ATTACK.get(rule_id, ("-", "-"))
    return {"rule": rule_id, "points": points, "detail": detail, "evidence": evidence,
            "attack_id": technique[0], "attack_name": technique[1]}


def analyze(email):
    findings = []
    sender_domain = email.get("from_domain", "")
    body = (email.get("body", "") or "").lower()
    auth = email.get("authentication", {})
    links = email.get("links", [])

    for attachment in email.get("attachments", []):
        name = attachment.get("filename", "")
        match = re.search(r"(\.[a-z0-9]{1,8})$", name.lower())
        ext = match.group(1) if match else ""
        if ext in RISKY_EXTENSIONS:
            findings.append(make_rule("risky-attachment", 30, f"Potentially risky attachment: {defang(name)} ({ext})", [name]))
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat|cmd|hta)$", name.lower()):
            findings.append(make_rule("double-extension", 25, f"Double extension may disguise a file type: {defang(name)}", [name]))

    link_hosts = []
    for link in links:
        url, host = link.get("url", ""), host_of(link.get("url", ""))
        if not host:
            continue
        link_hosts.append(host)
        shown = link.get("text", "").strip()
        shown_host = host_of(shown if shown.startswith(("http://", "https://")) else "http://" + shown) if "." in shown else ""
        if shown_host and registrable(shown_host) != registrable(host):
            findings.append(make_rule("link-text-mismatch", 25, f"Link text points to {defang(shown_host)} but destination is {defang(host)}", [url]))
        try:
            ipaddress.ip_address(host.strip("[]"))
            findings.append(make_rule("ip-url", 20, f"Link uses a numeric IP address: {host}", [url]))
        except ValueError:
            pass
        if host in SHORTENERS:
            findings.append(make_rule("url-shortener", 10, f"Link uses a URL shortener: {host}", [url]))
        if "xn--" in host:
            findings.append(make_rule("punycode-domain", 15, f"Link hostname contains an IDN punycode label: {host}", [url]))
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            findings.append(make_rule("risky-tld", 10, f"Link uses a TLD that warrants extra review: {host}", [url]))

    for mechanism, points in (("spf", 15), ("dkim", 10), ("dmarc", 20)):
        result = auth.get(mechanism, "unknown").lower()
        if result == "fail":
            rule = "dkim-fail" if mechanism == "dkim" else f"{mechanism}-fail"
            findings.append(make_rule(rule, points, f"{mechanism.upper()} authentication result is fail", [f"{mechanism}={result}"]))
        elif mechanism == "dkim" and result in ("none", "unknown"):
            findings.append(make_rule("dkim-none", 5, f"DKIM result is {result}", [f"dkim={result}"]))

    reply_domain = email.get("reply_to_domain", "")
    if sender_domain and reply_domain and registrable(sender_domain) != registrable(reply_domain):
        findings.append(make_rule("replyto-mismatch", 15, f"From domain {defang(sender_domain)} differs from Reply-To {defang(reply_domain)}", [sender_domain, reply_domain]))
    return_domain = email.get("return_path_domain", "")
    if sender_domain and return_domain and registrable(sender_domain) != registrable(return_domain):
        findings.append(make_rule("returnpath-mismatch", 10, f"From domain {defang(sender_domain)} differs from Return-Path {defang(return_domain)}", [sender_domain, return_domain]))

    display_name = email.get("from", "").split("<", 1)[0].strip().strip('"').lower()
    if sender_domain and any(brand in display_name for brand in BRANDS) and not any(
        brand.replace(" ", "") in sender_domain.replace("-", "") for brand in BRANDS if brand in display_name
    ):
        findings.append(make_rule("brand-spoof", 20, f"Display name claims a familiar brand, while sender domain is {defang(sender_domain)}", [display_name, sender_domain]))
    if any(phrase in body for phrase in URGENCY):
        findings.append(make_rule("urgency-language", 10, "Pressure or urgency wording was detected", []))
    if any(phrase in body for phrase in CREDENTIALS):
        findings.append(make_rule("credential-language", 10, "Credential or sensitive-data request wording was detected", []))

    aggregated = {}
    for finding in findings:
        old = aggregated.get(finding["rule"])
        if old:
            old["evidence"] = list(dict.fromkeys(old["evidence"] + finding["evidence"]))
            if finding["detail"] not in old["detail"]:
                old["detail"] += "; " + finding["detail"]
        else:
            aggregated[finding["rule"]] = finding
    findings = sorted(aggregated.values(), key=lambda item: (-item["points"], item["rule"]))
    score = min(100, sum(item["points"] for item in findings))
    verdict = "LIKELY MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LIKELY BENIGN"
    iocs = {"urls": [defang(item["url"]) for item in links],
            "domains": sorted({defang(host) for host in link_hosts if host}),
            "attachment_sha256": sorted({item.get("sha256", "") for item in email.get("attachments", []) if item.get("sha256")})}
    actions = ["Treat this score as triage guidance and verify findings in your mail gateway."]
    if any(item["rule"] in ("spf-fail", "dkim-fail", "dmarc-fail", "replyto-mismatch", "returnpath-mismatch") for item in findings):
        actions.append("Review message authentication and sender routing; compare with trusted gateway logs.")
    if email.get("attachments"):
        actions.append("Do not open attachments. Submit hashes to your approved malware-analysis workflow.")
    if links:
        actions.append("Do not click links. Review destinations in an approved isolated analysis environment.")
    if score >= 60:
        actions.append("Consider quarantining the message and checking whether other recipients received it.")
    return {"filename": email.get("filename", "(input)"), "subject": defang(email.get("subject", "(no subject)")),
            "from": defang(email.get("from", "")), "score": score, "verdict": verdict,
            "findings": findings, "iocs": iocs, "response_actions": actions}
