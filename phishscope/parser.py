"""Parse .eml messages without opening links or executing attachments."""
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import urlparse

MAX_EMAIL_BYTES = 10 * 1024 * 1024
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.href = None
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self.href = dict(attrs).get("href")
            self.text = []

    def handle_data(self, data):
        if self.href is not None:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.href is not None:
            self.links.append({"url": self.href.strip(), "text": " ".join(" ".join(self.text).split())})
            self.href, self.text = None, []


def email_domain(value):
    match = re.search(r"@([^\s<>]+)", value or "")
    return match.group(1).strip().strip(">").lower().rstrip(".") if match else ""


def parse_eml(path):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError(f"{path.name}: file exceeds the 10 MB safety limit")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    plain_parts, html_parts, attachments = [], [], []
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename:
            attachments.append({"filename": filename, "size": len(payload),
                                "sha256": sha256(payload).hexdigest(),
                                "content_type": part.get_content_type()})
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            content = payload.decode("utf-8", errors="replace")
        (plain_parts if part.get_content_type() == "text/plain" else html_parts).append(content)

    body = "\n".join(plain_parts)
    links = []
    for html in html_parts:
        parser = LinkParser()
        parser.feed(html)
        links.extend(parser.links)
    for found in URL_RE.findall(body):
        cleaned = found.rstrip(".,);:!?]")
        if cleaned.lower().startswith("www."):
            cleaned = "http://" + cleaned
        if not any(item["url"].lower() == cleaned.lower() for item in links):
            links.append({"url": cleaned, "text": ""})
    links = [item for item in links
             if urlparse(item["url"]).scheme.lower() in ("http", "https") and urlparse(item["url"]).hostname]

    auth_header = " ".join(message.get_all("Authentication-Results", []))
    auth = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(r"\b" + mechanism + r"\s*=\s*([a-zA-Z_-]+)", auth_header, re.I)
        auth[mechanism] = match.group(1).lower() if match else "unknown"
    sender = str(message.get("From", ""))
    reply = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    return {
        "filename": path.name, "subject": str(message.get("Subject", "(no subject)")),
        "from": sender, "from_domain": email_domain(sender),
        "reply_to": reply, "reply_to_domain": email_domain(reply),
        "return_path": return_path, "return_path_domain": email_domain(return_path),
        "authentication": auth, "body": body, "links": links, "attachments": attachments,
    }
