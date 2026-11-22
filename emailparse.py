# emailparse.py
#
# Reads a .eml file with Python's own `email` package and pulls out what
# the checks need: sender, reply and bounce addresses, the sender-check
# results (SPF / DKIM / DMARC), the text, every link, and every attachment.
#
# Attachments are never opened or run. We only read their names. For a
# .zip we read the list of file names inside it (zipfile.namelist), which
# does not extract anything.

import email
import io
import re
import zipfile
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')]+")


class LinkFinder(HTMLParser):
    """Collects every <a href="...">text</a> in an HTML body."""

    def __init__(self):
        super().__init__()
        self.links = []      # list of [text, url]
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.current = ["", href]

    def handle_data(self, data):
        if self.current is not None:
            self.current[0] += data

    def handle_endtag(self, tag):
        if tag == "a" and self.current is not None:
            self.current[0] = " ".join(self.current[0].split())
            self.links.append(self.current)
            self.current = None


def domain_of(address):
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().strip(">").strip()


def host_of(url):
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return host or ""


def read_auth_results(msg):
    """Returns {"spf": "pass", "dkim": "fail", "dmarc": "none"} or None if
    the email has no Authentication-Results header at all."""
    headers = msg.get_all("Authentication-Results")
    if not headers:
        return None
    text = " ".join(str(h) for h in headers).lower()
    results = {}
    for name in ["spf", "dkim", "dmarc"]:
        m = re.search(name + r"=(\w+)", text)
        results[name] = m.group(1) if m else "missing"
    return results


def zip_names(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.namelist()
    except (zipfile.BadZipFile, ValueError):
        return []


def parse_eml(raw):
    """raw is the bytes of a .eml file. Returns a dict."""
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    rp_name, return_path = parseaddr(str(msg.get("Return-Path", "")))

    text = ""
    html = ""
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        name = part.get_filename()
        if name or part.get_content_disposition() == "attachment":
            data = part.get_payload(decode=True) or b""
            inside = []
            if (name or "").lower().endswith(".zip"):
                inside = zip_names(data)
            attachments.append({"name": name or "(no name)", "type": part.get_content_type(),
                                "size": len(data), "inside": inside})
        elif part.get_content_type() == "text/plain":
            text += part.get_content()
        elif part.get_content_type() == "text/html":
            html += part.get_content()

    links = []
    if html:
        finder = LinkFinder()
        finder.feed(html)
        links = finder.links
    seen = set(url for t, url in links)
    for url in URL_IN_TEXT.findall(text):
        if url not in seen:
            links.append([url, url])
            seen.add(url)

    return {
        "from_name": from_name,
        "from_addr": from_addr.lower(),
        "from_domain": domain_of(from_addr),
        "reply_to": reply_addr.lower(),
        "return_path": return_path.lower(),
        "subject": str(msg.get("Subject", "")),
        "received": [str(h) for h in msg.get_all("Received", [])],
        "auth": read_auth_results(msg),
        "text": text,
        "html": html,
        "links": [{"text": t, "url": u, "host": host_of(u)} for t, u in links],
        "attachments": attachments,
        "synthetic": "SYNTHETIC" in str(msg.get("X-Synthetic", "")).upper(),
    }


def parse_file(path):
    with open(path, "rb") as f:
        return parse_eml(f.read())
