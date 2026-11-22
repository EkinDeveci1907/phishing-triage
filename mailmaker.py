# mailmaker.py
#
# Builds SYNTHETIC / MOCK emails with Python's `email` package. Used by
# make_samples.py (the 20 sample files) and train_model.py (the made-up
# training set for the demo model). Every email it makes carries an
# "X-Synthetic" header and a first line saying it is not a real email.
#
# Attachments are placeholders: a few bytes of text, never a real program.

import io
import zipfile
from email import policy
from email.message import EmailMessage

SYNTHETIC_HEADER = "SYNTHETIC / MOCK - made for phishing-triage tests. Not a real email."
SYNTHETIC_LINE = "[SYNTHETIC / MOCK sample email - not a real message]"
PLACEHOLDER = b"SYNTHETIC placeholder bytes - not a real program or document."

ATTACHMENT_TYPES = {
    ".pdf": ("application", "pdf"),
    ".zip": ("application", "zip"),
    ".docm": ("application", "vnd.ms-word.document.macroEnabled.12"),
    ".xlsm": ("application", "vnd.ms-excel.sheet.macroEnabled.12"),
    ".exe": ("application", "x-msdownload"),
    ".ics": ("text", "calendar"),
}


def zip_with(names):
    """A small zip whose files are placeholder text, under the given names."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for name in names:
            z.writestr(name, PLACEHOLDER)
    return buffer.getvalue()


def build_message(from_header, to, subject, text, html=None, reply_to=None, return_path=None,
                  auth=None, received=None, attachments=None, date="Thu, 19 Nov 2026 09:00:00 -0400"):
    """auth is the text of an Authentication-Results header, or None to leave it out.
    attachments is a list of (file name, list of names inside if it's a zip)."""
    msg = EmailMessage(policy=policy.default)
    if return_path:
        msg["Return-Path"] = "<" + return_path + ">"
    for hop in received or []:
        msg["Received"] = hop
    if auth:
        msg["Authentication-Results"] = auth
    msg["From"] = from_header
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = date
    msg["X-Synthetic"] = SYNTHETIC_HEADER

    msg.set_content(SYNTHETIC_LINE + "\n\n" + text)
    if html:
        msg.add_alternative("<p><i>" + SYNTHETIC_LINE + "</i></p>\n" + html, subtype="html")

    for name, inside in attachments or []:
        kind = name[name.rfind("."):].lower()
        maintype, subtype = ATTACHMENT_TYPES.get(kind, ("application", "octet-stream"))
        data = zip_with(inside) if kind == ".zip" else PLACEHOLDER
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg


def auth_header(domain, spf="pass", dkim="pass", dmarc="pass"):
    return ("mx.dal.ca; spf=" + spf + " smtp.mailfrom=" + domain + "; dkim=" + dkim
            + " header.d=" + domain + "; dmarc=" + dmarc + " header.from=" + domain)
