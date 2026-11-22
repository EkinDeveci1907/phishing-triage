# checks.py
#
# The six checks. Each one looks at the parsed email and returns a list of
# findings. A finding is:
#   code    short name, also used as a feature by the demo model
#   points  how much it adds to the 0-100 score
#   reason  one plain-English sentence an employee can understand
#
# Score = sum of points, capped at 100.
#   60 or more   -> Phishing
#   30 to 59     -> Suspicious
#   under 30     -> Likely safe

import csv
import ipaddress
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

PHISHING_AT = 60
SUSPICIOUS_AT = 30

FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.ca", "icloud.com",
             "proton.me", "protonmail.com", "aol.com", "gmx.com", "live.ca"}
ROLE_WORDS = ["helpdesk", "help desk", "it support", "service desk", "it department",
              "security team", "payroll", "human resources", "accounts payable",
              "administrator", "dean", "president", "director", "ceo"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
# endings where the real domain name is three labels, e.g. canada.gc.ca
TWO_PART_ENDINGS = {"gc.ca", "co.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.jp", "com.br"}

URGENCY = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bright away\b", r"\bas soon as possible\b",
    r"\b(within|in) 24 hours\b", r"\bfinal notice\b", r"\baction required\b",
    r"\bverify (now|your account|your identity)\b", r"\bconfirm your (details|password|account)\b",
    r"account (will be|has been) (locked|suspended|limited|closed|disabled)",
    r"\bunusual sign-in\b", r"\bpassword (expires|will expire)\b", r"\boverdue\b",
]
PROGRAM_TYPES = {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".msi", ".jar",
                 ".ps1", ".hta", ".lnk", ".iso", ".img"}
MACRO_TYPES = {".docm", ".xlsm", ".pptm", ".dotm", ".xlsb"}
# letters that are swapped in to fool the eye
LOOKALIKE_LETTERS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"),
                     ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"),
                     ("с", "c"), ("х", "x"), ("і", "i")]


def load_brands():
    brands = []
    with open(os.path.join(HERE, "config", "brands.csv"), newline="") as f:
        lines = [line for line in f if not line.startswith("#")]
    for row in csv.DictReader(lines):
        brands.append({"name": row["brand"],
                       "keywords": row["keywords"].split(";"),
                       "domains": row["domains"].split(";")})
    return brands


BRANDS = load_brands()


# ---------- small helpers ----------

def finding(code, points, reason):
    return {"code": code, "points": points, "reason": reason}


def registered_domain(host):
    """mail.login.example.com -> example.com, its.dal.ca -> dal.ca"""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_ENDINGS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def name_part(host):
    """The bit people read as the name: micros0ft.com -> micros0ft"""
    return registered_domain(host).split(".")[0]


def edit_distance(a, b):
    """Levenshtein distance: the fewest single-letter inserts, deletes or
    swaps that turn a into b."""
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def undo_lookalike_letters(text):
    for fake, real in LOOKALIKE_LETTERS:
        text = text.replace(fake, real)
    return text


def decode_host(host):
    """xn--pypal-4ve.com -> the letters it really shows, e.g. pаypal.com"""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def is_official(host):
    domain = registered_domain(host)
    for brand in BRANDS:
        if domain in brand["domains"]:
            return True
    return False


def brand_named_in(text):
    """The first brand whose keyword appears in some text, or None."""
    text = text.lower()
    for brand in BRANDS:
        for word in brand["keywords"]:
            if len(word) >= 4 and re.search(r"(^|[^a-z])" + re.escape(word) + r"($|[^a-z])", text):
                return brand
    return None


def lookalike_of(host):
    """If host imitates a brand domain, returns (official_domain, how), else None.
      - one letter different (edit distance 1), or
      - the same once look-alike letters are swapped back (rn -> m, 0 -> o,
        Cyrillic a -> a, ...)
    Names shorter than 5 letters are skipped: too many innocent near-misses."""
    if not host or is_official(host):
        return None
    shown = decode_host(host)
    name = name_part(shown)
    cleaned = undo_lookalike_letters(name)
    host_ending = host.split(".")[-1]
    for brand in BRANDS:
        # check the real domain with the same ending first (amazom.ca -> amazon.ca)
        officials = sorted(brand["domains"], key=lambda d: d.split(".")[-1] != host_ending)
        for official in officials:
            real = name_part(official)
            if len(real) < 5 or name == real:
                continue
            if cleaned == real:
                if shown != host:
                    return official, "it uses a letter from another alphabet"
                return official, "it swaps in look-alike characters"
            if edit_distance(name, real) == 1:
                return official, "only one letter is different"
    return None


def brand_in_other_domain(host):
    """A brand's name used inside someone else's domain, like
    dalhousie-secure.ca or paypal.com.verify-account.net. Returns the brand or None."""
    if not host or is_official(host):
        return None
    for brand in BRANDS:
        for word in brand["keywords"]:
            word = word.replace(" ", "")
            if len(word) >= 5 and word in host.lower():
                return brand
    return None


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------- check 1: display name ----------

def check_display_name(p):
    name = p["from_name"]
    lowered = name.lower()
    domain = p["from_domain"]

    hidden = re.search(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", lowered)
    if hidden and hidden.group(0) != p["from_addr"]:
        return [finding("display_hidden_address", 25,
                        "The sender's name shows " + hidden.group(0) + ", but the email really came from "
                        + p["from_addr"] + ".")]

    brand = brand_named_in(lowered)
    if brand and registered_domain(domain) not in brand["domains"]:
        return [finding("display_brand", 20,
                        "The sender's name says \"" + name + "\", but the email came from " + p["from_addr"]
                        + ", which is not a " + brand["name"] + " address.")]

    if domain in FREE_MAIL:
        for word in ROLE_WORDS:
            if re.search(r"\b" + word + r"\b", lowered):
                return [finding("display_role_freemail", 20,
                                "The sender calls themselves \"" + name + "\" but wrote from a personal "
                                + domain + " address. Real staff use their work email.")]
    return []


# ---------- check 2: lookalike domains ----------

def check_lookalike_domains(p):
    found = []
    sender = p["from_domain"]
    look = lookalike_of(sender)
    if look:
        found.append(finding("lookalike_sender", 35,
                             "The sender's domain " + decode_host(sender) + " is made to look like "
                             + look[0] + ": " + look[1] + "."))
    else:
        brand = brand_in_other_domain(sender)
        if brand:
            found.append(finding("brand_in_sender_domain", 30,
                                 "The sender's domain " + sender + " uses the name " + brand["name"]
                                 + ", but it is not " + brand["name"] + "'s real domain ("
                                 + brand["domains"][0] + ")."))

    for link in p["links"]:
        host = link["host"]
        look = lookalike_of(host)
        if look:
            found.append(finding("link_lookalike", 30,
                                 "A link goes to " + decode_host(host) + ", which is made to look like "
                                 + look[0] + ": " + look[1] + "."))
            break
        brand = brand_in_other_domain(host)
        if brand:
            found.append(finding("link_brand_other", 30,
                                 "A link goes to " + host + ", which uses the name " + brand["name"]
                                 + " but is not " + brand["name"] + "'s real website."))
            break
    return found


# ---------- check 3: links ----------

def looks_like_address(text):
    text = text.strip().lower()
    return " " not in text and "." in text and (text.startswith("http") or text.startswith("www.")
                                                 or re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(/.*)?$", text))


def check_links(p):
    found = []
    codes = set()
    for link in p["links"]:
        host = link["host"]
        if not host:
            continue
        text = link["text"].strip()

        if "link_text_mismatch" not in codes and looks_like_address(text):
            shown = text if "://" in text else "http://" + text
            shown_host = shown.split("://", 1)[1].split("/")[0].lower()
            if registered_domain(shown_host) != registered_domain(host):
                codes.add("link_text_mismatch")
                found.append(finding("link_text_mismatch", 25,
                                     "A link shows " + shown_host + " but really goes to " + host + "."))

        if "shortener" not in codes and host.lower() in SHORTENERS:
            codes.add("shortener")
            found.append(finding("shortener", 10,
                                 "A link is hidden behind a link shortener (" + host
                                 + "), so you can't see where it really goes."))

        if "punycode" not in codes and ("xn--" in host or not host.isascii()):
            codes.add("punycode")
            found.append(finding("punycode", 25,
                                 "A link goes to " + host + ", which shows as " + decode_host(host)
                                 + " but uses letters from another alphabet."))

        if "ip_link" not in codes and is_ip_address(host):
            codes.add("ip_link")
            found.append(finding("ip_link", 20,
                                 "A link goes to a bare number address (" + host
                                 + ") instead of a website name. Real companies don't do this."))
    return found


# ---------- check 4: headers ----------

def check_headers(p):
    found = []
    sender_domain = registered_domain(p["from_domain"]) if p["from_domain"] else ""

    reply = p["reply_to"]
    if reply and "@" in reply and registered_domain(reply.split("@")[1]) != sender_domain:
        found.append(finding("reply_to", 15,
                             "Replies would go to " + reply + ", not to the sender's address "
                             + p["from_addr"] + "."))

    auth = p["auth"]
    dmarc_passed = auth is not None and auth["dmarc"] == "pass"
    if auth is None:
        found.append(finding("no_auth", 10,
                             "The email has no sender checks (SPF, DKIM, DMARC), so there is no proof "
                             "of who sent it."))
    elif auth["dmarc"] == "fail":
        found.append(finding("dmarc_fail", 25,
                             "The email failed the check that proves it came from " + p["from_domain"]
                             + " (DMARC failed)."))
    else:
        failed = [name.upper() for name in ["spf", "dkim"] if auth[name] in ("fail", "softfail")]
        if failed:
            found.append(finding("spf_dkim_fail", 10,
                                 "The email failed a sender check (" + " and ".join(failed)
                                 + "), so it may not really be from " + p["from_domain"] + "."))

    # Bulk mail often bounces to a mailing service, which is fine when DMARC
    # passes (DMARC already proves the From domain). So only count it otherwise.
    rp = p["return_path"]
    if rp and "@" in rp and not dmarc_passed:
        if registered_domain(rp.split("@")[1]) != sender_domain:
            found.append(finding("return_path", 10,
                                 "Bounced mail goes to " + rp.split("@")[1] + ", a different domain from "
                                 "the sender, and the sender checks did not pass."))
    return found


# ---------- check 5: urgency and pressure ----------

def check_urgency(p):
    text = (p["subject"] + " " + p["text"]).lower()
    phrases = []
    for pattern in URGENCY:
        m = re.search(pattern, text)
        if m and m.group(0) not in phrases:
            phrases.append(m.group(0))
    if not phrases:
        return []
    quoted = ", ".join("\"" + x + "\"" for x in phrases[:3])
    if len(phrases) == 1:
        return [finding("urgency_one", 10, "It pushes you to act fast: " + quoted + ".")]
    return [finding("urgency_many", 20, "It pushes you to act fast: " + quoted + ".")]


# ---------- check 6: attachments ----------

def ending(name):
    name = name.lower()
    return name[name.rfind("."):] if "." in name else ""


def check_attachments(p):
    worst = None
    for a in p["attachments"]:
        name = a["name"]
        kind = ending(name)
        if kind in PROGRAM_TYPES:
            parts = name.lower().split(".")
            if len(parts) >= 3:
                reason = ("The attachment " + name + " pretends to be a ." + parts[-2]
                          + " file but is really a program. Opening it could install malware.")
            else:
                reason = "The attachment " + name + " is a program, not a document. Opening it could install malware."
            return [finding("attach_program", 40, reason)]
        if kind == ".zip":
            for inner in a["inside"]:
                if ending(inner) in PROGRAM_TYPES:
                    return [finding("zip_program", 40,
                                    "The zip file " + name + " has a program inside (" + inner
                                    + ") dressed up as a document.")]
        if kind in MACRO_TYPES and worst is None:
            worst = finding("attach_macro", 30,
                            "The attachment " + name + " is an Office file that can run hidden code (macros).")
    return [worst] if worst else []


# ---------- putting it together ----------

CHECKS = [check_display_name, check_lookalike_domains, check_links, check_headers,
          check_urgency, check_attachments]


def verdict_for(score):
    if score >= PHISHING_AT:
        return "Phishing"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Likely safe"


def score_email(p):
    findings = []
    for check in CHECKS:
        findings += check(p)
    findings.sort(key=lambda f: -f["points"])
    score = min(100, sum(f["points"] for f in findings))
    return {"score": score, "verdict": verdict_for(score), "findings": findings}
