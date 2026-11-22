# train_model.py
#
# Trains the demo model: a scikit-learn logistic regression on 1,000
# SYNTHETIC / MOCK emails made up right here. Nothing real is used.
#
# How the training mail is made: each email is randomly built as "phishing"
# or "normal", and each warning sign is added with a different chance for
# each kind (phishing usually has urgency, normal mail sometimes does too).
# Then every email goes through the same parser and checks as real input,
# and the findings become the features. 3% of labels are flipped on purpose,
# because real labels are never perfect.
#
# Because the model learns from mail this script invented, its accuracy
# only shows that it learned these made-up patterns. It says nothing about
# real phishing.
#
# Needs scikit-learn:  pip install -r requirements-train.txt
# Run:                 python3 train_model.py

import json
import random

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.model_selection import train_test_split

from checks import score_email
from emailparse import parse_eml
from mailmaker import auth_header, build_message
from model import FEATURES, MODEL_PATH

COUNT = 1000
LABEL_NOISE = 0.03
rng = random.Random(2026)

# chance of each sign, for phishing and for normal mail
PHISH = {"lookalike_sender": 0.2, "brand_sender": 0.2, "free_mail": 0.25, "brand_name": 0.5,
         "role_name": 0.2, "link": 0.85, "bad_link": 0.6, "text_mismatch": 0.35, "reply_to": 0.3,
         "no_auth": 0.25, "dmarc_fail": 0.3, "spf_fail": 0.15, "return_path": 0.3, "urgency": 0.8,
         "bad_attachment": 0.25}
NORMAL = {"lookalike_sender": 0.0, "brand_sender": 0.0, "free_mail": 0.15, "brand_name": 0.0,
          "role_name": 0.05, "link": 0.7, "bad_link": 0.12, "text_mismatch": 0.04, "reply_to": 0.1,
          "no_auth": 0.12, "dmarc_fail": 0.03, "spf_fail": 0.05, "return_path": 0.3, "urgency": 0.3,
          "bad_attachment": 0.02}

ORDINARY = ["northwind-supplies.ca", "shopnorth.ca", "halifaxtechmeetup.org", "maritimebooks.ca",
            "harbourdental.ca", "bluenoseinsurance.ca", "atlanticgym.ca", "seasidecu.ca"]
LOOKALIKES = ["micros0ft.com", "paypa1.com", "amaz0n.ca", "rnicrosoft.com", "docuslgn.com",
              "g00gle.com", "netfl1x.com", "linkedln.com"]
BRAND_OTHER = ["paypal-security.net", "canadapost-delivery.info", "docusign-mail.com",
               "microsoft-alerts.org", "dalhousie-secure.ca", "amazon-refunds.net"]
FREE = ["gmail.com", "outlook.com", "yahoo.com", "proton.me"]
REAL_BRANDS = [("Microsoft", "accountprotection.microsoft.com"), ("PayPal", "paypal.com"),
               ("Canada Post", "canadapost-postescanada.ca"), ("Amazon.ca", "amazon.ca"),
               ("GitHub", "github.com"), ("Dalhousie News", "dal.ca")]
PEOPLE = ["Sam Reid", "Jordan Lee", "Taylor Grant", "Morgan Ali", "Casey Roy"]
URGENT = ["urgent", "immediately", "within 24 hours", "final notice", "action required",
          "verify your account", "your account will be locked", "as soon as possible"]


def chance(rates, name):
    return rng.random() < rates[name]


def random_email(phishing):
    rates = PHISH if phishing else NORMAL

    # who it's from
    if chance(rates, "lookalike_sender"):
        domain = rng.choice(LOOKALIKES)
    elif chance(rates, "brand_sender"):
        domain = rng.choice(BRAND_OTHER)
    elif chance(rates, "free_mail"):
        domain = rng.choice(FREE)
    elif not phishing and rng.random() < 0.4:
        brand, domain = rng.choice(REAL_BRANDS)    # real brand mail from its real domain
    else:
        domain = rng.choice(ORDINARY)

    if not phishing and domain in [d for b, d in REAL_BRANDS]:
        name = [b for b, d in REAL_BRANDS if d == domain][0]
    elif chance(rates, "brand_name"):
        name = rng.choice(["Microsoft 365", "PayPal", "Canada Post", "DocuSign"])
    elif chance(rates, "role_name"):
        name = rng.choice(["IT Helpdesk", "Payroll", "Human Resources", "Service Desk"])
    else:
        name = rng.choice(PEOPLE)

    # the body: some urgent phrases, maybe a link
    phrases = rng.sample(URGENT, rng.randint(1, 3)) if chance(rates, "urgency") else []
    text = "Hello, please see below. " + " ".join("Note: " + p + "." for p in phrases)
    html = None
    if chance(rates, "link"):
        if chance(rates, "bad_link"):
            kind = rng.choice(["lookalike", "brand", "short", "ip", "puny"])
            host = {"lookalike": rng.choice(LOOKALIKES), "brand": rng.choice(BRAND_OTHER),
                    "short": "bit.ly", "ip": "203.0.113." + str(rng.randint(2, 250)),
                    "puny": "xn--pypal-4ve.com"}[kind]
        else:
            host = "www." + domain
        shown = "https://www.paypal.com/account" if chance(rates, "text_mismatch") else "Open it here"
        html = '<p>' + text + '</p><p><a href="https://' + host + '/x">' + shown + '</a></p>'

    # headers
    reply_to = "reply." + str(rng.randint(1, 999)) + "@gmail.com" if chance(rates, "reply_to") else None
    if chance(rates, "no_auth"):
        auth = None
    elif chance(rates, "dmarc_fail"):
        auth = auth_header(domain, spf="fail", dkim="fail", dmarc="fail")
    elif chance(rates, "spf_fail"):
        auth = auth_header(domain, spf="softfail", dkim="none", dmarc="none")
    else:
        auth = auth_header(domain)
    return_path = "bounce@mailer-" + str(rng.randint(1, 50)) + ".net" if chance(rates, "return_path") else None

    attachments = []
    if chance(rates, "bad_attachment"):
        attachments = [rng.choice([("update.exe", []), ("invoice.zip", ["invoice.pdf.exe"]), ("form.docm", [])])]
    elif rng.random() < 0.25:
        attachments = [rng.choice([("notes.pdf", []), ("invite.ics", [])])]

    msg = build_message(from_header=name + " <info@" + domain + ">", to="you@dal.ca",
                        subject="Message " + str(rng.randint(1000, 9999)), text=text, html=html,
                        reply_to=reply_to, return_path=return_path, auth=auth, attachments=attachments)
    return score_email(parse_eml(bytes(msg)))


def main():
    rows = []
    labels = []
    rule_flags = []
    for i in range(COUNT):
        phishing = rng.random() < 0.5
        result = random_email(phishing)
        label = 1 if phishing else 0
        if rng.random() < LABEL_NOISE:
            label = 1 - label
        rows.append([1 if f in set(x["code"] for x in result["findings"]) else 0 for f in FEATURES])
        labels.append(label)
        rule_flags.append(0 if result["verdict"] == "Likely safe" else 1)

    indexes = list(range(COUNT))
    train_i, test_i = train_test_split(indexes, test_size=0.25, random_state=7, stratify=labels)
    X_train = [rows[i] for i in train_i]
    y_train = [labels[i] for i in train_i]
    X_test = [rows[i] for i in test_i]
    y_test = [labels[i] for i in test_i]

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    predicted = list(model.predict(X_test))
    rules = [rule_flags[i] for i in test_i]

    def describe(name, guesses):
        tn, fp, fn, tp = confusion_matrix(y_test, guesses).ravel()
        return (name.ljust(34) + "accuracy " + format(accuracy_score(y_test, guesses), ".3f")
                + "  precision " + format(precision_score(y_test, guesses), ".3f")
                + "  recall " + format(recall_score(y_test, guesses), ".3f")
                + "   (TP " + str(tp) + ", FP " + str(fp) + ", FN " + str(fn) + ", TN " + str(tn) + ")")

    report = [
        "SYNTHETIC / MOCK - demo model report",
        "Trained on " + str(len(train_i)) + " and tested on " + str(len(test_i))
        + " made-up emails (" + str(int(LABEL_NOISE * 100)) + "% of labels flipped on purpose).",
        "",
        describe("Logistic regression (demo model)", predicted),
        describe("Rule score (Suspicious or worse)", rules),
        "",
        "These numbers only show how well each method fits mail this project invented.",
        "They are not a measure of how either would do on real phishing.",
    ]
    print("\n".join(report))

    weights = [round(w, 4) for w in model.coef_[0]]
    with open(MODEL_PATH, "w") as f:
        json.dump({"note": "SYNTHETIC / MOCK demo model, trained by train_model.py on made-up mail only.",
                   "features": FEATURES, "weights": weights,
                   "intercept": round(float(model.intercept_[0]), 4),
                   "held_out_accuracy": round(accuracy_score(y_test, predicted), 3)}, f, indent=1)
    with open("sample_output/model_report.txt", "w") as f:
        f.write("\n".join(report) + "\n\nWeights (feature: weight)\n")
        for name, weight in sorted(zip(FEATURES, weights), key=lambda x: -x[1]):
            f.write("  " + name.ljust(24) + format(weight, "+.2f") + "\n")
    print("\nSaved", MODEL_PATH, "and sample_output/model_report.txt")


if __name__ == "__main__":
    main()
