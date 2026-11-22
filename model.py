# model.py
#
# The demo model at triage time. The weights were learned by train_model.py
# (scikit-learn logistic regression on SYNTHETIC mail only) and saved as
# plain numbers in model.json, so using them needs no extra packages:
#
#   probability = 1 / (1 + e^-(intercept + sum of weight * feature))
#
# The features are the same findings the rule checks produce, 1 if present
# and 0 if not. The rule-based score is the part to trust; this number is a
# demo of the ML workflow, not a phishing detector.

import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "model.json")

FEATURES = ["display_hidden_address", "display_brand", "display_role_freemail",
            "lookalike_sender", "brand_in_sender_domain", "link_lookalike", "link_brand_other",
            "link_text_mismatch", "shortener", "punycode", "ip_link", "reply_to", "no_auth",
            "dmarc_fail", "spf_dkim_fail", "return_path", "urgency_one", "urgency_many",
            "attach_program", "zip_program", "attach_macro"]


def features(result):
    codes = set(f["code"] for f in result["findings"])
    return [1 if name in codes else 0 for name in FEATURES]


def load_model(path=MODEL_PATH):
    """Returns the saved model, or None if train_model.py hasn't been run."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def phishing_probability(model, vector):
    z = model["intercept"]
    for weight, value in zip(model["weights"], vector):
        z += weight * value
    return 1 / (1 + math.exp(-z))
