# Tests for phishing triage.
#
# tests/fixture/ holds small .eml files written by hand. Each one says in its
# body what it should produce, and FIXTURES below holds the same answer.
# Attachment cases are built in code (a zip has to be base64 inside an email,
# which is not something to type by hand).
#
# Run from the project folder:  python3 -m unittest discover -s tests -v

import csv
import os
import unittest

from awareness import employee_message
from checks import (brand_in_other_domain, edit_distance, lookalike_of, registered_domain,
                    score_email, verdict_for)
from emailparse import parse_eml, parse_file
from mailmaker import auth_header, build_message
from model import FEATURES, features, load_model, phishing_probability

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixture")
SAMPLES = os.path.join(os.path.dirname(HERE), "samples")

# file -> (verdict, score, finding codes, words the explanation must contain)
FIXTURES = {
    "f01_one_edit.eml": ("Suspicious", 35, ["lookalike_sender"],
                         ["amazon.com", "only one letter is different"]),
    "f02_two_edits.eml": ("Likely safe", 0, [], []),
    "f03_urgent_but_genuine.eml": ("Likely safe", 20, ["urgency_many"], ['"urgent"', '"immediately"']),
    "f04_reply_to_same.eml": ("Likely safe", 0, [], []),
    "f05_reply_to_other.eml": ("Likely safe", 15, ["reply_to"], ["alex.sample.notes@gmail.com"]),
    "f06_no_auth_return_path.eml": ("Likely safe", 20, ["no_auth", "return_path"], ["listmailer.net"]),
    "f07_return_path_dmarc_pass.eml": ("Likely safe", 0, [], []),
    "f08_hidden_address.eml": ("Suspicious", 50, ["display_hidden_address", "dmarc_fail"],
                               ["shows support@paypal.com", "DMARC failed"]),
    "f09_link_text_mismatch.eml": ("Suspicious", 35, ["link_text_mismatch", "no_auth"],
                                   ["shows www.rbc.com but really goes to rbc-secure-login.top"]),
}


def score_message(msg):
    return score_email(parse_eml(bytes(msg)))


def codes(result):
    return sorted(f["code"] for f in result["findings"])


def plain(subject="Hello", text="Hi there.", html=None, attachments=None,
          sender="Alex Sample <alex.sample@dal.ca>"):
    """A clean email from dal.ca with passing checks, plus whatever is added."""
    return build_message(from_header=sender, to="you@dal.ca", subject=subject, text=text, html=html,
                         auth=auth_header("dal.ca"), attachments=attachments)


class TestFixtures(unittest.TestCase):

    def test_every_fixture(self):
        for name, (verdict, score, expected_codes, words) in FIXTURES.items():
            with self.subTest(fixture=name):
                result = score_email(parse_file(os.path.join(FIXTURE, name)))
                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(result["score"], score)
                self.assertEqual(codes(result), sorted(expected_codes))
                reasons = " ".join(f["reason"] for f in result["findings"])
                for word in words:
                    self.assertIn(word, reasons)


class TestDomains(unittest.TestCase):

    def test_edit_distance(self):
        self.assertEqual(edit_distance("amazom", "amazon"), 1)
        self.assertEqual(edit_distance("amazing", "amazon"), 2)
        self.assertEqual(edit_distance("micros0ft", "microsoft"), 1)

    def test_one_edit_is_lookalike_two_is_not(self):
        self.assertEqual(lookalike_of("amazom.com")[0], "amazon.com")
        self.assertIsNone(lookalike_of("amazing.com"))

    def test_swapped_letters(self):
        self.assertEqual(lookalike_of("rnicrosoft.com")[0], "microsoft.com")   # rn looks like m
        self.assertEqual(lookalike_of("g00gle.com")[0], "google.com")          # 2 edits, but 0 looks like o
        self.assertIn("another alphabet", lookalike_of("xn--pypal-4ve.com")[1])

    def test_real_domains_are_not_lookalikes(self):
        self.assertIsNone(lookalike_of("microsoft.com"))
        self.assertIsNone(lookalike_of("login.microsoftonline.com"))
        self.assertIsNone(lookalike_of("dal.ca"))

    def test_brand_used_in_other_domain(self):
        self.assertEqual(brand_in_other_domain("dalhousie-secure.ca")["name"], "Dalhousie University")
        self.assertEqual(brand_in_other_domain("paypal.com.verify-account.net")["name"], "PayPal")
        # looks made up, but it is Canada Post's real domain
        self.assertIsNone(brand_in_other_domain("www.canadapost-postescanada.ca"))

    def test_registered_domain(self):
        self.assertEqual(registered_domain("its.dal.ca"), "dal.ca")
        self.assertEqual(registered_domain("www.canada.gc.ca"), "canada.gc.ca")
        self.assertEqual(registered_domain("login.micros0ft.com"), "micros0ft.com")


class TestLinks(unittest.TestCase):

    def test_punycode_link(self):
        html = '<a href="https://xn--pypal-4ve.com/signin">Log in</a>'
        result = score_message(plain(html=html))
        self.assertEqual(codes(result), ["link_lookalike", "punycode"])

    def test_shortener_and_ip(self):
        self.assertEqual(codes(score_message(plain(text="See https://bit.ly/abc"))), ["shortener"])
        self.assertEqual(codes(score_message(plain(text="See http://203.0.113.5/x"))), ["ip_link"])

    def test_matching_link_text_is_fine(self):
        html = '<a href="https://www.dal.ca/news">www.dal.ca/news</a>'
        self.assertEqual(codes(score_message(plain(html=html))), [])


class TestAttachments(unittest.TestCase):

    def test_zip_with_program_inside(self):
        result = score_message(plain(attachments=[("scan.zip", ["scan.pdf.exe"])]))
        self.assertEqual(codes(result), ["zip_program"])
        self.assertIn("scan.pdf.exe", result["findings"][0]["reason"])

    def test_zip_with_only_documents(self):
        self.assertEqual(codes(score_message(plain(attachments=[("scans.zip", ["scan.pdf"])]))), [])

    def test_double_extension(self):
        result = score_message(plain(attachments=[("invoice.pdf.exe", [])]))
        self.assertEqual(codes(result), ["attach_program"])
        self.assertIn("pretends to be a .pdf", result["findings"][0]["reason"])

    def test_macro_and_normal_files(self):
        self.assertEqual(codes(score_message(plain(attachments=[("budget.xlsm", [])]))), ["attach_macro"])
        self.assertEqual(codes(score_message(plain(attachments=[("report.pdf", [])]))), [])

    def test_attachment_names_are_read(self):
        p = parse_eml(bytes(plain(attachments=[("scan.zip", ["a.txt", "b.exe"])])))
        self.assertEqual(p["attachments"][0]["name"], "scan.zip")
        self.assertEqual(p["attachments"][0]["inside"], ["a.txt", "b.exe"])


class TestScore(unittest.TestCase):

    def test_verdict_boundaries(self):
        self.assertEqual(verdict_for(29), "Likely safe")
        self.assertEqual(verdict_for(30), "Suspicious")
        self.assertEqual(verdict_for(59), "Suspicious")
        self.assertEqual(verdict_for(60), "Phishing")

    def test_score_is_capped(self):
        result = score_email(parse_file(os.path.join(SAMPLES, "02_phish_microsoft_lookalike.eml")))
        self.assertGreater(sum(f["points"] for f in result["findings"]), 100)
        self.assertEqual(result["score"], 100)

    def test_one_urgent_word_vs_many(self):
        self.assertEqual(codes(score_message(plain(subject="Urgent"))), ["urgency_one"])
        self.assertEqual(codes(score_message(plain(subject="Urgent", text="Reply immediately."))),
                         ["urgency_many"])


class TestAwareness(unittest.TestCase):

    def test_phishing_message(self):
        result = score_email(parse_file(os.path.join(SAMPLES, "01_phish_it_helpdesk.eml")))
        text = employee_message(result)
        self.assertIn("very likely phishing", text)
        self.assertIn("report it", text)
        self.assertIn("Do not click", text)
        self.assertIn(result["findings"][0]["reason"], text)    # what gave it away

    def test_suspicious_message(self):
        result = score_email(parse_file(os.path.join(SAMPLES, "08_susp_gift_cards.eml")))
        text = employee_message(result)
        self.assertIn("contact the sender another way", text)
        self.assertIn("gift cards", text)

    def test_safe_message(self):
        result = score_email(parse_file(os.path.join(FIXTURE, "f03_urgent_but_genuine.eml")))
        text = employee_message(result)
        self.assertIn("No strong warning signs", text)
        self.assertIn("One small thing to notice", text)


class TestSamples(unittest.TestCase):
    """The README quotes these results, so check they stay true."""

    def test_answer_key(self):
        with open(os.path.join(SAMPLES, "expected.csv"), newline="") as f:
            rows = list(csv.DictReader(line for line in f if not line.startswith("#")))
        self.assertEqual(len(rows), 20)
        counts = {}
        for row in rows:
            with self.subTest(sample=row["file"]):
                parsed = parse_file(os.path.join(SAMPLES, row["file"]))
                self.assertTrue(parsed["synthetic"])
                result = score_email(parsed)
                self.assertEqual(result["verdict"], row["expected_verdict"])
                planted = sorted(c for c in row["planted"].split(";") if c)
                self.assertEqual(codes(result), planted)
                counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        self.assertEqual(counts, {"Phishing": 7, "Suspicious": 5, "Likely safe": 8})


class TestModel(unittest.TestCase):

    def test_saved_model_works(self):
        model = load_model()
        self.assertIsNotNone(model)
        self.assertEqual(model["features"], FEATURES)
        result = score_email(parse_file(os.path.join(SAMPLES, "02_phish_microsoft_lookalike.eml")))
        high = phishing_probability(model, features(result))
        result = score_email(parse_file(os.path.join(SAMPLES, "18_safe_colleague_report.eml")))
        low = phishing_probability(model, features(result))
        self.assertTrue(0 <= low < high <= 1)


if __name__ == "__main__":
    unittest.main()
