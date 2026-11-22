# Phishing Triage for Security Awareness

A Python tool that reads a `.eml` email file and gives back a verdict an ordinary employee can act on: **Phishing**, **Suspicious** or **Likely safe**, a score from 0 to 100, the reasons in plain English, and a short paragraph saying what to do and what not to do. It runs on one email or a whole folder, fully offline.

> **All emails in this repo are SYNTHETIC / MOCK.** The 20 samples in `samples/`, the test fixtures and the model's training mail were all made up for this project. No real inbox was read and no real email was used. Brand names (Microsoft, PayPal, Canada Post, ...) appear because phishing imitates real brands, but every sample is marked SYNTHETIC in an `X-Synthetic` header and in its first line, and its attachments are a few bytes of placeholder text, not real files. Outside IP addresses come from the documentation ranges (RFC 5737).

The point of the tool is the second half of the job in a security-awareness role: not just deciding "phishing or not", but explaining to the person who reported it what gave it away and what to do next.

## What it checks

Each check is its own small function in [`checks.py`](checks.py), and every finding comes with one plain-English sentence.

1. **Sender name vs address.** The name says "IT Helpdesk" or "Microsoft 365" but the address is a Gmail account or someone else's domain (+20). A name that contains a different email address, like `"support@paypal.com" <alerts@mailbox-relay.net>` (+25).
2. **Lookalike domains.** The sender's domain or a link's domain imitates a well-known brand from [`config/brands.csv`](config/brands.csv). Caught when:
   - the name is one letter away (`amazom.ca` vs `amazon.ca`)
   - it swaps in look-alike characters (`micros0ft`, `rnicrosoft`, a Cyrillic `а` in `pаypal`)
   - it puts the brand's name inside a different domain (`dalhousie-secure.ca`, `canadapost-delivery.info`)

   +35 for the sender, +30 for the sender's domain using a brand name, +30 for a link.
3. **Links.**
   - The text shows one address but the link goes to another (+25).
   - A link shortener such as bit.ly hides the destination (+10).
   - Punycode or non-ASCII letters in the domain (+25).
   - A bare IP address instead of a name (+20).
4. **Headers.**
   - Reply-To goes to a different domain than From (+15).
   - DMARC failed (+25), or SPF/DKIM failed (+10).
   - No sender checks at all (+10).
   - The bounce address (Return-Path) is on another domain and DMARC did not pass (+10).
5. **Urgency and pressure.** Phrases like "urgent", "within 24 hours", "verify now", "your account will be locked": one phrase +10, two or more +20.
6. **Risky attachments.**
   - A program (`.exe`, `.scr`, `.js`, `.iso`...), including disguised ones like `invoice.pdf.exe` (+40).
   - A `.zip` with a program inside, judged by name only (+40).
   - A macro-enabled Office file (`.docm`, `.xlsm`...) (+30).

Attachments are **never opened or run**. The tool reads their names, and for a `.zip` it reads the list of file names inside without extracting anything.

**Score** = the sum, capped at 100. **60 or more is Phishing, 30 to 59 Suspicious, under 30 Likely safe.**

## Run it (3 commands)

Needs Python 3.9 or newer. The triage tool uses only the standard library, so `requirements.txt` installs nothing.

```bash
git clone https://github.com/EkinDeveci1907/phishing-triage.git && cd phishing-triage
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 triage.py samples/01_phish_it_helpdesk.eml
```

Batch mode, a whole folder at once:

```bash
python3 triage.py samples/
```

This prints a table, checks it against `samples/expected.csv` when that file is present, and writes `output/triage_report.csv` with every reason and the employee message for each email.

## Sample output

One email (`python3 triage.py samples/01_phish_it_helpdesk.eml`):

```
*** SYNTHETIC / MOCK email ***
File:      01_phish_it_helpdesk.eml
From:      Dalhousie IT Helpdesk <dal.it.helpdesk@gmail.com>
Subject:   Your password expires today - verify now
Received:  1 hop(s), first: from mail-sor-f41.google.com (mail-sor-f41.google.com [192.0.2.41])
Links:     2   Attachments: none

Verdict:   PHISHING   (score 95/100)
Model:     0.98 chance of phishing (demo trained on synthetic mail; trust the score above)

Why:
  +30  A link goes to dalhousie-secure.ca, which uses the name Dalhousie University but is not Dalhousie University's real website.
  +25  A link shows www.dal.ca but really goes to dalhousie-secure.ca.
  +20  The sender's name says "Dalhousie IT Helpdesk", but the email came from dal.it.helpdesk@gmail.com, which is not a Dalhousie University address.
  +20  It pushes you to act fast: "within 24 hours", "verify now", "account will be locked".

What to tell the employee:
  This email is very likely phishing (score 95/100). What gave it away: A link goes to
  dalhousie-secure.ca, which uses the name Dalhousie University but is not Dalhousie
  University's real website. A link shows www.dal.ca but really goes to
  dalhousie-secure.ca. The sender's name says "Dalhousie IT Helpdesk", but the email came
  from dal.it.helpdesk@gmail.com, which is not a Dalhousie University address. What to do:
  report it with the Report Phishing button, or forward it to the IT security team, then
  delete it. Do not click the links, open attachments, reply, or type your password
  anywhere it sends you. If you already clicked or entered your password, change your
  password on the real website and tell IT right away. You won't get in trouble for
  reporting it.
```

Note that this email passes SPF, DKIM and DMARC. Gmail really did send it; the problem is who is using the Gmail account.

The whole folder (`python3 triage.py samples/`):

| File | Verdict | Score | Model (demo) | Main reason |
|---|---|---:|---:|---|
| 01_phish_it_helpdesk | Phishing | 95 | 0.98 | Link to dalhousie-secure.ca, not Dalhousie's real site |
| 02_phish_microsoft_lookalike | Phishing | 100 | 1.00 | Sender micros0ft.com imitates microsoft.com |
| 03_phish_canada_post_fee | Phishing | 100 | 1.00 | Sender canadapost-delivery.info is not Canada Post |
| 04_phish_invoice_zip | Phishing | 85 | 0.84 | Zip holds Invoice_8841.pdf.exe |
| 05_phish_salary_macro | Phishing | 80 | 0.93 | Macro-enabled Word file |
| 06_phish_paypal_punycode | Phishing | 100 | 0.99 | pаypal.com with a Cyrillic а |
| 07_phish_docusign_ip | Phishing | 100 | 1.00 | Sender docusign-envelopes.net is not DocuSign |
| 08_susp_gift_cards | Suspicious | 40 | 0.26 | A "Dean" writing from Outlook.com |
| 09_susp_survey_ip_link | Suspicious | 30 | 0.22 | Link to a bare IP address |
| 10_susp_shared_file_shortener | Suspicious | 35 | 0.69 | Replies go to a Gmail address |
| 11_susp_newsletter_no_auth | Suspicious | 30 | 0.31 | Link hidden behind bit.ly |
| 12_susp_amazon_lookalike_link | Suspicious | 30 | 0.11 | Link to amazom.ca, one letter off amazon.ca |
| 13_safe_dal_newsletter | Likely safe | 0 | 0.06 | - |
| 14_safe_github_password_reset | Likely safe | 10 | 0.18 | "in 24 hours" |
| 15_safe_canada_post_delivery | Likely safe | 0 | 0.06 | - |
| 16_safe_it_maintenance | Likely safe | 20 | 0.17 | "urgent", "immediately" |
| 17_safe_microsoft_signin_alert | Likely safe | 10 | 0.18 | "unusual sign-in" |
| 18_safe_colleague_report | Likely safe | 0 | 0.06 | - |
| 19_safe_zoom_invite | Likely safe | 0 | 0.06 | - |
| 20_safe_amazon_shipped | Likely safe | 0 | 0.06 | - |

Phishing 7, Suspicious 5, Likely safe 8: **matches the answer key for all 20.** The full outputs are in [`sample_output/`](sample_output).

### What the employee is told for the other two verdicts

Suspicious (`08_susp_gift_cards.eml`, a gift-card request from a "Dean" on Outlook.com):

> Some things about this email are not right (score 40/100). What to check: The sender calls themselves "Dr. Dana Whitfield, Dean of Science" but wrote from a personal outlook.com address. Real staff use their work email. It pushes you to act fast: "urgently", "right away". Before you do what it asks, contact the sender another way, using a phone number or address you already know, not one from this email. Don't click links, open attachments, or send money or gift cards until you have checked. If you can't confirm it, report it.

Likely safe (`16_safe_it_maintenance.eml`, a genuine but urgent IT notice):

> No strong warning signs in this email (score 20/100). One small thing to notice: It pushes you to act fast: "urgent", "immediately". It's fine to act on it if you were expecting it. If it ever asks for your password, payment, or something unusual, check with the sender first, and report it if you're unsure.

## What was planted in the samples

`make_samples.py` builds the 20 emails, and `samples/expected.csv` is the answer key: the verdict each one should get and the exact findings planted in it. The tool finds exactly those, no more and no fewer. That is 48 findings across 15 emails, and the test suite checks every one.

- **7 phishing:**
  - a fake IT helpdesk on Gmail with a link to `dalhousie-secure.ca`
  - `micros0ft.com`
  - a Canada Post parcel-fee scam behind bit.ly
  - a zip with `Invoice_8841.pdf.exe` inside
  - a macro-enabled "salary review"
  - a PayPal lookalike in punycode (`xn--pypal-4ve.com`)
  - a DocuSign lookalike whose link text shows `docusign.net` but goes to a bare IP
- **5 suspicious:**
  - a gift-card request from a "Dean" on Outlook.com
  - a survey link to a bare IP with a failed DKIM: exactly 30 points, the boundary
  - a vendor email whose replies go to Gmail and whose link is shortened
  - a newsletter with no sender checks and a shortened link
  - a lone lookalike link to `amazom.ca`
- **8 likely safe, 6 of them deliberate near misses that must not be flagged:**
  - a Dal newsletter whose bounces go to a mailing service (fine, because DMARC passes for dal.ca)
  - a GitHub password reset you asked for, which says "expires in 24 hours"
  - Canada Post's real domain, `canadapost-postescanada.ca`, which looks made up but is genuine
  - an urgent outage notice from the real `dal.ca`
  - a real Microsoft sign-in alert from `accountprotection.microsoft.com`
  - a colleague's report with a Reply-To that matches From
  - plus a Zoom invite and an Amazon shipping notice.

Planted findings by type: urgency 12 (7 with two or more phrases), sender name mismatch 6, lookalike or brand-named domain 8 (sender 4, link 4), shortener 3, no sender checks 3, Reply-To mismatch 3, DMARC fail 2, SPF/DKIM fail 2, Return-Path mismatch 2, link text mismatch 2, IP link 2, punycode 1, zip with a program 1, macro file 1.

## The demo model (and why the rule score is the part to trust)

[`train_model.py`](train_model.py) trains a scikit-learn logistic regression on the same features the checks produce (each finding present or not). It is trained **only on 1,000 synthetic emails** that the script makes up: each is randomly "phishing" or "normal", each warning sign is added with a different chance for each kind, and 3% of labels are flipped on purpose. On 250 held-out synthetic emails:

```
Logistic regression (demo model)  accuracy 0.892  precision 0.962  recall 0.813
Rule score (Suspicious or worse)  accuracy 0.852  precision 0.816  recall 0.902
```

Do not read this as "the model beats the rules". Both numbers only measure how well each method fits mail this project invented, so they say nothing about real phishing. The model learned the made-up mix of signs. For example, it gives little weight to a lookalike link, because some of the made-up normal mail had one too, so it rates `12_susp_amazon_lookalike_link` at 0.11 while the rules call it Suspicious. The rule score is the part to trust: every point comes from a check with a reason a person can read and verify.

The learned weights are saved as plain numbers in `model.json`, and triage applies them with a few lines of ordinary math in [`model.py`](model.py). So triage does not need scikit-learn, and no pickle file is ever loaded. To retrain:

```bash
pip install -r requirements-train.txt
python3 train_model.py
```

Retraining is deterministic and gives the same `model.json`. The full report and the weights are in [`sample_output/model_report.txt`](sample_output/model_report.txt).

## Resource use

Measured on 2026-11-21 with `python3 measure.py` on a MacBook Air M2 (8 GB RAM), in a Linux shell running on that Mac (Python 3.10, arm64):

- **Triage**, one email and then the whole samples folder: peak memory **14 MB**. Disk is **16 MB** in total: 0.2 MB for the project and 15 MB for the `.venv`, which is just pip.
- **Retraining the demo model** (optional): a venv with scikit-learn, numpy and scipy is **269 MB**, which is over this project's 200 MB budget. That is why scikit-learn is kept out of the triage tool's requirements. Training peaks at **108 MB** of memory, takes a few seconds, and reproduced the shipped `model.json` exactly (scikit-learn 1.7.2 on the Mac, 1.9.1 where it was first trained).

Run `python3 measure.py` to get the numbers for your own machine.

## Tests

`python3 -m unittest discover -s tests -v` runs 23 tests. The fixtures in `tests/fixture/` are small `.eml` files written by hand, each saying in its body what it should produce. Attachment cases are built in the test code. The boundary cases:

- `amazom.com`, 1 edit from amazon.com: flagged. `amazing.com`, 2 edits: not flagged. `g00gle.com` is 2 edits but swaps 0 for o: flagged.
- Urgent wording in a genuine `dal.ca` email with every check passing: Likely safe.
- A Reply-To that matches From: nothing. A Reply-To on Gmail: flagged.
- A Return-Path on another domain: flagged without sender checks, ignored when DMARC passes.
- Scores of 29 and 30, and of 59 and 60, fall on either side of the verdict lines.
- A zip with `scan.pdf.exe` inside: flagged. A zip with only `scan.pdf`: not flagged.
- Every sample matches its verdict and its exact planted findings in `expected.csv`.

Changing any threshold or rule (for example 60 to 61, the edit distance from 1 to 2, or dropping the 0-for-o swap) makes at least one test fail.

## Project layout

```
triage.py             command line: one .eml or a whole folder
emailparse.py         reads a .eml with Python's email package: headers, text, links, attachment names
checks.py             the six checks, the score and the verdict
awareness.py          the "what to tell the employee" paragraph
model.py              applies the demo model's saved weights (no scikit-learn needed)
model.json            the demo model's weights, learned from SYNTHETIC mail
train_model.py        retrains the demo model with scikit-learn
mailmaker.py          builds SYNTHETIC emails (used by make_samples.py and train_model.py)
make_samples.py       writes the 20 SYNTHETIC samples and their answer key
config/brands.csv     brands that phishing imitates, and their real domains
samples/              the 20 SYNTHETIC .eml files and expected.csv
sample_output/        batch table, single-email outputs, CSV report, model report
measure.py            measures memory and disk use
tests/                unittest suite and hand-written .eml fixtures
```

## Limits

This is a portfolio project, not an email gateway. A real one would also need:

- **Trustworthy sender-check results.** The tool reads the `Authentication-Results` header as written. A real mail server strips any copy of that header arriving from outside before adding its own, so trust it only on mail exported from your own mailbox.
- **Reputation and live lookups.** There is no URL reputation, domain age or DNS lookup, on purpose, so it works offline. Real gateways use all three.
- **More brands and languages.** The brand list has 14 entries and the urgency phrases are English only.
- **Better handling of business email compromise.** A gift-card request with no links or attachments only reaches Suspicious, which is why the awareness text for Suspicious says to confirm by phone.
- **Real training data.** The demo model has never seen real mail.
