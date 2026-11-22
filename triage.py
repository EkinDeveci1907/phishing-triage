# triage.py
#
# Phishing triage for security awareness.
#
#   python3 triage.py samples/01_phish_it_helpdesk.eml    one email: verdict, reasons, advice
#   python3 triage.py samples/                            a folder: summary table + CSV report
#
# Works fully offline: no lookups, no network calls. Attachments are never
# opened or run, only their names are read.

import csv
import os
import sys
import textwrap

from awareness import employee_message
from checks import score_email
from emailparse import parse_file
from model import features, load_model, phishing_probability

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_COLUMNS = ["file", "verdict", "score", "model_demo", "from", "subject", "reasons", "tell_the_employee"]


def triage(path, model):
    parsed = parse_file(path)
    result = score_email(parsed)
    result["file"] = os.path.basename(path)
    result["parsed"] = parsed
    result["message"] = employee_message(result)
    result["model"] = None
    if model is not None:
        result["model"] = phishing_probability(model, features(result))
    return result


def model_text(result):
    if result["model"] is None:
        return "-"
    return format(result["model"], ".2f")


def show_one(result):
    p = result["parsed"]
    # never split a domain like dalhousie-secure.ca across two lines
    wrap = textwrap.TextWrapper(width=90, initial_indent="  ", subsequent_indent="  ",
                                break_on_hyphens=False, break_long_words=False)
    print()
    if p["synthetic"]:
        print("*** SYNTHETIC / MOCK email ***")
    print("File:     ", result["file"])
    print("From:     ", p["from_name"], "<" + p["from_addr"] + ">")
    print("Subject:  ", p["subject"])
    if p["received"]:
        print("Received: ", len(p["received"]), "hop(s), first:", p["received"][-1].split(" by ")[0])
    print("Links:    ", len(p["links"]), "  Attachments:", ", ".join(a["name"] for a in p["attachments"]) or "none")
    print()
    print("Verdict:   " + result["verdict"].upper() + "   (score " + str(result["score"]) + "/100)")
    print("Model:     " + model_text(result) + " chance of phishing (demo trained on synthetic mail; trust the score above)")
    print()
    if result["findings"]:
        print("Why:")
        for f in result["findings"]:
            print("  +" + str(f["points"]).ljust(4) + f["reason"])
    else:
        print("Why: nothing found by any check.")
    print()
    print("What to tell the employee:")
    print(wrap.fill(result["message"]))
    print()


def show_folder(results, folder):
    print()
    if any(r["parsed"]["synthetic"] for r in results):
        print("*** SYNTHETIC / MOCK emails ***")
    print("File".ljust(38) + "Verdict".ljust(13) + "Score".rjust(5) + "Model".rjust(7) + "   Main reason")
    for r in results:
        reason = r["findings"][0]["reason"] if r["findings"] else "-"
        if len(reason) > 70:
            reason = reason[:67] + "..."
        print(r["file"].ljust(38) + r["verdict"].ljust(13) + str(r["score"]).rjust(5)
              + model_text(r).rjust(7) + "   " + reason)

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print()
    print("Phishing:", counts.get("Phishing", 0), "| Suspicious:", counts.get("Suspicious", 0),
          "| Likely safe:", counts.get("Likely safe", 0))

    # if the folder has an answer key (the samples do), check against it
    key_path = os.path.join(folder, "expected.csv")
    if os.path.exists(key_path):
        with open(key_path, newline="") as f:
            expected = {row["file"]: row["expected_verdict"]
                        for row in csv.DictReader(line for line in f if not line.startswith("#"))}
        matches = sum(1 for r in results if expected.get(r["file"]) == r["verdict"])
        print("Matches the answer key (expected.csv):", matches, "of", len(results))


def write_report(results, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        if any(r["parsed"]["synthetic"] for r in results):
            f.write("# SYNTHETIC / MOCK - triage of made-up emails\n")
        writer = csv.writer(f)
        writer.writerow(REPORT_COLUMNS)
        for r in results:
            p = r["parsed"]
            writer.writerow([r["file"], r["verdict"], r["score"], model_text(r), p["from_addr"],
                             p["subject"], " | ".join(f["reason"] for f in r["findings"]), r["message"]])


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 triage.py FILE.eml   or   python3 triage.py FOLDER")
        sys.exit(1)
    target = sys.argv[1]
    model = load_model()

    if os.path.isdir(target):
        names = sorted(n for n in os.listdir(target) if n.lower().endswith(".eml"))
        results = [triage(os.path.join(target, n), model) for n in names]
        show_folder(results, target)
        report = os.path.join(HERE, "output", "triage_report.csv")
        write_report(results, report)
        print("Wrote", os.path.relpath(report, HERE), "(every reason and the employee message for each email)")
    else:
        show_one(triage(target, model))


if __name__ == "__main__":
    main()
