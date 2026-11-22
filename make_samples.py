# make_samples.py
#
# Writes the 20 SYNTHETIC / MOCK sample emails in samples/ and the answer
# key samples/expected.csv. None of these are real emails. The brands are
# real names on purpose, because phishing imitates real brands, but every
# message is marked SYNTHETIC in its headers and its first line, links go
# nowhere useful, and attachments are a few bytes of placeholder text.
#
# Each sample lists the findings it was built to trigger ("planted"). The
# near misses list none: they must come out Likely safe.
#
# Run:  python3 make_samples.py

import csv

from mailmaker import auth_header, build_message

TO = "you@dal.ca"


def hop(host, ip):
    return "from " + host + " (" + host + " [" + ip + "]) by mx.dal.ca; Thu, 19 Nov 2026 08:59:58 -0400"


SAMPLES = [
    # ---------------- clear phishing ----------------
    {"file": "01_phish_it_helpdesk.eml", "expect": "Phishing",
     "planted": "display_brand;link_brand_other;link_text_mismatch;urgency_many",
     "note": "Fake IT helpdesk on Gmail; sender checks pass because Gmail is real",
     "mail": dict(from_header="Dalhousie IT Helpdesk <dal.it.helpdesk@gmail.com>",
                  subject="Your password expires today - verify now",
                  text="Your Dalhousie password expires within 24 hours. Verify now or your account "
                       "will be locked: https://www.dal.ca/password",
                  html='<p>Your Dalhousie password expires within 24 hours. Verify now or your account '
                       'will be locked.</p><p><a href="http://dalhousie-secure.ca/login">https://www.dal.ca/password</a></p>',
                  auth=auth_header("gmail.com"), received=[hop("mail-sor-f41.google.com", "192.0.2.41")])},

    {"file": "02_phish_microsoft_lookalike.eml", "expect": "Phishing",
     "planted": "display_brand;lookalike_sender;link_lookalike;dmarc_fail;urgency_many",
     "note": "micros0ft.com: a zero in place of the letter o",
     "mail": dict(from_header="Microsoft 365 <no-reply@micros0ft.com>",
                  subject="Unusual sign-in activity",
                  text="We noticed unusual sign-in activity. Review it today or your account will be suspended.",
                  html='<p>We noticed unusual sign-in activity. Review it today or your account will be '
                       'suspended.</p><p><a href="https://login.micros0ft.com/review">Review activity</a></p>',
                  auth=auth_header("micros0ft.com", spf="fail", dkim="none", dmarc="fail"),
                  received=[hop("smtp.micros0ft.com", "203.0.113.17")])},

    {"file": "03_phish_canada_post_fee.eml", "expect": "Phishing",
     "planted": "display_brand;brand_in_sender_domain;shortener;no_auth;return_path;urgency_many",
     "note": "Parcel fee scam from canadapost-delivery.info",
     "mail": dict(from_header="Canada Post <notice@canadapost-delivery.info>",
                  subject="Your parcel is on hold",
                  text="Final notice: pay the $2.99 redelivery fee within 24 hours or your parcel goes back.",
                  html='<p>Final notice: pay the $2.99 redelivery fee within 24 hours or your parcel goes '
                       'back.</p><p><a href="https://bit.ly/3xYzAb1">Pay now</a></p>',
                  return_path="bounce@mailer-x.top", received=[hop("mailer-x.top", "198.51.100.66")])},

    {"file": "04_phish_invoice_zip.eml", "expect": "Phishing",
     "planted": "reply_to;spf_dkim_fail;urgency_many;zip_program",
     "note": "Zip holding Invoice_8841.pdf.exe; replies go to a ProtonMail address",
     "mail": dict(from_header="Accounts Payable <ap@northwind-billing.biz>",
                  reply_to="payments.northwind@proton.me",
                  subject="Overdue invoice 8841 - final notice",
                  text="Invoice 8841 is overdue. This is your final notice. Open the attached invoice "
                       "and pay immediately to avoid late fees.",
                  auth=auth_header("northwind-billing.biz", spf="softfail", dkim="none", dmarc="none"),
                  received=[hop("mail.northwind-billing.biz", "203.0.113.88")],
                  attachments=[("Invoice_8841.zip", ["Invoice_8841.pdf.exe"])])},

    {"file": "05_phish_salary_macro.eml", "expect": "Phishing",
     "planted": "reply_to;dmarc_fail;urgency_one;attach_macro",
     "note": "Macro-enabled Word file pretending to be a salary review",
     "mail": dict(from_header="Human Resources <hr-notice@payroll-portal.net>",
                  reply_to="hr.department.office@gmail.com",
                  subject="2026 salary review - action required",
                  text="Your 2026 salary review is attached. Enable editing to see your new salary.",
                  auth=auth_header("payroll-portal.net", spf="fail", dkim="fail", dmarc="fail"),
                  received=[hop("payroll-portal.net", "198.51.100.140")],
                  attachments=[("Salary_Review_2026.docm", [])])},

    {"file": "06_phish_paypal_punycode.eml", "expect": "Phishing",
     "planted": "display_brand;lookalike_sender;link_lookalike;punycode;urgency_many",
     "note": "xn--pypal-4ve.com shows as paypal.com with a Cyrillic a; its sender checks pass",
     "mail": dict(from_header="PayPal <service@xn--pypal-4ve.com>",
                  subject="Confirm your details",
                  text="Please confirm your details. Until you do, your account will be limited.",
                  html='<p>Please confirm your details. Until you do, your account will be limited.</p>'
                       '<p><a href="https://xn--pypal-4ve.com/signin">Log in to PayPal</a></p>',
                  auth=auth_header("xn--pypal-4ve.com"), received=[hop("mx.xn--pypal-4ve.com", "203.0.113.120")])},

    {"file": "07_phish_docusign_ip.eml", "expect": "Phishing",
     "planted": "display_brand;brand_in_sender_domain;link_text_mismatch;ip_link;no_auth;urgency_one",
     "note": "Link text shows docusign.net but goes to a bare IP address",
     "mail": dict(from_header="DocuSign <dse@docusign-envelopes.net>",
                  subject="A document is waiting for your signature",
                  text="You have a document to sign. The link expires in 24 hours.",
                  html='<p>You have a document to sign. The link expires in 24 hours.</p>'
                       '<p><a href="http://198.51.100.24/docs/view">https://www.docusign.net/review</a></p>',
                  received=[hop("docusign-envelopes.net", "198.51.100.24")])},

    # ---------------- suspicious / borderline ----------------
    {"file": "08_susp_gift_cards.eml", "expect": "Suspicious",
     "planted": "display_role_freemail;urgency_many",
     "note": "Gift-card request from a 'Dean' on Outlook.com; no links or attachments to catch",
     "mail": dict(from_header='"Dr. Dana Whitfield, Dean of Science" <d.whitfield.dean@outlook.com>',
                  subject="Quick favour",
                  text="Are you free? I need you to buy five gift cards for a staff event urgently. "
                       "I'm stuck in meetings, so reply right away and I'll explain.",
                  auth=auth_header("outlook.com"), received=[hop("mail-oln040092.outlook.com", "192.0.2.92")])},

    {"file": "09_susp_survey_ip_link.eml", "expect": "Suspicious",
     "planted": "ip_link;spf_dkim_fail",
     "note": "Exactly 30 points: the Suspicious boundary",
     "mail": dict(from_header="Campus Survey Team <survey@studentvoice-research.com>",
                  subject="Win a $50 gift card: 5-minute student survey",
                  text="Tell us about campus life. Take the survey: http://203.0.113.80/survey",
                  auth=auth_header("studentvoice-research.com", dkim="fail", dmarc="none"),
                  received=[hop("mail.studentvoice-research.com", "203.0.113.80")])},

    {"file": "10_susp_shared_file_shortener.eml", "expect": "Suspicious",
     "planted": "reply_to;shortener;urgency_one",
     "note": "Real-looking vendor, but replies go to Gmail and the link is shortened",
     "mail": dict(from_header="Mark Allen <m.allen@northwind-supplies.ca>",
                  reply_to="mark.allen.files@gmail.com",
                  subject="Updated price list",
                  text="Hi, here is the updated price list. Please review it as soon as possible.",
                  html='<p>Hi, here is the updated price list. Please review it as soon as possible.</p>'
                       '<p><a href="https://tinyurl.com/nw-files-2026">Open shared file</a></p>',
                  auth=auth_header("northwind-supplies.ca"),
                  received=[hop("mail.northwind-supplies.ca", "192.0.2.150")])},

    {"file": "11_susp_newsletter_no_auth.eml", "expect": "Suspicious",
     "planted": "no_auth;return_path;shortener",
     "note": "Probably a harmless newsletter, but nothing proves who sent it",
     "mail": dict(from_header="Halifax Tech Meetup <hello@halifaxtechmeetup.org>",
                  subject="December meetup: security talks",
                  text="Join us on December 10 for two short security talks.",
                  html='<p>Join us on December 10 for two short security talks.</p>'
                       '<p><a href="https://bit.ly/htm-dec">RSVP here</a></p>',
                  return_path="bounce@sendlist-mailer.com",
                  received=[hop("out.sendlist-mailer.com", "198.51.100.200")])},

    {"file": "12_susp_amazon_lookalike_link.eml", "expect": "Suspicious",
     "planted": "link_lookalike",
     "note": "One strong sign on its own: amazom.ca is one letter off amazon.ca",
     "mail": dict(from_header="Order Updates <orders@shopnorth.ca>",
                  subject="Your order has shipped",
                  text="Your order has shipped. You can view it on Amazon.",
                  html='<p>Your order has shipped.</p><p><a href="https://www.amazom.ca/orders">View order</a></p>',
                  auth=auth_header("shopnorth.ca"), received=[hop("mail.shopnorth.ca", "192.0.2.170")])},

    # ---------------- legitimate, including near misses ----------------
    {"file": "13_safe_dal_newsletter.eml", "expect": "Likely safe",
     "planted": "",
     "note": "Near miss: bounces go to a mailing service, but DMARC passes for dal.ca",
     "mail": dict(from_header="Dalhousie News <news@dal.ca>",
                  subject="This week at Dal",
                  text="Exam schedule, library hours and winter events.",
                  html='<p>Exam schedule, library hours and winter events.</p>'
                       '<p><a href="https://www.dal.ca/news.html">Read more</a></p>',
                  return_path="bounce-2291@mail.newsletterhub.com", auth=auth_header("dal.ca"),
                  received=[hop("mail.newsletterhub.com", "192.0.2.201")])},

    {"file": "14_safe_github_password_reset.eml", "expect": "Likely safe",
     "planted": "urgency_one",
     "note": "Near miss: a reset you asked for says the link expires in 24 hours",
     "mail": dict(from_header="GitHub <noreply@github.com>",
                  subject="[GitHub] Please reset your password",
                  text="We heard that you lost your GitHub password. This link expires in 24 hours.",
                  html='<p>We heard that you lost your GitHub password. This link expires in 24 hours.</p>'
                       '<p><a href="https://github.com/password_reset/sample-token">Reset your password</a></p>',
                  auth=auth_header("github.com"), received=[hop("out-21.smtp.github.com", "192.0.2.21")])},

    {"file": "15_safe_canada_post_delivery.eml", "expect": "Likely safe",
     "planted": "",
     "note": "Near miss: canadapost-postescanada.ca looks made up but is Canada Post's real domain",
     "mail": dict(from_header="Canada Post <noreply@canadapost-postescanada.ca>",
                  subject="Your parcel was delivered",
                  text="Your parcel was delivered today at 14:12.",
                  html='<p>Your parcel was delivered today at 14:12.</p><p><a href='
                       '"https://www.canadapost-postescanada.ca/track-reperage/en">Track your parcel</a></p>',
                  auth=auth_header("canadapost-postescanada.ca"),
                  received=[hop("mail.canadapost-postescanada.ca", "192.0.2.33")])},

    {"file": "16_safe_it_maintenance.eml", "expect": "Likely safe",
     "planted": "urgency_many",
     "note": "Near miss: urgent wording, but from the real dal.ca with every check passing",
     "mail": dict(from_header="Dalhousie ITS <its@dal.ca>",
                  subject="Urgent: planned network outage tonight",
                  text="The campus network will be down from 23:00 to 01:00 tonight. Save your work "
                       "immediately before 23:00. You do not need to reply.",
                  auth=auth_header("dal.ca"), received=[hop("smtp.dal.ca", "192.0.2.10")])},

    {"file": "17_safe_microsoft_signin_alert.eml", "expect": "Likely safe",
     "planted": "urgency_one",
     "note": "Near miss: a real Microsoft security alert from accountprotection.microsoft.com",
     "mail": dict(from_header="Microsoft account team <account-security-noreply@accountprotection.microsoft.com>",
                  subject="Microsoft account security alert",
                  text="We detected unusual sign-in activity on your Microsoft account.",
                  html='<p>We detected unusual sign-in activity on your Microsoft account.</p>'
                       '<p><a href="https://account.live.com/Activity">Review recent activity</a></p>',
                  auth=auth_header("accountprotection.microsoft.com"),
                  received=[hop("mail.accountprotection.microsoft.com", "192.0.2.44")])},

    {"file": "18_safe_colleague_report.eml", "expect": "Likely safe",
     "planted": "",
     "note": "Near miss: has a Reply-To, but it is the same address as From",
     "mail": dict(from_header="Alex Sample <alex.sample@dal.ca>", reply_to="alex.sample@dal.ca",
                  subject="Q3 report",
                  text="Hi, the Q3 report is attached. Let me know if anything looks off.",
                  auth=auth_header("dal.ca"), received=[hop("smtp.dal.ca", "192.0.2.10")],
                  attachments=[("Q3_report.pdf", [])])},

    {"file": "19_safe_zoom_invite.eml", "expect": "Likely safe",
     "planted": "",
     "note": "Calendar invite with an .ics file, from zoom.us",
     "mail": dict(from_header="Zoom <no-reply@zoom.us>",
                  subject="Invitation: Project check-in",
                  text="You are invited to a Zoom meeting on Friday at 10:00.",
                  html='<p>You are invited to a Zoom meeting on Friday at 10:00.</p>'
                       '<p><a href="https://dal.zoom.us/j/1234567890">Join meeting</a></p>',
                  auth=auth_header("zoom.us"), received=[hop("mail.zoom.us", "192.0.2.55")],
                  attachments=[("invite.ics", [])])},

    {"file": "20_safe_amazon_shipped.eml", "expect": "Likely safe",
     "planted": "",
     "note": "Real Amazon domain in both sender and link",
     "mail": dict(from_header="Amazon.ca <shipment-tracking@amazon.ca>",
                  subject="Your package has shipped",
                  text="Your package is on the way and should arrive Monday.",
                  html='<p>Your package is on the way and should arrive Monday.</p>'
                       '<p><a href="https://www.amazon.ca/progress-tracker/package">Track package</a></p>',
                  auth=auth_header("amazon.ca"), received=[hop("a27-12.smtp-out.amazonses.com", "192.0.2.77")])},
]


def main():
    with open("samples/expected.csv", "w", newline="") as f:
        f.write("# SYNTHETIC / MOCK - the answer key for the sample emails\n")
        writer = csv.writer(f)
        writer.writerow(["file", "expected_verdict", "planted", "note"])
        for s in SAMPLES:
            msg = build_message(to=TO, **s["mail"])
            with open("samples/" + s["file"], "wb") as out:
                out.write(bytes(msg))
            writer.writerow([s["file"], s["expect"], s["planted"], s["note"]])
    print("Wrote", len(SAMPLES), "sample emails to samples/")


if __name__ == "__main__":
    main()
