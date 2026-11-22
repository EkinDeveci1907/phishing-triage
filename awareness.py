# awareness.py
#
# Turns a result into the short paragraph a security-awareness analyst would
# send back to the employee who reported the email: what gave it away, what
# to do, and what not to do. Plain words, no jargon, no blame.

def top_reasons(result, count=3):
    return [f["reason"] for f in result["findings"][:count]]


def employee_message(result):
    verdict = result["verdict"]
    score = str(result["score"]) + "/100"
    reasons = top_reasons(result)

    if verdict == "Phishing":
        return ("This email is very likely phishing (score " + score + "). What gave it away: "
                + " ".join(reasons) + " What to do: report it with the Report Phishing button, or "
                "forward it to the IT security team, then delete it. Do not click the links, open "
                "attachments, reply, or type your password anywhere it sends you. If you already "
                "clicked or entered your password, change your password on the real website and "
                "tell IT right away. You won't get in trouble for reporting it.")

    if verdict == "Suspicious":
        return ("Some things about this email are not right (score " + score + "). What to check: "
                + " ".join(reasons) + " Before you do what it asks, contact the sender another way, "
                "using a phone number or address you already know, not one from this email. Don't "
                "click links, open attachments, or send money or gift cards until you have checked. "
                "If you can't confirm it, report it.")

    message = "No strong warning signs in this email (score " + score + ")."
    if reasons:
        message += " One small thing to notice: " + reasons[0]
    message += (" It's fine to act on it if you were expecting it. If it ever asks for your "
                "password, payment, or something unusual, check with the sender first, and report "
                "it if you're unsure.")
    return message
