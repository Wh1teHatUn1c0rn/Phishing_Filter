import email
import re


def is_phishing(email_message):
    # Check for suspicious sender
    if not email_message.get("From").endswith("example.com"):
        return True

    # Check for suspicious links
    for part in email_message.walk():
        if part.get_content_type() == "text/plain":
            body = part.get_payload()
            links = re.findall(r"https?://[^\s]+", body)
            for link in links:
                if not link.startswith("https://example.com"):
                    return True

    # No signs of phishing found
    return False


with open("email.eml", "r") as f:
    email_message = email.message_from_file(f)
    if is_phishing(email_message):
        print("Phishing email detected.")
    else:
        print("No phishing detected.")