
import re
import ipaddress
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


def analyze_email(email_bytes):

    # Read uploaded email
    email_message = BytesParser(policy=policy.default).parsebytes(email_bytes)

    sender = email_message.get("From", "Unknown")
    receiver = email_message.get("To", "Unknown")
    subject = email_message.get("Subject", "No subject")

    # Reply-To analysis
    reply_to = email_message.get("Reply-To", "")
    reply_warnings = []

    if reply_to and reply_to.lower() != sender.lower():
          
        reply_warnings.append("Reply-To address differs from sender address.")
    # Email Authentication Analysis
    authentication_results = email_message.get_all(
        "Authentication-Results", []
    )

    auth_checks = []

    if authentication_results:
       for result in authentication_results:
           auth_checks.append(str(result))
    else:
       auth_checks.append("No Authentication-Results header found.")    
    # Extract email body
    body_part = email_message.get_body(preferencelist=("plain",))

    if body_part:
        body = body_part.get_content()
    else:
        body = ""

    # Suspicious keywords
    suspicious_keywords = [
        "urgent",
        "verify your account",
        "suspended",
        "password",
        "click here",
        "confirm your identity",
        "won a prize",
        "account blocked",
        "immediately"
    ]

    email_text = body.lower()

    detected_keywords = [
        keyword for keyword in suspicious_keywords
        if keyword in email_text
    ]

    # Extract URLs
    url_pattern = r'https?://[^\s<>"]+'
    urls = re.findall(url_pattern, body)

    # URL threat analysis
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd"
    ]

    url_warnings = []
    risk_score = len(detected_keywords) * 5

    for url in urls:

        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if not domain:
            continue

        try:
            ipaddress.ip_address(domain)
            url_warnings.append("URL uses an IP address")
            risk_score += 20
        except ValueError:
            pass

        if domain.lower() in shorteners:
            url_warnings.append("Shortened URL detected")
            risk_score += 15

        if "@" in url:
            url_warnings.append("URL contains @ symbol")
            risk_score += 15

        if len(url) > 100:
            url_warnings.append("Unusually long URL")
            risk_score += 10

    # Sender and link domain comparison
    sender_match = []

    sender_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', sender)

    sender_domain = (
        sender_domain_match.group(1).lower()
        if sender_domain_match else ""
    )

    for url in urls:
        domain = urlparse(url).hostname

        if domain and sender_domain and domain.lower() != sender_domain:
            sender_match.append(
                f"Sender domain {sender_domain} differs from link domain {domain}"
            )

    # Final verdict
    if risk_score >= 60:
        verdict = "HIGH RISK"
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    # Return results to Flask
    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "body": body,
        "keywords": detected_keywords,
        "urls": urls,
        "url_warnings": url_warnings,
        "sender_warnings": sender_match,
        "reply_warnings": reply_warnings,
        "auth_checks": auth_checks,
        "risk_score": risk_score,
        "verdict": verdict
    }
