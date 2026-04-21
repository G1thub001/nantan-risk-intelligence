import re

def base_domain(domain):
    if not domain:
        return None
    parts = domain.split(".")
    return ".".join(parts[-2:])  # last two parts

def extract_header_field(text, field):
    pattern = rf"{field}:\s*(.*)"
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else None

def extract_email_domain(email):
    if not email:
        return None
    match = re.search(r"@([\w\.-]+)", email)
    return match.group(1).lower() if match else None

def analyze_headers(text):
    findings = []
    risk_score = 0

    # Extract fields
    from_field = extract_header_field(text, "from")
    reply_to = extract_header_field(text, "reply-to")
    return_path = extract_header_field(text, "return-path")
    mailed_by = extract_header_field(text, "mailed-by")
    signed_by = extract_header_field(text, "signed-by")

    from_domain = extract_email_domain(from_field)
    reply_domain = extract_email_domain(reply_to)
    return_domain = extract_email_domain(return_path)

    # --- 1. Reply-To mismatch ---
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(f"Reply-To mismatch: {from_domain} vs {reply_domain}")
        risk_score += 3

    # --- 2. Return-Path mismatch ---
    if from_domain and return_domain and from_domain != return_domain:
        findings.append(f"Return-Path mismatch: {from_domain} vs {return_domain}")
        risk_score += 2

    # --- 3. Mailed-by vs Signed-by mismatch ---
    if mailed_by and signed_by:
        if base_domain(mailed_by) != base_domain(signed_by):
         findings.append(f"Mail infrastructure mismatch: mailed-by={mailed_by}, signed-by={signed_by}")
         risk_score += 2
        

    # --- 4. Suspicious sender domain ---
    suspicious_keywords = ["secure", "verify", "update", "login"]
    if from_domain and any(word in from_domain for word in suspicious_keywords):
        findings.append(f"Suspicious sender domain: {from_domain}")
        risk_score += 1

    return {
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "mailed_by": mailed_by,
        "signed_by": signed_by,
        "header_risk_score": risk_score,
        "header_findings": findings
    }

#test
if __name__ == "__main__":
    email = """
from: Google <no-reply@accounts.google.com>
to: bkibagendi20@gmail.com
date: Apr 12, 2026, 2:52 AM
subject: Security alert for durbansa43@gmail.com
mailed-by: identity-reachout.bounces.google.com
signed-by: accounts.google.com
security: Standard encryption (TLS)
"""

    print(analyze_headers(email))