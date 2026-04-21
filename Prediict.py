
import joblib
import re
import os

from analyze_url import analyze_urls, extract_urls, get_domain
from header_analyzer import analyze_headers
from advanced_features import (
    detect_qr_phishing,
    detect_attachment_risk,
    detect_pressure_language
)

# Load saved assets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(os.path.join(BASE_DIR, "models", "phishing_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE_DIR, "models", "tfidf_vectorizer.pkl"))

# Trusted domains
TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "myaccount.google.com",
    "microsoft.com",
    "outlook.com"
}


def is_trusted_domain(domain):
    if not domain:
        return False
    return any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS)

def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", "", text)
    text = re.sub(r"\b(subject|hello|hi|dear)\b", "", text)
    text = re.sub(r"[^a-zA-Z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def classify_email(text):
    cleaned = clean_text(text)
    vec = vectorizer.transform([cleaned])
    prob = model.predict_proba(vec)[0][1]

    if prob > 0.90:
        action = "BLOCK 🚫"
    elif prob >= 0.50:
        action = "WARN ⚠️"
    else:
        action = "ALLOW ✅"

    return {
        "probability": float(round(prob, 3)),
        "action": action
    }

def assess_confidence(text: str) -> str:
    word_count = len(text.split())

    if word_count < 20:
        return "LOW"
    elif word_count < 80:
        return "MEDIUM"
    return "HIGH"



#detect marketing emails

def detect_marketing_email(text: str) -> bool:
    text_lower = text.lower()

    marketing_signals = [
        "unsubscribe",
        "privacy policy",
        "terms of service",
        "twitter",
        "instagram",
        "linkedin",
        "youtube",
        "blog",
        "support",
        "cashback",
        "offer",
        "promo",
        "promotion",
        "newsletter",
        "wallet",
        "countries",
        "currencies"
    ]

    matches = sum(1 for signal in marketing_signals if signal in text_lower)

    has_footer = (
        "unsubscribe" in text_lower
        or "privacy" in text_lower
        or "terms" in text_lower
    )

    return matches >= 2 and has_footer

def probability_phrase(prob: float) -> str:
    if prob >= 0.90:
        return "very high phishing probability from content analysis"
    elif prob >= 0.75:
        return "high phishing probability from content analysis"
    elif prob >= 0.65:
        return "moderate phishing probability from content analysis"
    elif prob >= 0.50:
        return "elevated phishing probability from content analysis"
    return "low phishing probability from content analysis"

#finak decision

def final_decision(text):
    ml_result = classify_email(text)
    url_result = analyze_urls(text)
    header_result = analyze_headers(text)

    qr_result = detect_qr_phishing(text)
    attachment_result = detect_attachment_risk(text)
    pressure_result = detect_pressure_language(text)

    prob = ml_result["probability"]
    url_score = url_result["url_risk_score"]
    header_score = header_result["header_risk_score"]
    qr_score = qr_result["qr_risk_score"]
    attachment_score = attachment_result["attachment_risk_score"]
    pressure_score = pressure_result["pressure_risk_score"]
    confidence = assess_confidence(text)
    is_marketing = detect_marketing_email(text)
    probability_text = probability_phrase(prob)

    print("is_marketing:", is_marketing)

    reason_parts = []
    severity = ""

    # Base fusion logic
    if url_score >= 5:
        final_action = "BLOCK 🚫"
        severity = "critical"
        reason_parts.append("high-confidence URL risk indicators detected")

    elif header_score >= 4:
        final_action = "BLOCK 🚫"
        severity = "critical"
        reason_parts.append("high-risk email header anomalies detected")

    elif attachment_score >= 2 and prob >= 0.60:
        final_action = "BLOCK 🚫"
        severity = "high"
        reason_parts.append("suspicious attachment combined with risky content")

    elif prob >= 0.95:
        final_action = "BLOCK 🚫"
        severity = "high"
        reason_parts.append(probability_text)

    elif prob >= 0.75 and (url_score >= 2 or header_score >= 2 or attachment_score >= 3):
        final_action = "BLOCK 🚫"
        severity = "critical"
        reason_parts.append("high content risk combined with strong technical indicators")

    elif prob >= 0.60 and (url_score >= 3 or header_score >= 2 or attachment_score >= 3):
        final_action = "BLOCK 🚫"
        severity = "high"
        reason_parts.append("content and technical signals indicate elevated phishing risk")

    elif prob >= 0.65:
        final_action = "WARN ⚠️"
        severity = "medium"
        reason_parts.append(probability_text)

    elif url_score >= 2:
        final_action = "WARN ⚠️"
        severity = "medium"
        reason_parts.append("suspicious URL patterns detected")

    elif header_score >= 2:
        final_action = "WARN ⚠️"
        severity = "medium"
        reason_parts.append("suspicious email header patterns detected")

    elif attachment_score >= 3:
        final_action = "WARN ⚠️"
        severity = "medium"
        reason_parts.append("suspicious attachment indicators detected")

    elif qr_score >= 2 and pressure_score >= 1:
        final_action = "WARN ⚠️"
        severity = "medium"
        reason_parts.append("QR-based phishing indicators combined with pressure language detected")

    elif pressure_score >= 2:
        final_action = "WARN ⚠️"
        severity = "low"
        reason_parts.append("pressure or urgency language detected")

    elif prob >= 0.30 and (url_score >= 1 or qr_score >= 1 or pressure_score >= 1):
        final_action = "WARN ⚠️"
        severity = "low"
        reason_parts.append("low-to-moderate content risk with supporting suspicious indicators")

    else:
        final_action = "ALLOW ✅"
        severity = "low"
        reason_parts.append("no strong phishing indicators detected")

    # Whitelist mitigation
    WHITELIST = {"internal-company.com", "trusted-partner.org"}

    def is_whitelisted_domain(url):
        domain = get_domain(url)
        return domain in WHITELIST

    urls = extract_urls(text)
    whitelisted = any(is_whitelisted_domain(url) for url in urls)
    trusted = any(is_trusted_domain(get_domain(url)) for url in urls)

    if whitelisted:
        if final_action == "BLOCK 🚫" and prob < 0.95 and url_score < 5:
            final_action = "WARN ⚠️"
            severity = "medium"
            reason_parts.append("domain is whitelisted, so the action was softened for review")
        elif final_action == "WARN ⚠️" and prob < 0.50 and url_score < 2:
            final_action = "ALLOW ✅"
            severity = "low"
            reason_parts.append("low overall risk detected and domain is whitelisted")

    # Trusted domain handling
    if trusted:
        # Trusted sender + attachment with no technical anomalies
        if attachment_score >= 2 and prob < 0.60 and header_score == 0 and url_score == 0:
            final_action = "ALLOW ✅"
            severity = "low"
            reason_parts.append("trusted sender with attachment and no technical anomalies")

        # Header anomalies always override trust
        if header_score >= 2:
            final_action = "BLOCK 🚫"
            severity = "high"
            reason_parts = ["trusted domain detected, but header anomalies indicate possible spoofing"]

        elif final_action == "BLOCK 🚫":
            if url_score >= 4 and prob >= 0.90:
                final_action = "BLOCK 🚫"
                severity = "high"
                reason_parts = ["trusted domain detected, but strong combined content and URL risk remains"]
            else:
                final_action = "WARN ⚠️"
                severity = "medium"
                reason_parts.append("trusted domain detected, so blocking was softened to warning pending review")

        elif final_action == "WARN ⚠️":
            if prob < 0.40 and url_score == 0 and header_score == 0:
                final_action = "ALLOW ✅"
                severity = "low"
                reason_parts.append("trusted domain detected and no meaningful technical risk found")

    # Marketing softening
    
    
    if is_marketing:
        if final_action == "BLOCK 🚫" and header_score == 0 and url_score <= 1 and attachment_score == 0:
            final_action = "WARN ⚠️"
            severity = "medium"
            reason_parts = [
                f"{probability_text}, but the message matches a marketing-style pattern with limited technical risk indicators"
            ]

        elif final_action == "WARN ⚠️" and header_score == 0 and url_score == 0 and attachment_score == 0:
            final_action = "WARN ⚠️"
            severity = "low"
            reason_parts = [
                f"{probability_text}, but the message matches a legitimate marketing or newsletter pattern with low technical risk"
            ]

    # Build final reason
    if not reason_parts:
        reason = "No strong phishing indicators detected."
    else:
        reason = "; ".join(dict.fromkeys(reason_parts)).capitalize() + "."

    return {
        "ml_probability": prob,
        "ml_action": ml_result["action"],
        "url_risk_score": url_score,
        "url_findings": url_result["url_findings"],
        "header_risk_score": header_score,
        "header_findings": header_result["header_findings"],
        "final_action": final_action,
        "severity": severity,
        "reason": reason,
        "qr_risk_score": qr_score,
        "qr_findings": qr_result["qr_findings"],
        "attachment_risk_score": attachment_score,
        "attachment_findings": attachment_result["attachment_findings"],
        "pressure_risk_score": pressure_score,
        "pressure_findings": pressure_result["pressure_findings"],
        "confidence": confidence,
    }

# test
if __name__ == "__main__":
    test_emails = [
        "Your account has been locked. Click here immediately to verify.",
        "Meeting scheduled for tomorrow at 10am.",
        "Urgent: update your payment details now at https://bit.ly/secure-account-login",
        "Please review the policy update at https://company.com/hr/benefits",
        "Reset now: http://verify-login-security.top/reset",
        "Please use the internal portal: https://internal-company.com/login",
        "Please use the internal portal immediately to verify your payroll details: https://internal-company.com/login",
        "Please use the partner site: https://trusted-partner.org/reset",
        "Please verify your account here: https://internal-company-secure.top/login",
        "URGENT: Your account will be suspended. Open invoice.pdf.exe immediately",
        """Google
A new sign-in on Windows

durbansa43@gmail.com
We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don’t need to do anything. If not, we’ll help you secure your account.

Check activity https://accounts.google.com/v3/signin/identifier?Email=durbansa43%40gmail.com
You can also see security activity at
https://myaccount.google.com/notifications
""",
        """From: Google <no-reply@accounts.google.com>
Reply-To: attacker@evil.com
Subject: Security alert

Verify your account now:
https://accounts.google.com
""",
        "Scan the QR code below immediately to verify your payroll account",
        "Please review the attached document invoice.docm and confirm today",
        "Security team notice: act now to avoid account suspension. Scan the QR code and open file update.xlsm",
        "Please open invoice.pdf.exe immediately",
    ]

    test_cases = [
        "Please open invoice.pdf.exe immediately",
        "Please review document.docm and confirm today",
        "Security update available at https://accounts.google.com/signin",
        "You can also see security activity at https://myaccount.google.com/notifications"
    ]

    for email in test_emails:
        print(f"\nEmail:\n{email}")
        print(final_decision(email))

    for case in test_cases:
        print(case)
        print(detect_attachment_risk(case))
        print("-" * 40)