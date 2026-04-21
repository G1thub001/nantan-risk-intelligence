import re

# --- QR PHISHING ---
def detect_qr_phishing(text):
    findings = []
    risk_score = 0

    qr_keywords = ["scan", "qr code", "scan code", "barcode"]

    if any(word in text.lower() for word in qr_keywords):
        findings.append("QR code or scan instruction detected")
        risk_score += 2

    if "data:image" in text.lower():
        findings.append("Embedded image detected (possible hidden QR)")
        risk_score += 3

    return {
        "qr_risk_score": risk_score,
        "qr_findings": findings
    }

# --- ATTACHMENT ANALYSIS ---
def detect_attachment_risk(text):
    findings = []
    risk_score = 0

    text_lower = text.lower()

    # Suspicious executable / macro-enabled attachment types
    suspicious_ext = [
        ".exe", ".zip", ".rar", ".scr", ".bat",
        ".js", ".docm", ".xlsm"
    ]

    for ext in suspicious_ext:
        # Match actual filename-like patterns, not just any text containing ".ext"
        if re.search(rf"\b[\w\-]+{re.escape(ext)}\b", text_lower):
            findings.append(f"Suspicious attachment type detected: {ext}")
            risk_score += 3

    # Double-extension disguise detection, e.g. invoice.pdf.exe
    double_ext_pattern = (
        r"\b[\w\-]+\."
        r"(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt)"
        r"\."
        r"(exe|js|scr|bat|zip|rar)\b"
    )

    if re.search(double_ext_pattern, text_lower):
        findings.append("Double file extension detected (possible disguise)")
        risk_score += 2

    return {
        "attachment_risk_score": risk_score,
        "attachment_findings": findings
    }

# --- PRESSURE / SENTIMENT ---
def detect_pressure_language(text):
    findings = []
    risk_score = 0

    urgency_words = [
        "urgent", "immediately", "act now", "limited time",
        "expires", "verify now"
    ]

    fear_words = [
        "account locked", "suspended", "unauthorized",
        "security alert"
    ]

    authority_words = [
        "ceo", "admin", "support team", "bank", "security team"
    ]

    text_lower = text.lower()

    if any(word in text_lower for word in urgency_words):
        findings.append("Urgency language detected")
        risk_score += 1

    if any(word in text_lower for word in fear_words):
        findings.append("Fear-based language detected")
        risk_score += 1

    if any(word in text_lower for word in authority_words):
        findings.append("Authority impersonation language detected")
        risk_score += 1

    return {
        "pressure_risk_score": risk_score,
        "pressure_findings": findings
    }