# 🛡️ Nantan Risk Intelligence Engine

## Multi-Layer Phishing Detection & Email Threat Analysis

Nantan is a multi-layer email threat analysis system that combines machine learning with technical security indicators to identify phishing emails and produce explainable risk decisions.

The system is designed around a fusion-based detection architecture rather than relying exclusively on a traditional content-classification model.

It combines:

- Machine-learning content classification
- URL intelligence and risk analysis
- Homograph and Punycode detection
- Email-header analysis
- QR-code phishing detection
- Attachment risk analysis
- Sentiment and pressure-language detection
- Trusted-domain and newsletter-context analysis
- Explainable final risk decisions

The system exposes a FastAPI backend and Streamlit interface for submitting and analyzing email content.

---

# 🎯 Problem

Traditional phishing detection systems often rely heavily on the textual content of an email.

Modern phishing attacks can evade content-only approaches by:

- Using legitimate-looking domains
- Embedding malicious intent in URLs or headers
- Impersonating legitimate services
- Using QR codes to redirect users
- Using malicious attachments
- Mimicking legitimate marketing or transactional messages
- Applying pressure-based language to influence users

Nantan addresses this problem by combining multiple independent security signals before producing a final decision.

---

# 🧠 Detection Architecture

Nantan uses a six-layer detection engine.

```text
                 Email Input
                     │
                     ▼
        ┌──────────────────────────┐
        │ Content Classification   │
        │ Machine Learning Model   │
        └────────────┬─────────────┘
                     │
        ┌────────────┴─────────────┐
        │                          │
        ▼                          ▼
 URL Intelligence             Header Analysis
        │                          │
        ├─ Domain Risk             ├─ Spoofing
        ├─ Homographs              └─ Anomalies
        └─ Punycode
        │
        ├──────────────────────────────┐
        │                              │
        ▼                              ▼
 QR Code Analysis              Attachment Analysis
        │                              │
        └──────────────┬───────────────┘
                       │
                       ▼
             Pressure Language
                Detection
                       │
                       ▼
             Context / Fusion
                 Decision
                       │
                       ▼
            Risk + Severity +
              Explanation
                       │
                       ▼
              Streamlit UI
                 / Report
