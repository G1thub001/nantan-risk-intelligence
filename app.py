import io
import uuid
from datetime import datetime

import requests
import streamlit as st
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

API_URL = "http://127.0.0.1:8000/analyze"

st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="📧",
    layout="wide"
)

# ---------- Styling ----------
st.markdown("""
<style>
    .main {
        padding-top: 1.2rem;
    }
    .hero {
        padding: 1.2rem 1.4rem;
        border-radius: 16px;
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        color: white;
        margin-bottom: 1.2rem;
    }
    .hero h1 {
        margin: 0;
        font-size: 2.1rem;
    }
    .hero p {
        margin-top: 0.45rem;
        margin-bottom: 0;
        color: #cbd5e1;
        font-size: 1rem;
    }
    .verdict-box {
        padding: 1rem 1.2rem;
        border-radius: 16px;
        margin-bottom: 1rem;
        border: 1px solid rgba(255,255,255,0.08);
    }
    .verdict-block {
        background: rgba(127, 29, 29, 0.10);
        border-left: 6px solid #dc2626;
    }
    .verdict-warn {
        background: rgba(120, 53, 15, 0.10);
        border-left: 6px solid #f59e0b;
    }
    .verdict-allow {
        background: rgba(20, 83, 45, 0.10);
        border-left: 6px solid #16a34a;
    }
    .verdict-title {
        font-size: 1.25rem;
        font-weight: 700;
        margin-bottom: 0.3rem;
    }
    .verdict-sub {
        font-size: 0.98rem;
        margin-bottom: 0.2rem;
    }
    .footer-note {
        margin-top: 1rem;
        color: #64748b;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Helpers ----------
def verdict_style(action: str):
    if "BLOCK" in action:
        return "verdict-block", "🔴 BLOCK"
    if "WARN" in action:
        return "verdict-warn", "🟠 WARN"
    return "verdict-allow", "🟢 ALLOW"

def safe_findings(result: dict, key: str):
    return result.get(key, []) or []

def render_expander(title: str, score_key: str, findings_key: str, result: dict, empty_text: str):
    with st.expander(title, expanded=False):
        st.write(f"**Risk Score:** {result.get(score_key, 0)}")
        findings = safe_findings(result, findings_key)
        if findings:
            for finding in findings:
                st.write(f"- {finding}")
        else:
            st.write(empty_text)

def wrap_text(text: str, width: int = 95):
    words = text.split()
    lines = []
    current = ""

    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word

    if current:
        lines.append(current)

    return lines

def add_pdf_section(c, title, lines, y):
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, title)
    y -= 18
    c.setFont("Helvetica", 10)

    if not lines:
        c.drawString(60, y, "None")
        y -= 16
        return y

    for line in lines:
        wrapped = wrap_text(str(line), 95)
        for w in wrapped:
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica", 10)
            c.drawString(60, y, f"- {w}")
            y -= 14

    y -= 6
    return y

def build_pdf_report(result: dict, email_text: str) -> bytes:
    case_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    y = 760

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Email Threat Analysis Report")
    y -= 28

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Case ID: {case_id}")
    y -= 15
    c.drawString(50, y, f"Generated: {timestamp}")
    y -= 20

    c.drawString(50, y, f"Final Action: {result['final_action']}")
    y -= 15
    c.drawString(50, y, f"Severity: {result['severity'].upper()}")
    y -= 15
    c.drawString(50, y, f"Reason: {result['reason']}")
    y -= 24

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Top Metrics")
    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(60, y, f"ML Probability: {result['ml_probability']}")
    y -= 14
    c.drawString(60, y, f"URL Risk Score: {result['url_risk_score']}")
    y -= 14
    c.drawString(60, y, f"Header Risk Score: {result['header_risk_score']}")
    y -= 14
    c.drawString(60, y, f"QR Risk Score: {result['qr_risk_score']}")
    y -= 14
    c.drawString(60, y, f"Attachment Risk Score: {result['attachment_risk_score']}")
    y -= 14
    c.drawString(60, y, f"Pressure Risk Score: {result['pressure_risk_score']}")
    y -= 24

    y = add_pdf_section(c, "URL Findings", safe_findings(result, "url_findings"), y)
    y = add_pdf_section(c, "Header Findings", safe_findings(result, "header_findings"), y)
    y = add_pdf_section(c, "QR Findings", safe_findings(result, "qr_findings"), y)
    y = add_pdf_section(c, "Attachment Findings", safe_findings(result, "attachment_findings"), y)
    y = add_pdf_section(c, "Pressure Findings", safe_findings(result, "pressure_findings"), y)

    if y < 140:
        c.showPage()
        y = 750

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Analyzed Email Snapshot")
    y -= 18
    c.setFont("Helvetica", 9)

    for line in wrap_text(email_text[:2500], 105):
        if y < 60:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 9)
        c.drawString(50, y, line)
        y -= 12

    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

# ---------- Header ----------
st.markdown("""
<div class="hero">
    <h1>📧 Multi-Layer Phishing Detection System</h1>
    <p>
        Professional email threat analysis powered by a FastAPI backend with layered detection:
        content classification, URL intelligence, header analysis, QR phishing checks,
        attachment risk analysis, and pressure-language detection.
    </p>
</div>
""", unsafe_allow_html=True)

with st.expander("Paste Email Content", expanded=True):
    user_input = st.text_area(
        "",
        height=180,
        placeholder="Paste the full email body, suspicious message, or header-rich content here...",
        label_visibility="collapsed"
    )

analyze_clicked = st.button("Analyze Email", use_container_width=True)

if analyze_clicked:
    if not user_input.strip():
        st.warning("Please paste some email content first.")
    else:
        try:
            with st.spinner("Analyzing email across all detection layers..."):
                response = requests.post(
                    API_URL,
                    json={"content": user_input},
                    timeout=30
                )
                response.raise_for_status()
                result = response.json()

            verdict_class, verdict_label = verdict_style(result["final_action"])

            st.markdown(
                f"""
                <div class="verdict-box {verdict_class}">
                    <div class="verdict-title">{verdict_label}</div>
                    <div class="verdict-sub"><strong>Severity:</strong> {result['severity'].upper()}</div>
                    <div class="verdict-sub"><strong>Reason:</strong> {result['reason']}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.caption(f"Confidence Level: **{result['confidence']}**")

            m1, m2, m3, m4, m5 = st.columns(5)

            m1.metric("ML Probability", result["ml_probability"])
            m2.metric("URL Risk", result["url_risk_score"])
            m3.metric("Header Risk", result["header_risk_score"])
            m4.metric("Attachment Risk", result["attachment_risk_score"])
            m5.metric("Confidence", result["confidence"])

            

            pdf_bytes = build_pdf_report(result, user_input)
            st.download_button(
                label="Download Forensic Report (PDF)",
                data=pdf_bytes,
                file_name="email_threat_analysis_report.pdf",
                mime="application/pdf",
                use_container_width=True
            )

            st.markdown("### Detection Breakdown")
            col1, col2 = st.columns(2)

            with col1:
                with st.expander("Content Model", expanded=True):
                    st.write(f"**ML Probability:** {result['ml_probability']}")
                    st.write(f"**Model Action:** {result['ml_action']}")

                render_expander(
                    "URL Analysis",
                    "url_risk_score",
                    "url_findings",
                    result,
                    "No suspicious URL findings."
                )

                render_expander(
                    "Header Analysis",
                    "header_risk_score",
                    "header_findings",
                    result,
                    "No suspicious header findings."
                )

            with col2:
                render_expander(
                    "QR Analysis",
                    "qr_risk_score",
                    "qr_findings",
                    result,
                    "No suspicious QR findings."
                )

                render_expander(
                    "Attachment Analysis",
                    "attachment_risk_score",
                    "attachment_findings",
                    result,
                    "No suspicious attachment findings."
                )

                render_expander(
                    "Pressure / Sentiment Analysis",
                    "pressure_risk_score",
                    "pressure_findings",
                    result,
                    "No pressure-based findings."
                )

            st.markdown(
                '<div class="footer-note">Tip: paste full email text including links and headers for the most accurate analysis.</div>',
                unsafe_allow_html=True
            )

        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the API. Make sure FastAPI is running on http://127.0.0.1:8000")
        except requests.exceptions.Timeout:
            st.error("The API request timed out.")
        except requests.exceptions.HTTPError as e:
            st.error(f"API returned an error: {e}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")