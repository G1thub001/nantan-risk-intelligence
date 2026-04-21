# 📧 Multi-Layer Phishing Detection System
An email threat analysis system based on a FastAPI backend and Streamlit UI, powered by production-like.  
The project deploys a multi-layer fusion engine that integrates machine learning and technical security indicators to identify phishing emails with greater accuracy and fewer false positives.
---
##  Overview
Old school phishing detection systems are very content-based machine learning models.  
Nevertheless, the contemporary phishing attacks tend to evade such systems by:
- Using legitimate-looking domains
- Inoculating malicious intent in the header or links.
- Impersonating actual marketing or service emails.
With this system, the problem is solved with a 6-layer detection engine:
1. Content Classification (ML Model).
2. URL Intelligence (homograph detection + risk scoring)
3. Header Analysis (spoofing detection)
4. QR Code Phishing Detection.
5. Attachment Risk Analysis
6. Sentiment / Pressure Language Detection
---
##  The Fusion Advantage
This project relies on a fusion-based decision engine rather than traditional ML-only systems.
### Example (Real-World Case)
An authentic marketing email of Raenest:
- ML Model → 🚫 BLOCK (0.94 probability)
- No URL risk
- No header anomalies
- Marketing/newsletter patterns detected
###  Final System Decision:
- ⚠️ WARN (LOW severity)
- Explanation:
  Content analysis has a very high likelihood of phishing, yet the message is an authentic marketing or newsletter template with low technical risk.
This avoids the false positives, which are a significant problem in real-world systems.
##  System Architecture
```text
User Input (Email)
        ↓
Streamlit UI (Frontend)
        ↓
FastAPI Backend (API Layer)
        ↓
Multi-Layer Detection Engine (Prediict.py)
        ↓
Final Decision + Explanation
        ↓
UI Display + PDF Forensic Report.

##  Project Context

The proposed project is part of the current study in AI Governance and Cybersecurity and focuses on an intelligent threat detection system for modern digital infrastructure and smart cities.

It demonstrates how layered AI systems can improve accuracy, reduce false positives, and provide explainable security decisions.



## 📊 Performance Impact

This multi-layer fusion scheme is better than traditional ML-only phishing detection systems in several significant aspects:

### 1. Reduced False Positives
Classical content-based classifiers tend to over-flag:
- newsletters
- marketing emails
- account notifications
- transactional service emails

To eliminate false positives, this system integrates ML output with:
- URL risk analysis
- header anomaly checks
- attachment inspection
- marketing/newsletter pattern detection
- trusted-domain softening logic

### 2. Higher Precision
Accuracy is enhanced since the system is not based on content probability only.  
Only when technical risk indicators reinforce suspicious content is an email more likely to be blocked.

### 3. Strong Recall Retention
Recall is good since the system continues to be aggressive in detecting:
- homograph and punycode domain names
- spoofed headers
- risky attachments
- QR phishing signals
- pressure-based phishing language

This will allow the phishing detection to be maintained, as well as unwarranted blocking to be minimised.

### 4. Improved F1 Score
Since accuracy gets better as Recall is high, the total F1 score will likely be better than when using an independent ML classifier.

### 5. Better Explainability
The system provides the explanation of the final decision in the form of layers of reasoning, like: instead of simply giving back a raw phishing probability.
- suspicious URL patterns
- header anomalies
- attachment risk
- marketing/newsletter classification
- trusted-domain behavior

This is more applicable to practical Security Operations Center (SOC) operations.

### 6. Confidence Awareness
Another benefit of the system is the confidence level, according to the content that can be analysed in the email.  
This assists users in determining the extent of reliability of the verdict, particularly when the email is extremely brief or when it does not include any indicators of utility.

An example of a real-world false positive reduction.
In a real marketing mail by Raenest:
- A very high phishing probability was obtained with the ML layer alone.
- A classic ML-only system would block the email.
- This combination engine reduced the sentence to a warning due to:
  - No technical abnormalities.
  - The layout corresponded to a valid newsletter/marketing pattern.
  - There were footer and unsubscribe indicators.

This shows that the fusion method decreases the number of false positives without compromising security.

## ⚠️ Limitations (Advanced / Industrial-Scale)

Infrastructure, data access or system integration is out of scope of this project, but will be required as follows:

### 1. Threat Intelligence Incorporation.
The system excludes the integration with live threat intelligence systems, such as:
- VirusTotal
- Google Safe Browsing
- enterprise SIEM systems

Such services demand API control, rate limiting and, frequently, paid access levels.  
In their absence, they can only detect locally present signals as opposed to globally present, real-time threat information.

---

### 2. Ongoing learning and retraining of models.
The model is not dynamic, and it does not automatically update itself with the occurrence of new phishing patterns.

To achieve a production system, it would demand:
- automated pipelines to collect data.  
- periodic retraining workflows  
- monitoring and versioning of models.  

This will likely have MLOps infrastructure and big data.

---

### 3. Complete Email Rendering and Visual Deception Detection.
The system does not interpret HTML emails or examine visual tricks of deception, like:
- hidden elements
- CSS-based obfuscation
- incompatible anchor text and rendered views displayed links.

A browser engine or sandboxed rendering environment would be necessary to detect accurately.

---

### 4. Contextual and User Behavior Modeling.
The system is email-only and fails to include:
- prior sender-recipient relationships  
- user communication patterns  
- historical behavior anomaly detection.  

This would need long-term user data and behavioral modeling systems to implement.

---

### 5. Integration of an email system in real time.
This project is not directly incorporated into:
- Gmail / Outlook inboxes  
- enterprise email gateways  
- live mail transfer agents (MTAs)

To implement in real-time, it would need:
- authentication (OAuth, API keys)  
- secure message handling  
- event-driven architecture  

---

### 6. Cloud Deployment and Monitoring that can be scaled.
The system is not in a scalable environment and is not deployed locally.

To deploy production, the following would be needed:
- cloud infrastructure (AWS, Azure, GCP)  
- containerisation (Docker/Kubernetes)  
- logging, monitoring and alerting systems.  

---
## 🤝 Contributing

Contributions are welcome! Feel free to fork the repository, open issues, or submit pull requests to improve the system.
