## 📧 Mini Project #2: Email Security and Phishing Investigation

**Focus:** Email threat detection and investigation.  
**Tools:** Defender for Office 365, Threat Explorer, KQL.  
**Duration:** Days 10–16.

---

## 🎯 Objective

Configure email security controls, simulate a phishing attack, and perform a SOC-style investigation from detection through containment.

This project focuses on validating email security controls and documenting a realistic phishing investigation workflow.

---

## 🛠️ Work Performed

### Email Security Configuration
- Implemented Safe Links for time-of-click URL protection.
- Configured Anti-Phishing policies for impersonation detection.
- Enforced quarantine policies for high-confidence phishing messages.

### Phishing Simulation
- Delivered a credential harvesting email to a test mailbox.
- Delivered a credential harvesting email to a test mailbox.
- Investigated the message using Threat Explorer.
- Analyzed email headers and embedded URLs.
- Validated Safe Links blocked access to the phishing page.
- Documented findings in a formal investigation report.

---

### 📋 Investigation Summary
A phishing email impersonating an internal security notification was delivered to a test mailbox. Header analysis identified authentication failures and a newly registered sender domain.
Safe Links blocked access to the credential harvesting page at time of click. The message was automatically quarantined, and no user credentials were compromised.
A complete SOC-style investigation report is available in investigation-report.md.

---

## 📊 Results

| Metric             | Outcome                                |
| ------------------ | -------------------------------------- |
| Incident Reports   | 1 phishing investigation completed.    |
| Policies Validated | Safe Links, Anti-Phishing, Quarantine. |
| Threats Blocked    | 1 credential harvesting attempt.       |
| User Impact        | None.                                  |

---
## 🧠 What I Learnt

- Safe Links enforcement occurs at time of click, not delivery.
- SPF, DKIM, and DMARC failures are strong phishing indicators.
- Threat Explorer data may take 15–30 minutes time to populate.
- Clear documentation improves investigation handoff.

---
## 🚧 Improvements Identified

- Add detections for newly registered domains.
- Automate URL and domain enrichment.
- Validate user-reported phishing workflows.
- Develop a standardized phishing response playbook.

---

## 📂 Project Structure
```text
02-email-security/
├── README.md
├── investigation-report.md
├── kql/
│   └── email-threat-queries.kql
├── artifacts/
│   ├── email-headers.txt
│   └── iocs.txt
└── screenshots/




