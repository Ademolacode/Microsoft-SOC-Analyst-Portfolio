## 🔗 Mini Project #4: Cross-Domain Incident Investigation (Final)

**Focus Area:** End-to-end SOC investigation and correlation  
**Tools Used:** Microsoft Sentinel, Defender XDR, Entra ID, KQL

---

## 🎯 Objective

Simulate and investigate a multi-stage attack spanning email, identity, and endpoint activity, then produce a full SOC-style incident report.

This project serves as the capstone of the portfolio.

---

## 🧠 What I Learned

- Isolated alerts provide limited context without correlation
- Identity telemetry often bridges email and endpoint activity
- Conditional Access in report-only mode introduces real risk
- Timeline reconstruction is critical for decision-making

---

## 🛠️ Key Tasks Performed

- Simulated phishing, risky sign-in, and endpoint execution
- Correlated telemetry across email, identity, and endpoint data
- Built unified KQL queries for timeline reconstruction
- Mapped activity to the MITRE ATT&CK framework
- Documented full incident response and recommendations

---

## 📊 Concrete Outcomes

- Produced **1 full cross-domain incident report**
- Correlated **email → identity → endpoint telemetry**
- Mapped **multiple MITRE ATT&CK techniques**
- Documented containment and prevention actions

---

## 🔍 Investigation Summary

A simulated attack chain beginning with phishing progressed through identity compromise and endpoint execution.  
The incident was fully reconstructed, contained, and documented with actionable recommendations.

---

## 📸 Evidence & Screenshots

Included screenshots:
- Sentinel incident graph
- Cross-domain KQL correlation
- Identity sign-in logs
- Endpoint alert linkage

Screenshots are stored in the `screenshots/` folder.

---

## 📂 Project Structure

```text
04-cross-domain-investigation/
├── README.md
├── final-incident-report.md
├── correlation-queries/
└── screenshots/
  ```

##🚧 What I Would Improve Next

Automate response actions using Sentinel playbooks

Add threat intelligence enrichment

Expand correlation rules for similar attack patterns
