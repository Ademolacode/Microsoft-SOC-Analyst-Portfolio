## 📧 Mini Project #2: Email Security & Phishing Investigation

**Focus Area:** Email security and phishing response  
**Tools Used:** Defender for Office 365, Microsoft Sentinel, KQL

---

## 🎯 Objective

Configure email security controls and investigate a simulated phishing attempt to understand how email threats are detected, analyzed, and documented in a SOC.

---

## 🧠 What I Learned

- Safe Links protection operates at time of click, not just delivery
- Email verdicts require analyst validation
- Investigation workflows are as important as technical controls
- Header and URL analysis provide critical context

---

## 🛠️ Key Tasks Performed

- Configured Safe Links and Anti-Phishing policies
- Sent a controlled phishing-style email to a test mailbox
- Investigated the message using Threat Explorer
- Analyzed email headers and embedded URLs
- Documented findings using a SOC reporting format

---

## 📊 Concrete Outcomes

- Produced **1 phishing incident report**
- Investigated **1 credential harvesting scenario**
- Validated Safe Links enforcement in logs
- Documented email artifacts and evidence

---

## 🔍 Investigation Summary

A phishing email impersonating an internal user was detected and quarantined.  
No user interaction occurred, and email security controls functioned as expected.

---

## 📸 Evidence & Screenshots

Included screenshots:
- Safe Links detonation result
- Threat Explorer message view
- Email flow and verdict

Screenshots are stored in the `screenshots/` folder.

---

## 📂 Project Structure

```text
02-email-security/
├── README.md
├── investigation-report.md
├── kql/
├── artifacts/
└── screenshots/
