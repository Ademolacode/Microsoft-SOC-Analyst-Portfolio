## 🖥️ Mini Project #3: Endpoint Detection & Response

**Focus Area:** Endpoint telemetry and control validation  
**Tools Used:** Microsoft Defender for Endpoint, Intune, Atomic Red Team, KQL

---

## 🎯 Objective

Investigate an endpoint alert generated from controlled adversary simulation and validate endpoint security controls using Defender for Endpoint and Intune.

---

## 🧠 What I Learned

- Endpoint telemetry provides deep visibility when interpreted correctly
- ASR rules must be validated, not assumed effective
- Device timelines help reconstruct attacker behavior
- Hypothesis-driven hunting exposes detection gaps

---

## 🛠️ Key Tasks Performed

- Onboarded Windows 11 VM to Defender for Endpoint
- Configured Attack Surface Reduction rules via Intune
- Executed Atomic Red Team techniques
- Investigated alerts using the device timeline
- Wrote hunting queries to pivot on suspicious behavior

---

## 📊 Concrete Outcomes

- Generated and investigated **1 endpoint alert**
- Validated **ASR rule block event** in logs
- Executed **2 Atomic Red Team techniques**
- Produced **1 endpoint incident report**

---

## 🔍 Investigation Summary

A registry-based persistence technique was detected during controlled testing.  
ASR rules triggered as expected, and no lateral movement was observed.

---

## 📸 Evidence & Screenshots

Included screenshots:
- MDE alert details
- Device timeline
- ASR policy configuration
- Atomic test execution

Screenshots are stored in the `screenshots/` folder.

---

## 📂 Project Structure

```text
03-endpoint-detection/
├── README.md
├── investigation-report.md
├── kql/

```

## 🚧 What I Would Improve Next

Expand hunting beyond persistence techniques

Add detection for payload execution attempts

Automate alert enrichment workflows
├── atomic-tests/
└── screenshots/
