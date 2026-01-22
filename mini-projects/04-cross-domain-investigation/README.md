## 🔗 Mini Project #4: Cross-Domain Incident Investigation (Capstone)

**Focus Area:** End-to-end SOC investigation and cross-domain correlation.  
**Tools Used:** Microsoft Sentinel, Defender XDR, Entra ID, KQL.  
**Duration:** Days 24–30.

---

## 🎯 Objective

Investigate a simulated multi-stage attack spanning email, identity, and endpoint activity.

This capstone project focuses on correlating telemetry across security domains, reconstructing a complete attack timeline, and producing a professional SOC-style incident report.

---

## 🧠 Skills and Concepts Applied

- Cross-domain alert correlation using Sentinel.
- Identity telemetry as a pivot between email and endpoint activity.
- Timeline reconstruction using time-bound KQL queries.
- Mapping attacker behavior to the MITRE ATT&CK framework.
- Translating technical findings into containment and prevention actions.

---

## 🛠️ Investigation Performed

### Attack Scenario Simulated
- Phishing email delivered to a test user.
- User interaction leading to credential exposure.
- Risky sign-in from an anonymous network.
- Suspicious PowerShell execution on the endpoint.
- Registry-based persistence attempt blocked by ASR rules.

### Correlation and Analysis
- Unified email, identity, and endpoint logs in Microsoft Sentinel.
- Built KQL queries to link activity across domains.
- Created a time-ordered incident timeline.
- Validated whether activity represented a successful compromise or a disrupted attack chain.

---

## 📊 Concrete Outcomes

- Investigated **one high-severity cross-domain incident**.
- Correlated telemetry across **email, identity, and endpoint** sources.
- Identified **five attack stages** within a 12-minute window.
- Mapped observed behavior to **multiple MITRE ATT&CK techniques**.
- Documented containment actions and long-term hardening recommendations.

---

## 🔍 Investigation Summary

A phishing-based attack chain progressed from email delivery to identity risk signals and endpoint execution attempts.

By correlating Defender for Office 365, Entra ID, and Defender for Endpoint telemetry in Sentinel, the full sequence of events was reconstructed. Endpoint and identity controls disrupted the attack before persistence or lateral movement could occur.

The investigation highlighted identity telemetry as the critical link between initial access and endpoint activity.

---

## 🧩 MITRE ATT&CK Techniques Observed

- **T1566.002** – Phishing Link  
- **T1078** – Valid Accounts  
- **T1059.001** – PowerShell  
- **T1547.001** – Registry Run Keys  
- **T1056.003** – Credential Harvesting (attempted)

---

## 📸 Evidence and Artifacts

Artifacts included in this project:
- Sentinel incident graph and entity correlation.
- Cross-domain KQL correlation queries.
- Identity sign-in and risk detection logs.
- Endpoint process and registry activity timelines.

Screenshots and supporting evidence are stored in the `screenshots/` directory and referenced within the final incident report.

---

## 🧠 Key Takeaways

- Individual alerts provide limited value without correlation.
- Identity telemetry often connects email compromise to endpoint behavior.
- Attack timelines can unfold in minutes, not hours.
- Report-only Conditional Access policies introduce real operational risk.

---

## 🚧 Improvements Identified

- Automate response actions using Sentinel playbooks.
- Enrich investigations with threat intelligence feeds.
- Expand correlation rules for similar multi-stage attack patterns.
- Enforce Conditional Access controls for high-risk sign-ins.

---

## 📂 Project Structure

```text
04-cross-domain-investigation/
├── README.md
├── final-incident-report.md
├── correlation-queries/
│   ├── attack-timeline.kql
│   ├── risky-signin-to-endpoint.kql
│   └── email-to-execution.kql
├── mitre-mapping.md
└── screenshots/
