# Microsoft-SOC-Lab-Portfolio

### Detection, Investigation, and Incident Reporting

*(Microsoft Sentinel · Defender XDR · Entra ID · Intune · KQL)*

[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge\&logo=microsoftazure\&logoColor=white)](https://azure.microsoft.com/products/microsoft-sentinel/)
[![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-5E5E5E?style=for-the-badge\&logo=microsoft\&logoColor=white)](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/)
[![Defender for Office 365](https://img.shields.io/badge/Defender%20for%20Office%20365-5E5E5E?style=for-the-badge\&logo=microsoft\&logoColor=white)](https://learn.microsoft.com/microsoft-365/security/office-365-security/)
[![Microsoft Entra](https://img.shields.io/badge/Microsoft%20Entra-008272?style=for-the-badge\&logo=microsoft\&logoColor=white)](https://learn.microsoft.com/entra/)
[![Microsoft Intune](https://img.shields.io/badge/Intune-0078D4?style=for-the-badge\&logo=microsoft\&logoColor=white)](https://learn.microsoft.com/mem/intune/)
[![KQL](https://img.shields.io/badge/KQL-000000?style=for-the-badge\&logo=microsoft\&logoColor=white)](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
[![MITRE ATT\&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-FF0000?style=for-the-badge\&logo=mitre\&logoColor=white)](https://attack.mitre.org/)
[![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-000000?style=for-the-badge\&logo=redhat\&logoColor=white)](https://atomicredteam.io/)

---

## 📖 Table of Contents

* Project Purpose
* Portfolio Highlights
* Technology Stack
* Mini-Project Milestones
* Mini-Project Structure
* Investigation Reports
* Screenshot Index
* Repository Structure
* Key Technical Challenges
* Skills Demonstrated

---

## 📌 Project Purpose

This repository is a SOC-style portfolio built through the **MyDFIR 30-Day Microsoft SOC Challenge**.
It demonstrates how a junior SOC analyst builds visibility, writes KQL for triage and hunting, investigates alerts across Microsoft security tools, and produces professional incident reports with evidence and clear recommendations.

This is intentionally written as a **portfolio**, not a day-by-day lab journal.

---

## 📊 Portfolio Highlights

| Area                     | Outcome                                      |
| ------------------------ | -------------------------------------------- |
| Incident Reports         | 4 complete SOC-style investigations          |
| KQL Development          | 12 custom detection and hunting queries      |
| Dashboards               | 3 operational Sentinel dashboards created    |
| Endpoint Validation      | ASR rule block events confirmed in logs      |
| Email Security           | 1 phishing investigation with full artifacts |
| Cross-Domain Correlation | 1 full kill-chain reconstruction             |
| MITRE Coverage           | 25+ techniques across multiple tactics       |

---

## 🛠️ Technology Stack

| Domain              | Tooling                         |
| ------------------- | ------------------------------- |
| SIEM                | Microsoft Sentinel              |
| Endpoint Security   | Microsoft Defender for Endpoint |
| Email Security      | Defender for Office 365         |
| Identity            | Microsoft Entra ID              |
| Device Management   | Microsoft Intune                |
| Query Language      | Kusto Query Language (KQL)      |
| Adversary Emulation | Atomic Red Team                 |
| Framework           | MITRE ATT&CK                    |

---

## 🧩 Mini-Project Milestones

### 🏗️ Mini Project #1: SOC Foundation & Lab Blueprint

**Focus:** Establishing visibility and architecture.
**Outcome:** Sentinel workspace with validated ingestion, dashboards, and initial detections.
**Concrete Result:** Created 2 dashboards and wrote 4 authentication-focused KQL queries.

**What I Learned:**
Visibility is not automatic. I learned how to configure data connectors correctly and how a consistent naming convention prevents “log soup” in a real SOC.

📂 `mini-projects/01-soc-foundation/`

---

### 📧 Mini Project #2: Email Security & Phishing Investigation

**Focus:** Defensive policy configuration and email forensics.
**Outcome:** Investigated a credential harvesting attempt and documented the response.
**Concrete Result:** Produced 1 phishing incident report with headers, URL analysis, and recommendations.

**What I Learned:**
How Safe Links affects time-of-click protection and why detection alone is not enough without a clear investigation workflow.

📂 `mini-projects/02-email-security/`

---

### 🖥️ Mini Project #3: Endpoint Detection & Response

**Focus:** Endpoint telemetry, detection validation, and hunting.
**Outcome:** Investigated an endpoint alert generated from controlled adversary simulation.
**Concrete Result:** Validated ASR rule enforcement and wrote 1 endpoint incident report.

**What I Learned:**
How Defender for Endpoint correlates process, registry, and timeline data, and how hypothesis-driven hunting reveals detection gaps.

📂 `mini-projects/03-endpoint-detection/`

---

### 🔗 Mini Project #4: Cross-Domain Incident Investigation

**Focus:** End-to-end SOC investigation across email, identity, and endpoint.
**Outcome:** Full kill-chain reconstruction with unified KQL correlation.
**Concrete Result:** Delivered 1 final SOC-style incident report with timeline and response actions.

**What I Learned:**
Cross-domain visibility turns isolated alerts into a story. Conditional Access in report-only mode is a real risk.

📂 `mini-projects/04-cross-domain-investigation/`

---

## 🗂️ Mini-Project Structure (What Lives Where)

Each mini project follows a consistent SOC documentation pattern:

* **README.md** – scope, objective, and outcome
* **screenshots/** – dashboards, alerts, policies, timelines
* **kql/** – detection, pivot, and hunting queries
* **investigation-report.md** – SOC-style incident write-up
* **artifacts/** – headers, indicators, or evidence where applicable

This mirrors how investigations are documented in real SOC environments.

---

## 📸 Screenshot Index

Screenshots are stored inside their relevant mini-project folders and referenced where appropriate.

| Screenshot            | Description                                   |
| --------------------- | --------------------------------------------- |
| Sentinel Dashboard    | Authentication trends and baseline visibility |
| KQL Query Results     | Failed logon and hunting pivots               |
| Safe Links Detonation | Credential harvesting page blocked            |
| MDE Timeline          | Process and registry persistence activity     |
| ASR Policy            | Intune-configured rule enforcement            |
| Incident Graph        | Cross-domain correlation in Sentinel          |

---

## 📁 Repository Structure

```text
microsoft-soc-lab-portfolio/
├── README.md
├── mini-projects/
│   ├── 01-soc-foundation/
│   ├── 02-email-security/
│   ├── 03-endpoint-detection/
│   └── 04-cross-domain-investigation/
└── screenshots/
```

---

## ⚙️ Key Technical Challenges

**KQL Performance Optimization**
Reduced authentication queries from 18 seconds to under 2 seconds by adding time filters and aggregation logic.

**Alert Fatigue Reduction**
Adjusted thresholds and baselined behavior, reducing false positives by approximately 73 percent.

**Cross-Domain Correlation**
Unified email, identity, and endpoint telemetry using Sentinel to reduce investigation time and context switching.

---

## 🎯 Skills Demonstrated

* Detection engineering using KQL
* SOC triage and investigation workflows
* Endpoint and email incident response
* Cross-domain correlation and timeline reconstruction
* Professional security documentation
* MITRE ATT&CK mapping where relevant

---

### Final note
