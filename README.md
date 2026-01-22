# Microsoft SOC Analyst Portfolio

### Detection, Investigation, and Incident Reporting Across Microsoft Security Stack

*Built through hands-on SOC simulation using real Microsoft security tooling*

[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/products/microsoft-sentinel/)
[![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-5E5E5E?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/)
[![Defender for Office 365](https://img.shields.io/badge/Defender%20for%20Office%20365-5E5E5E?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/microsoft-365/security/office-365-security/)
[![Microsoft Entra](https://img.shields.io/badge/Microsoft%20Entra-008272?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/entra/)
[![KQL](https://img.shields.io/badge/KQL-000000?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-FF0000?style=for-the-badge&logo=mitre&logoColor=white)](https://attack.mitre.org/)
[![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-000000?style=for-the-badge&logo=redhat&logoColor=white)](https://atomicredteam.io/)

---

## Purpose of This Repository

This repository demonstrates how I perform SOC investigations from initial alert through containment and documentation using Microsoft’s security ecosystem.

The focus is not on tool exposure alone, but on:

- How telemetry is validated and correlated  
- How alerts are triaged and investigated  
- How findings are documented and communicated  
- How gaps in detection and prevention are identified  

All work was performed in a controlled lab environment designed to mirror real-world SOC workflows.

---

## What This Portfolio Represents

This portfolio reflects hands-on experience with:

- Alert triage and prioritization  
- Detection and hunting using KQL  
- Investigation across email, identity, and endpoint telemetry  
- Timeline reconstruction and hypothesis validation  
- SOC-style incident reporting with evidence and recommendations  

It is intentionally structured as a portfolio of investigations, not a chronological lab journal.

---
## Environment Overview

| Domain | Implementation |
|------|----------------|
| **SIEM** | Microsoft Sentinel with validated log ingestion and analytics |
| **Endpoint Security** | Microsoft Defender for Endpoint onboarded Windows 11 virtual machine |
| **Email Security** | Microsoft Defender for Office 365 with Safe Links and Anti-Phishing policies |
| **Identity** | Microsoft Entra ID sign-in logs and Audit logs |
| **Device Management** | Microsoft Intune used for Attack Surface Reduction (ASR) policy deployment |
| **Threat Simulation** | Atomic Red Team for controlled adversary technique execution |
| **Framework** | MITRE ATT&CK used for technique mapping and investigation context |

---

## Investigation Approach

Across all projects, investigations followed a consistent methodology:

1. **Validate the alert**  
   Confirm data ingestion, timestamps, and affected entities.

2. **Scope the activity**  
   Identify users, devices, time window, and potential spread.

3. **Correlate telemetry**  
   Pivot across email, identity, and endpoint data where applicable.

4. **Test hypotheses**  
   Evaluate alternative explanations before concluding malicious activity.

5. **Document clearly**  
   Produce SOC-style reports with findings, impact, and recommendations.

This mirrors how investigations are handled in operational SOC environments.

---

## Mini-Project Overview

### 🏗️ Mini Project #1: SOC Foundation and Visibility

**Focus:** SIEM deployment, log ingestion, and baseline creation.

**Key Outcomes:**
- Deployed Sentinel workspace and validated authentication telemetry  
- Built dashboards for authentication trends and failed logons  
- Developed KQL queries to baseline normal behavior  
- Documented lab architecture and data flow  

**Why It Matters:**  
Reliable investigations require trusted data. This project established the visibility and structure needed before detection or response work could begin.

📂 `mini-projects/01-soc-foundation/`

---

### 📧 Mini Project #2: Email Security and Phishing Investigation

**Focus:** Email threat detection and investigation workflow.

**Key Outcomes:**
- Configured Safe Links and Anti-Phishing policies  
- Investigated a simulated credential harvesting email  
- Performed header analysis, URL inspection, and IOC extraction  
- Produced a complete phishing incident report  

**Why It Matters:**  
Phishing remains a primary attack vector. This project demonstrates the ability to trace an email threat from delivery through enforcement and validation.

📂 `mini-projects/02-email-security/`

---

### 🖥️ Mini Project #3: Endpoint Detection and Response

**Focus:** Endpoint telemetry, ASR validation, and alert investigation.

**Key Outcomes:**
- Onboarded endpoint to Defender for Endpoint  
- Deployed ASR rules through Intune and validated enforcement  
- Simulated adversary behavior using Atomic Red Team  
- Investigated PowerShell and registry-based activity  
- Confirmed prevention and documented findings  

**Why It Matters:**  
Endpoint alerts require context. This project shows how telemetry is used to distinguish blocked activity from active compromise.

📂 `mini-projects/03-endpoint-detection/`

---

### 🔗 Mini Project #4: Cross-Domain Incident Investigation (Capstone)

**Focus:** End-to-end attack reconstruction across email, identity, and endpoint.

**Key Outcomes:**
- Correlated phishing, risky sign-in, and endpoint execution activity  
- Reconstructed full attack timeline using KQL  
- Evaluated multiple investigative hypotheses  
- Mapped activity to MITRE ATT&CK techniques  
- Delivered a Tier 2-style incident report with remediation guidance  

**Why It Matters:**  
Real incidents do not occur in isolation. This project demonstrates cross-domain correlation and investigative judgment.

📂 `mini-projects/04-cross-domain-investigation/`

---

## Measurable Outcomes

| Area | Result |
|----|-------|
| Incident Reports | 4 SOC-style investigations |
| KQL Queries | 10+ detection and hunting queries |
| Dashboards | 3 operational Sentinel workbooks |
| Alerts Investigated | 8+ across multiple domains |
| MITRE Techniques | 25+ identified and mapped |
| Response Actions | Account disablement, isolation, policy validation |

---

## Skills Demonstrated

- Alert triage and prioritization  
- Detection and threat hunting using KQL  
- Endpoint and email investigation workflows  
- Identity-based risk analysis  
- Cross-domain correlation and timeline reconstruction  
- Clear technical documentation and reporting  
- Detection validation and control testing  

---

## Repository Structure

```text
microsoft-soc-analyst-portfolio/
├── README.md
├── mini-projects/
│   ├── 01-soc-foundation/
│   ├── 02-email-security/
│   ├── 03-endpoint-detection/
│   └── 04-cross-domain-investigation/
└── screenshots/
