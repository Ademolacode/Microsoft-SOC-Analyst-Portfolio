# Microsoft SOC Analyst Portfolio

### Detection, Investigation, and Incident Reporting Across Microsoft Security Stack.

*Built through hands-on SOC simulation using real Microsoft security tooling.*

[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/products/microsoft-sentinel/)
[![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-5E5E5E?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/)
[![Defender for Office 365](https://img.shields.io/badge/Defender%20for%20Office%20365-5E5E5E?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/microsoft-365/security/office-365-security/)
[![Microsoft Entra](https://img.shields.io/badge/Microsoft%20Entra-008272?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/entra/)
[![KQL](https://img.shields.io/badge/KQL-000000?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-FF0000?style=for-the-badge&logo=mitre&logoColor=white)](https://attack.mitre.org/)
[![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-000000?style=for-the-badge&logo=redhat&logoColor=white)](https://atomicredteam.io/)

---

## Table of Contents

- [Purpose of This Repository](#purpose-of-this-repository)
- [What This Portfolio Represents](#what-this-portfolio-represents)
- [Environment Overview](#environment-overview)
- [Investigation Approach](#investigation-approach)
- [Mini-Project Overview](#mini-project-overview)
  - [Mini Project #1: SOC Foundation and Visibility](#-mini-project-1-soc-foundation-and-visibility)
  - [Mini Project #2: Email Security and Phishing Investigation](#-mini-project-2-email-security-and-phishing-investigation)
  - [Mini Project #3: Endpoint Detection and Response](#-mini-project-3-endpoint-detection-and-response)
  - [Mini Project #4: Cross-Domain Incident Investigation (Capstone)](#-mini-project-4-cross-domain-incident-investigation-capstone)
- [Repository Overview](#repository-overview)
- [Skills Demonstrated](#skills-demonstrated)
- [Repository Structure](#repository-structure)

---

## Purpose of This Repository

This repository demonstrates how SOC investigations are performed from initial alert through containment and documentation using Microsoft’s security ecosystem.

The emphasis is on investigation quality rather than tool exposure, including:

- Validation and correlation of telemetry.  
- Alert triage and scoping.  
- Hypothesis-driven investigation.  
- Clear, actionable documentation.  

All activity was conducted in a controlled lab environment designed to mirror real-world SOC workflows.

---

## What This Portfolio Represents

This portfolio reflects hands-on experience with:

- Alert triage and prioritization.  
- Detection and threat hunting using KQL.  
- Investigation across email, identity, and endpoint telemetry.  
- Timeline reconstruction and hypothesis validation.  
- SOC-style incident reporting with evidence and recommendations.  

It is structured as a portfolio of investigations, not a chronological lab journal.

---

## Environment Overview

| Domain | Implementation |
|------|----------------|
| **SIEM** | Microsoft Sentinel with validated log ingestion and analytics. |
| **Endpoint Security** | Microsoft Defender for Endpoint onboarded Windows 11 virtual machine. |
| **Email Security** | Microsoft Defender for Office 365 with Safe Links and Anti-Phishing policies. |
| **Identity** | Microsoft Entra ID sign-in logs and identity risk telemetry. |
| **Device Management** | Microsoft Intune used for Attack Surface Reduction (ASR) policy deployment. |
| **Threat Simulation** | Atomic Red Team for controlled adversary technique execution. |
| **Framework** | MITRE ATT&CK for technique mapping and investigation context. |

---

## Investigation Approach

All investigations followed a consistent SOC methodology.

1. **Validate the alert.**  
   Confirm timestamps, ingestion, and affected entities.

2. **Scope the activity.**  
   Identify users, devices, time window, and potential spread.

3. **Correlate telemetry.**  
   Pivot across email, identity, and endpoint data where applicable.

4. **Test hypotheses.**  
   Evaluate alternative explanations before concluding malicious activity.

5. **Document clearly.**  
   Produce SOC-style reports with findings, impact, and recommendations.

---

## Mini-Project Overview

### 🏗️ Mini Project #1: SOC Foundation and Visibility

📂 **Project Folder:** [mini-projects/01-soc-foundation/](./mini-projects/01-soc-foundation/)

**Focus:** SIEM deployment, log ingestion, and baseline creation.

**Key Outcomes:**
- Deployed Sentinel workspace and validated authentication telemetry.  
- Built dashboards for authentication trends and failed logons.  
- Developed KQL queries to baseline normal behavior.  
- Documented lab architecture and data flow.  

---

### 📧 Mini Project #2: Email Security and Phishing Investigation

📂 **Project Folder:** [mini-projects/02-email-security/](./mini-projects/02-email-security/)

**Focus:** Email threat detection and investigation workflow.

**Key Outcomes:**
- Configured Safe Links and Anti-Phishing policies.  
- Investigated a simulated credential harvesting email.  
- Performed header analysis, URL inspection, and IOC extraction.  
- Produced a complete phishing incident report.  

---

### 🖥️ Mini Project #3: Endpoint Detection and Response

📂 **Project Folder:** [mini-projects/03-endpoint-detection/](./mini-projects/03-endpoint-detection/)

**Focus:** Endpoint telemetry, ASR validation, and alert investigation.

**Key Outcomes:**
- Onboarded endpoint to Defender for Endpoint.  
- Deployed ASR rules via Intune and validated enforcement.  
- Simulated adversary behavior using Atomic Red Team.  
- Investigated PowerShell and registry-based activity.  

---

### 🔗 Mini Project #4: Cross-Domain Incident Investigation (Capstone)

📂 **Project Folder:** [mini-projects/04-cross-domain-investigation/](./mini-projects/04-cross-domain-investigation/)

**Focus:** End-to-end attack reconstruction across email, identity, and endpoint.

**Key Outcomes:**
- Correlated phishing, risky sign-in, and endpoint execution activity.  
- Reconstructed full attack timeline using KQL.  
- Evaluated multiple investigative hypotheses.  
- Delivered a Tier 2-style incident report with remediation guidance.  

---

## Repository Overview

| Path | Description |
|------|-------------|
| `README.md` | Portfolio overview and investigation methodology. |
| `mini-projects/` | SOC investigation projects organized by domain. |
| `screenshots/` | Dashboards, alerts, timelines, and investigation evidence. |

---

## Skills Demonstrated

- Alert triage and prioritization.  
- Detection and threat hunting using KQL.  
- Endpoint and email investigation workflows.  
- Identity-based risk analysis.  
- Cross-domain correlation and timeline reconstruction.  
- Clear technical documentation and reporting.  

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
