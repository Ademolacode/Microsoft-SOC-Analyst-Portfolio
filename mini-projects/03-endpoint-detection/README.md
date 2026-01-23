## 🖥️ Mini Project #3: Endpoint Detection and Response

**Focus:** Endpoint telemetry and security control validation.  
**Tools:** Defender for Endpoint, Intune, Atomic Red Team, KQL.  
**Duration:** Days 17–23.

---

## 🎯 Objective

Validate endpoint security controls by simulating adversary techniques and investigating generated alerts using structured SOC investigation workflows.
This project focuses on understanding how endpoint telemetry is generated, correlated, and used to confirm whether malicious activity was blocked or successful.

---

## 🛠️ Work Performed

### Endpoint Configuration
- Onboarded a Windows 11 test VM into Defender for Endpoint.
- Configured Attack Surface Reduction rules via Intune.
- Validated telemetry ingestion and policy enforcement in the MDE portal.

### Adversary Simulation and Investigation
- Executed controlled Atomic Red Team techniques:
  - **T1059.001** – PowerShell execution.
  - **T1547.001** – Registry Run Keys persistence.
- Generated alerts for investigation and validation.
- Analyzed alerts in Defender for Endpoint.
- Reviewed device timeline for process creation, registry modification, and network activity.
- Confirmed ASR rules blocked malicious behavior.
- Documented findings in an endpoint-focused investigation report.

---

## 📋 Investigation Summary

A suspicious PowerShell execution alert was generated during controlled testing. Analysis revealed an encoded PowerShell command attempting to establish registry-based persistence via a Run key.
Attack Surface Reduction rules blocked the activity before persistence was established. Device timeline analysis confirmed no payload execution, no lateral movement, and no additional impacted hosts. Full analysis is documented in investigation-report.md.

---


## 📊 Results
| Metric                | Outcome                                        |
| --------------------- | ---------------------------------------------- |
| Alerts Investigated   | 1 medium-severity endpoint alert.              |
| ASR Rules Validated   | 2 rules confirmed blocking malicious activity. |
| Atomic Tests Executed | 2 adversary techniques.                        |
| Incident Reports      | 1 endpoint investigation completed.            |
| User Impact           | None.                                          |


##  📸 Screenshots
Screenshots include:
- Defender for Endpoint alert details.
- Device timeline showing process and registry activity.
- Intune ASR policy configuration.
- Atomic Red Team execution output.
Screenshots and supporting files are stored in the screenshots/ and atomic-tests/ directories.

## 🧠 Key Findings

- Encoded PowerShell commands are a high-fidelity indicator of malicious activity.
- Registry-only persistence attempts can occur without file drops.
- ASR rules must be validated through telemetry, not assumed effective.
- Device timelines are critical for reconstructing attacker behavior.

##  🚧 Improvements Identified

- Expand hunting for lateral movement techniques such as PsExec, WMI, and RDP.
- Test evasion techniques using obfuscated PowerShell.
- Automate enrichment of process hashes during investigations.
- Baseline legitimate PowerShell usage to reduce false positives.
- Practice endpoint isolation and evidence collection workflows.


## 📂 Project Structure
```
03-endpoint-detection/
├── README.md
├── investigation-report.md
├── kql/
│   └── endpoint-hunting-queries.kql
├── atomic-tests/
│   ├── T1059.001-powershell.txt
│   └── T1547.001-registry-run-keys.txt
└── screenshots/
