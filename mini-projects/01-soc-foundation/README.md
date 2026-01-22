## 🏗️ Mini Project #1: SOC Foundation and Lab Blueprint.

**Focus Area:** SIEM Deployment, Data Ingestion, and Operational Visibility.

**Tools Used:** :Microsoft Sentinel, Azure Monitor, On-Prem Virtual Machine, KQL.

---

## 🎯 Objective

Deploy Microsoft Sentinel, establish log ingestion from a test VM, and create dashboards for authentication monitoring.

This project focuses on making security data structured, reliable, and investigation-ready rather than simply available.

---

## 🧠 Skills and Concepts Demonstrated

- Visibility requires deliberate configuration rather than default settings
- Data connectors must be validated before detections can be trusted
- Consistent naming and structure reduce investigation friction
- Dashboards provide baseline context and trends, not alerts

---

## 🛠️ Tasks Performed

- Deployed and configured a Microsoft Sentinel workspace
- Connected authentication-related log sources and validated ingestion
- Developed KQL queries to identify failed authentication patterns
- Built dashboards to baseline authentication behavior
- Bookmarked notable events to support future investigations

---

## 📊 Concrete Outcomes

- Created **2 Sentinel dashboards** focused on authentication visibility
- Wrote **4 KQL queries** targeting failed logons and suspicious patterns
- Validated ingestion from **one primary authentication log source**
- Documented the SOC lab architecture and data flow as a blueprint

---

## 🔎 Technical Validation 

To ensure the environment was investigation-ready, I validated both **data quality and query performance**:

- Confirmed authentication events were consistently ingested and time-aligned
- Optimized baseline queries using time filters and aggregation
- Reduced authentication query runtime from **~18 seconds to under 2 seconds** on a 7-day lookback

This ensured dashboards and investigations remained responsive as data volume increased.

---

## 📸 Evidence and Artifacts

Artifacts included in this project:
- Sentinel workspace overview
- Authentication baseline dashboard
- KQL query execution with results

Screenshots are stored in the `screenshots/` directory and referenced where applicable.

---

## 📂 Project Structure

```text
01-soc-foundation/
├── README.md
├── kql/
├── dashboards/
├── screenshots/
└── notes.md
