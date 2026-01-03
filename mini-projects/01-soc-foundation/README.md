## 🏗️ Mini Project #1: SOC Foundation & Lab Blueprint

**Focus Area:** SIEM foundations and visibility  
**Tools Used:** Microsoft Sentinel, Azure Monitor, KQL

---

## 🎯 Objective

Establish foundational SOC visibility by deploying Microsoft Sentinel, validating log ingestion, and building dashboards that support authentication triage and baseline analysis.

This project focuses on making security data usable and structured, not just available.

---

## 🧠 What I Learned

- Visibility requires deliberate configuration, not default settings
- Data connectors must be validated before relying on detections
- Naming conventions and structure prevent investigation confusion
- Dashboards provide context and baselines, not alerts

---

## 🛠️ Key Tasks Performed

- Deployed Microsoft Sentinel workspace
- Connected and validated authentication log sources
- Wrote KQL queries to identify failed authentication patterns
- Built dashboards for authentication baselining
- Bookmarked notable events for investigation

---

## 📊 Concrete Outcomes

- Created **2 Sentinel dashboards**
- Wrote **4 authentication-focused KQL queries**
- Validated ingestion from **1 primary log source**
- Documented SOC lab blueprint and structure

---

## 📸 Evidence & Screenshots

Included screenshots:
- Sentinel workspace overview
- Authentication dashboard
- KQL query with results

Screenshots are stored in the `screenshots/` folder.

---

## 📂 Project Structure

```text
01-soc-foundation/
├── README.md
├── kql/
├── dashboards/
├── screenshots/
└── notes.md
```

## 🚧 What I Would Improve Next

Expand detections beyond authentication events

Establish longer baselines for normal behavior

Add enrichment context such as user roles and geography
