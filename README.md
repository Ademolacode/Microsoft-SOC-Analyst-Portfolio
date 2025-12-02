# 30-Day Microsoft SOC Analyst Challenge

## 👋 About This Project

This portfolio documents my hands-on journey through a 30-day Security Operations Center (SOC) challenge, where I built and operated a complete Microsoft security environment from scratch. This project demonstrates real-world skills used by SOC analysts to detect, investigate, and respond to cyber threats.

**What I Built:** A fully functional security monitoring lab using Microsoft's enterprise security tools  
**Duration:** 30 Days (1-3 hours daily)  
**Key Focus:** Threat detection, incident investigation, and security response

---

## 🛠️ Technologies & Tools Used

- **Microsoft Sentinel** - Cloud-based system for collecting and analyzing security alerts
- **Microsoft Defender for Endpoint** - Protection tool that monitors computers for threats
- **Microsoft Defender for Office 365** - Email and collaboration security
- **Azure Entra ID** - Identity and access management (user login security)
- **KQL (Kusto Query Language)** - Search language for finding patterns in security logs
- **MITRE ATT&CK Framework** - Industry standard for categorizing attacker techniques

---

## 📋 Table of Contents

1. [Lab Setup & Configuration](#lab-setup--configuration)
2. [Query Development & Dashboard Creation](#query-development--dashboard-creation)
3. [Threat Detection & Alert Creation](#threat-detection--alert-creation)
4. [Incident Investigation & Response](#incident-investigation--response)
5. [Key Takeaways & Skills Gained](#key-takeaways--skills-gained)

---

## 🏗️ Lab Setup & Configuration

### Environment Architecture

**Naming Convention Used:**  
`MyDFIR-[YourName]-[ResourceType]`

Example:
- `MyDFIR-AdeOni-VM` (Virtual Machine)
- `MyDFIR-AdeOni-Sentinel` (Sentinel Workspace)
- `MyDFIR-AdeOni-LAW` (Log Analytics Workspace)

### What I Built:
✅ Created Azure cloud account with cost monitoring alerts  
✅ Deployed Windows 10 virtual machine for testing  
✅ Configured Microsoft Sentinel workspace  
✅ Connected security tools to collect threat data  

**Why This Matters:** SOC analysts must understand how security tools connect and share information. This foundation is critical for detecting threats across an entire organization.

![Sentinel Workspace Overview](./screenshots/day3-sentinel-workspace.png)
*My configured Sentinel workspace showing connected data sources*

---

## 🔍 Query Development & Dashboard Creation

### KQL Query Examples

#### Query 1: Failed Login Detection
```kql
SecurityEvent_CL 
| where EventID_s == "4625" 
| summarize FailedLogons = count() by Account_s
| where FailedLogons >= 1000
```

**What This Does:** Searches through login records to find accounts with 1,000+ failed password attempts  
**Why It's Important:** High numbers of failed logins often indicate someone is trying to break into an account by guessing passwords (called a "brute force attack")

![Query Results](./screenshots/day4-kql-query-results.png)

#### Query 2: [Add Your Second Query Title]
```kql
// Add your second KQL query here
```

**What This Does:** [Explain what this query searches for]  
**Why It's Important:** [Explain the security value]

#### Query 3: [Add Your Third Query Title]
```kql
// Add your third KQL query here
```

**What This Does:** [Explain what this query searches for]  
**Why It's Important:** [Explain the security value]

### Custom Security Dashboard

I built a custom monitoring dashboard with multiple visualization types to track security metrics in real-time:

- **Bar Charts** - Compare threat counts across different categories
- **Line Graphs** - Track security events over time
- **Pie Charts** - Show proportion of different alert types
- **Data Tables** - Detailed views of specific security events

![Custom Dashboard](./screenshots/day5-custom-dashboard.png)
*Security monitoring dashboard showing real-time threat indicators*

**Business Value:** Dashboards help security teams spot unusual patterns quickly, allowing faster response to potential attacks.

---

## 🚨 Threat Detection & Alert Creation

### Alert Rule: Brute Force Attack Detection

**Detection Logic:**  
Monitor for accounts experiencing 1,000+ failed login attempts within a specific time window

**Alert Configuration:**
- **Trigger Condition:** 1,000+ failed logins on any single account
- **Severity:** High
- **Expected Response Time:** Immediate investigation required

**KQL Rule Used:**
```kql
SecurityEvent_CL 
| where EventID_s == "4625" 
| summarize FailedLogons = count() by Account_s
| where FailedLogons >= 1000
```

![Alert Configuration](./screenshots/day6-alert-creation.png)
*Custom alert rule for detecting password attack attempts*

**Real-World Application:** Automated alerts like this allow SOC teams to catch attacks 24/7, even when analysts aren't actively watching screens.

---

## 📊 Incident Investigation & Response

### Case Study: Brute Force Attack Investigation

**Scenario:** Alert triggered showing massive spike in failed login attempts

#### Investigation Findings

**Evidence Discovered:**
- **\ADMINISTRATOR** - 20,510 failed login attempts
- **\admin** - 3,978 failed login attempts  
- **\administrator** - 3,728 failed login attempts
- **\ADMIN** - 1,196 failed login attempts

**Total Impact:** 29,412 failed login attempts across administrator accounts

#### Detailed Analysis

| Investigation Element | Findings |
|----------------------|----------|
| **WHO - Targeted Accounts** | All four accounts were administrator-level, meaning they have full control over the system. Attackers target these because gaining access means complete system compromise. |
| **WHAT - Attack Type** | Automated password guessing attack (brute force) attempting to gain unauthorized access to high-privilege accounts. |
| **WHEN - Timeline** | Failed attempts occurred during monitored timeframe. Continuous monitoring implemented to detect ongoing activity. |
| **WHERE - Attack Location** | Authentication system targeting the Windows login process. |
| **WHY - Attacker Motivation** | Likely seeking administrative access to steal data, install malware, or gain persistent access to the network. |
| **HOW - Attack Method** | Attacker used automated tools to systematically try thousands of password combinations against administrator accounts. |

![Investigation Results](./screenshots/day7-investigation-results.png)
*KQL query results showing targeted accounts and failed login counts*

#### Recommended Actions

**Immediate Response (0-24 hours):**
1. ✅ Force password reset for all four compromised accounts
2. ✅ Enable Multi-Factor Authentication (MFA) - requires phone/app confirmation, not just password
3. ✅ Review logs for any successful logins after failed attempts
4. ✅ Block attacking IP addresses at the firewall

**Short-Term Fixes (1-7 days):**
5. ✅ Implement account lockout after 5 failed attempts
6. ✅ Investigate for "lateral movement" - check if attacker accessed other systems
7. ✅ Review all administrative account activity for suspicious behavior

**Long-Term Improvements (Ongoing):**
8. ✅ Rename or disable default "Administrator" accounts
9. ✅ Implement privilege access management (PAM) solution
10. ✅ Create automated response playbook for future brute force detections

---

## 📌 Incident Bookmarking & Case Management

### Notable Security Event - Day 8

**Event Summary:**  
[Add your 2-3 sentence description of the bookmarked event here]

**Why This Was Flagged:**  
[Explain why this particular log entry was important and warranted creating an incident]

**Investigation Actions:**  
Created manual incident ticket for further investigation and tracking. This demonstrates proper SOC workflow where interesting findings are escalated for deeper analysis.

![Bookmark Example](./screenshots/day8-bookmark-incident.png)

---

## 💡 Key Takeaways & Skills Gained

### Technical Skills Developed

✅ **Threat Detection** - Built custom detection rules to identify attack patterns  
✅ **Log Analysis** - Used KQL to search through millions of security events  
✅ **Incident Response** - Investigated security alerts and determined appropriate actions  
✅ **Security Tool Integration** - Connected multiple Microsoft security products into unified system  
✅ **Dashboard Creation** - Built visual monitoring tools for tracking threats  
✅ **Report Writing** - Documented findings using industry-standard frameworks (MITRE ATT&CK)

### Most Valuable Lesson

The most impactful part of this challenge was learning how automated detection rules work alongside human investigation. Technology can flag thousands of suspicious events, but analyst expertise is needed to determine which ones are real threats versus false alarms. This balance between automation and human judgment is what makes SOC work both challenging and rewarding.

### Real-World Applications

This hands-on experience mirrors actual SOC analyst responsibilities:
- Monitoring security dashboards for anomalies
- Writing and tuning detection rules
- Investigating alerts and determining severity
- Documenting findings for stakeholders
- Recommending remediation actions

### Areas for Continued Growth

- Advanced threat hunting techniques
- Malware analysis and reverse engineering  
- Cloud security architecture
- Security automation and orchestration (SOAR)
- Advanced persistent threat (APT) detection
- Incident response automation with playbooks

---

## 📁 Project Structure

```
30-Day-SOC-Challenge/
├── README.md (This file)
├── screenshots/
│   ├── day3-sentinel-workspace.png
│   ├── day4-kql-query-results.png
│   ├── day5-custom-dashboard.png
│   ├── day6-alert-creation.png
│   ├── day7-investigation-results.png
│   └── day8-bookmark-incident.png
├── queries/
│   ├── failed-logins-detection.kql
│   ├── query-example-2.kql
│   └── query-example-3.kql
├── reports/
│   └── brute-force-investigation-report.md
└── documentation/
    └── lab-setup-notes.md
```

---

## 🎯 Challenge Completion

**Program:** MyDFIR 30-Day Microsoft SOC Analyst Challenge  
**Completion Date:** [Add your completion date]  
**Total Hours Invested:** 30-90 hours (1-3 hours daily)  
**Key Deliverables:** 4 mini-projects, multiple incident investigations, production-ready security monitoring environment

---

## 📫 Connect With Me

I'm actively seeking SOC Analyst opportunities where I can apply these skills to protect organizations from real-world threats.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](your-linkedin-url)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](your-github-url)
[![Email](https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:your-email)

---

## 🙏 Acknowledgments

This challenge was completed as part of the MyDFIR 30-Day SOC Analyst Challenge. Special thanks to the cybersecurity community for feedback and support throughout this learning journey.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Last Updated: December 2024*  
*Challenge Start Date: [Your start date]*  
*Challenge Completion Date: [Your completion date]*
