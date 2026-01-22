## 📧 Mini Project #2: Email Security and Phishing Investigation

**Focus:** Email threat detection and investigation.  
**Tools:** Defender for Office 365, Threat Explorer, KQL.  
**Duration:** Days 10–16.

---

## 🎯 Objective

Configure email security controls, simulate a phishing attack, and document a complete SOC-style investigation from detection through remediation.

---

## 🛠️ Work Performed

### Email Security Configuration
- Safe Links for time-of-click URL protection.
- Anti-Phishing policies for impersonation detection.
- Quarantine policies for high-confidence phishing messages.

### Phishing Simulation
- Delivered a credential harvesting email to a test mailbox.
- Monitored detection and enforcement using Threat Explorer.
- Analyzed email headers and embedded URLs.
- Validated Safe Links blocked access to the phishing page.

---

## 📋 Investigation Report Summary

### Findings
- **Date/Time:** 2025-01-15 09:47:32 UTC.  
- **Recipient:** testuser@labdomain.onmicrosoft.com.  
- **Sender:** security-alert@phishing-test[.]com.  
- **Subject:** “Urgent: Verify Your Account”.  
- **Malicious URL:** hxxps://fake-login-page[.]com/verify.  
- **Verdict:** Phishing, high confidence.  
- **Action Taken:** Automatically quarantined.

### Investigation Summary
A phishing email impersonating an internal security notification was delivered to a test mailbox. Header analysis showed SPF and DKIM authentication failures, and the sender domain had been registered three days prior. Safe Links blocked the credential harvesting page at time of click. No user interaction occurred, and no credentials were compromised.

### Who, What, When, Where, Why, How
- **Who:** Test user mailbox.  
- **What:** Credential harvesting phishing email.  
- **When:** 2025-01-15 09:47:32 UTC.  
- **Where:** Microsoft 365 test environment.  
- **Why:** Simulated attack to validate email security controls.  
- **How:** Email bypassed initial spam filtering but was blocked by Safe Links and Anti-Phishing enforcement.

---

## 🛡️ Recommendations

- Confirm Safe Links and Anti-Phishing policies apply to all mailboxes.
- Block the sender domain `phishing-test[.]com` at the tenant level.
- Create detection rules for urgent account verification themes from external senders.
- Prevent users from self-releasing quarantined phishing messages.
- Use this incident as an example for phishing awareness training.

---

## 🔍 KQL Queries Used

### Phishing Email Detection
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Phish"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction
| order by TimeGenerated desc

Safe Links Block Events
UrlClickEvents
| where TimeGenerated > ago(7d)
| where ActionType == "ClickBlocked"
| project TimeGenerated, AccountUpn, Url, UrlChain

Quarantined Messages by Sender
EmailEvents
| where DeliveryAction == "Quarantined"
| summarize Count = count() by SenderFromAddress
| order by Count desc

```

| Metric             | Outcome                                |
| ------------------ | -------------------------------------- |
| Incident Reports   | 1 phishing investigation completed.    |
| Policies Validated | Safe Links, Anti-Phishing, Quarantine. |
| Threats Blocked    | 1 credential harvesting attempt.       |
| User Impact        | None.                                  |


## 🧠 Key Learnings

Safe Links enforcement occurs at time of click, not delivery.

SPF, DKIM, and DMARC failures are strong phishing indicators.

Threat Explorer data may take 15–30 minutes to populate.

Clear documentation improves investigation handoff and communication.

## 🚧 Improvements Identified

Add detection for newly registered domains under seven days old.

Automate URL and domain enrichment during investigations.

Validate user-reported phishing workflows.

Develop a standardized phishing response playbook.

---

## 📂 Project Structure

02-email-security/
├── README.md
├── investigation-report.md
├── kql/
│   └── email-threat-queries.kql
├── artifacts/
│   ├── email-headers.txt
│   └── iocs.txt
└── screenshots/



