# 📧 Mini Project #2 Investigation Report
## Phishing Email Investigation

---

## Findings (What did you find)

- Time: 2026-01-22 02:11:34 UTC.
- Recipient: david.books@CyberLetcode.onmicrosoft.com.
- Sender Address: hr-notify@external-payroll[.]com.
- Subject: Urgent Payroll Update Required.
- Malicious URL: hxxps://secure-payroll-update[.]com/login.
- Verdict: Phishing (Credential Harvesting).
- Action Taken: Message quarantined, URL blocked by Safe Links.
- Product: Microsoft Defender for Office 365.
---

## Investigation Summary (What happened)

On January 22, 2026, a phishing email impersonating an internal HR payroll notification was delivered to a test mailbox within the CyberLetcode Microsoft 365 environment.

The email contained a malicious link designed to harvest user credentials via a spoofed login page. Defender for Office 365 analyzed the message, and Safe Links blocked the embedded URL at time of click. The email was automatically quarantined based on anti-phishing policy enforcement.

No evidence of user interaction, credential compromise, or follow-on malicious activity was identified during the investigation.

# Who, What, When, Where, Why, How

---
## Who

- Targeted user: david.books@CyberLetcode.onmicrosoft.com.
- Sender: External sender impersonating internal HR

## What

- Credential harvesting phishing email

## When

January 22, 2026 at 02:11:34 UTC

Activity was limited to a single email event and is no longer ongoing.

## Where

Microsoft 365 email environment protected by Defender for Office 365.

## Why

The attacker attempted to collect user credentials using social engineering and urgency.

## How

The email bypassed initial spam filtering.

Safe Links evaluated the embedded URL at time of click and blocked access.

Anti-phishing policies quarantined the message.

---

## Validation Steps Performed

- Reviewed Threat Explorer to confirm message delivery and verdict.
- Analyzed email headers to validate authentication failures.
- Confirmed Safe Links URL block event.
- Queried for additional emails from the same sender domain.
- Checked Entra ID sign-in logs for suspicious activity related to the recipient.

--- 

## Recommendations

- Confirm Safe Links and Anti-Phishing policies are enforced across all user mailboxes.
- Add the sender domain external-payroll[.]com to the tenant block list.
- Monitor for similar payroll or HR-themed phishing attempts from external senders.
- Ensure users cannot self-release quarantined phishing messages.
- Use this incident as a phishing awareness training example for users.
---

## Analyst Notes

Threat Explorer did not immediately display the message after delivery. Data became available approximately 20 minutes later, highlighting the importance of re-querying during active investigations.
