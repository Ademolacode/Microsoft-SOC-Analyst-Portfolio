## 📧 Mini Project #2: Email Security and Phishing Investigation

**Focus Area:** Email security and phishing response  
**Tools Used:** Defender for Office 365, Threat Explorer, KQL  

---

## 🎯 Objective

Configure email security controls and investigate a simulated phishing attempt to demonstrate how email-based threats are detected, analyzed, and documented in a SOC environment.

---

## 🧠 Skills and Concepts Demonstrated

- Safe Links protection operates at time of click rather than delivery
- Automated verdicts require analyst validation and context
- Header and URL analysis provide critical attribution signals
- Clear investigation workflows are as important as technical controls

---

## 🛠️ Investigation Workflow

- Configured Safe Links and Anti-Phishing policies in Defender for Office 365
- Delivered a controlled phishing-style email to a test mailbox
- Identified the message in Threat Explorer
- Analyzed email headers including SPF, DKIM, and DMARC results
- Reviewed Safe Links detonation and URL redirection behavior
- Documented indicators and findings using a SOC-style report format

---

## 📊 Concrete Outcomes

- Produced **one complete phishing incident report**
- Investigated **one credential harvesting scenario**
- Validated Safe Links enforcement at time of click
- Documented sender, URL, and header-based indicators

---

## 🔍 Investigation Summary

A phishing email impersonating an internal security notification was delivered to a test mailbox. The message contained a malicious URL designed to harvest user credentials through a fake login page.

The sender domain failed SPF and DKIM authentication and was identified as a newly registered domain, increasing confidence in the phishing verdict. Safe Links blocked access to the malicious URL at time of click, and the message was automatically quarantined by anti-phishing policies.

No user interaction occurred, and no credentials were compromised.

---

## 🧾 Key Findings

- **Date and Time:** 2025-01-15 09:47:32 UTC  
- **Recipient:** testuser@labdomain.onmicrosoft.com  
- **Sender:** security-alert@phishing-test[.]com  
- **Subject:** “Urgent: Verify Your Account”  
- **Malicious URL:** hxxps://fake-login-page[.]com/verify  
- **Verdict:** Phishing (High Confidence)  
- **Action Taken:** Automatically quarantined, URL blocked by Safe Links  

---

## 🔎 Who, What, When, Where, Why, How

**Who**  
A test user mailbox and an external sender impersonating an internal security notification.

**What**  
A phishing email containing a credential harvesting link.

**When**  
January 15, 2025 at 09:47:32 UTC. The activity is no longer ongoing.

**Where**  
Microsoft 365 email environment protected by Defender for Office 365.

**Why**  
The attacker’s objective was credential harvesting through social engineering.

**How**  
The email bypassed initial delivery filtering but was detected and blocked by Safe Links and anti-phishing policies during analysis and at time of click.

---


