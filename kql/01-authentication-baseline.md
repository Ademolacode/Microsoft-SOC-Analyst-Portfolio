# Phase 1 - Authentication Baseline

**Lab phase:** SOC Foundation  
**SIEM:** Microsoft Sentinel  
**Table:** `SecurityEvent_CL`  
**Techniques:** EventID analysis, failed logon triage, brute force detection

These are the first queries I ran after setting up Sentinel and connecting the log source from the test VM. The goal before writing any detection was simple: understand what data I was actually looking at. Skipping this step is how you end up writing rules against the wrong table or missing obvious signals that were sitting there the whole time.

---

## Query 1.1 - Schema Check

Run this first on any unfamiliar table. It shows what columns exist and gives you a feel for the data before committing to any filters.

```kql
SecurityEvent_CL
| take 10
```

> **Pro Tip:** Don't take 100. Take 10, scan the columns, understand what `AccountName`, `EventID_s`, and `Computer` look like in this specific dataset. Rushing past this is the most common reason queries return nothing — the column name is slightly different from what you assumed.

---

## Query 1.2 - EventID Distribution

What types of events are actually being generated? Run this before writing any detection; it tells you where the volume is and where to focus first.

```kql
SecurityEvent_CL
| summarize Count = count() by EventID_s
| sort by Count desc
```

**What I found:** EventID 4625 (failed logon) dominated at 18,163 events in a 24-hour window. That volume immediately indicated something was actively probing the VM. Everything else was baseline noise by comparison.

**Key EventIDs to know:**

| EventID | Description |
|---|---|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |
| 4688 | Process created (requires audit policy) |
| 4648 | Logon using explicit credentials |
| 4768 | Kerberos TGT request |
| 4776 | Credential validation |

---

## Query 1.3 - Failed Logon Triage

Now that I know where the volume is, focus on it, Who is being targeted, and how many times?

```kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize FailedAttempts = count() by Account_s
| sort by FailedAttempts desc
| take 10
```

**What this revealed:**

- `\ADMINISTRATOR` - 10,255 attempts. This is the default local admin account name that every automated scanner tries first. Being hammered within hours of VM deployment confirmed the device was internet-facing and actively probed.
- `\admin` (1,989) and `\administrator` (1,864) - case variations of the same account. Automated tools test multiple formats in a single spray.
- `Tamarindo@tamacc\Administrator` - 373 attempts from an external domain account I hadn't configured. Worth flagging for further investigation.

---

## Query 1.4 - Failed Logon Timeline

After identifying the volume, understand the timing. Is this sustained automated scanning or a deliberate burst?

```kql
SecurityEvent_CL
| where EventID_s == "4625"
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

> **Pro Tip:** Use `bin()` with a time interval to group events into hourly buckets.
> - Flat distribution across hours = sustained automated scanning (internet noise)
> - Sharp spike = targeted burst attack or scripted credential test
>
> This tells you whether you are looking at opportunistic background noise or something more deliberate.

---

## Query 1.5 - Top 4 Targeted Accounts (Dashboard Visualisation)

The query behind the Sentinel workbook bar chart. Limited to 4 accounts to keep the visualisation readable.

```kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize Count = count() by Account_s
| sort by Count desc
| take 4
```

In a production environment, add a time filter and exclude known service accounts before using this in a dashboard:

```kql
SecurityEvent_CL
| where EventID_s == "4625"
| where TimeGenerated > ago(7d)
| where Account_s !in ("svc_backup", "svc_monitoring")  // exclude known service accounts
| summarize Count = count() by Account_s
| sort by Count desc
| take 4
```

---

## Query 1.6 - Successful Logon After Failure

The 18,163 failed logons only matter if one of them succeeded. This is the pivot that determines whether the spray was noise or a confirmed compromise.

```kql
let FailedAccounts =
    SecurityEvent_CL
    | where EventID_s == "4625"
    | where TimeGenerated > ago(24h)
    | distinct Account_s;

SecurityEvent_CL
| where EventID_s == "4624"             // Successful logon
| where Account_s in (FailedAccounts)  // Same account was previously failing
| where TimeGenerated > ago(24h)
| project TimeGenerated, Account_s, Computer, EventID_s
| sort by TimeGenerated asc
```

If this returns results, cross-reference the success timestamp against the failure timestamps. A successful logon that follows a run of failures from the same source is a confirmed compromise signal — escalate immediately and pivot to identity logs.

**In this lab:** No confirmed successes were found from the spray activity. The query returned no results, confirming that the brute force was opportunistic scanning rather than a targeted attack that succeeded.

---

*Phase 2 → [Email Security and Phishing Investigation](02-email-phishing-investigation.md)*  
*Back to [Query Index](00-quick-reference.md)*
