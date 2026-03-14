# KQL Quick Reference

**Lab:** MyDFIR 30-Day Microsoft SOC Analyst Challenge  
**Environment:** Microsoft Sentinel + Defender XDR  
**Methodology:** MAHCyberDefense Investigation Playbook (Collect → Correlate → Contextualize → Construct)

Use this as your starting point when you receive an alert and need to orient quickly. Pick the section that matches where the alert originated, run the triage query, then follow the cross-domain pivots at the bottom.

---

## Tables Used in This Lab

| Table | Data | Use For |
|---|---|---|
| `SecurityEvent_CL` | Windows security events from VM | EventID 4625 (failed logon), 4624 (success) |
| `SignInLogs` | Entra ID interactive sign-ins | Authentication anomalies, CA policy results |
| `AADNonInteractiveUserSignInLogs` | Service-to-service auth | OAuth token abuse, service principal activity |
| `EmailEvents` | Email delivery from MDO | Phishing delivery, sender analysis |
| `EmailUrlInfo` | URLs extracted from emails | IOC extraction, URL reputation |
| `UrlClickEvents` | User click events via Safe Links | Confirming a user clicked a phishing URL |
| `DeviceProcessEvents` | Process creation on MDE endpoints | Command execution, malware detection |
| `DeviceFileEvents` | File operations on MDE endpoints | Malware drops, staging directories |
| `DeviceRegistryEvents` | Registry changes on MDE endpoints | Persistence, configuration changes |
| `DeviceNetworkEvents` | Network connections from MDE endpoints | C2 detection, exfiltration |
| `DeviceLogonEvents` | Logon events on MDE endpoints | RDP, lateral movement |
| `CloudAppEvents` | Cloud app activity (SharePoint, Exchange) | Post-compromise data access, forwarding rules |
| `AuditLogs` | Entra ID admin actions | Account changes, role assignments |

---

## The 4-Step Investigation Method

### Step 1 — Collect
Run a broad query on the relevant table. No filters except time. Document what you see before you start narrowing.

```kql
SecurityEvent_CL
| where TimeGenerated > ago(24h)
| take 50
```

### Step 2 — Correlate
Link events across tables using shared entity identifiers.

- `UserPrincipalName` / `Account_s` — identity thread  
- `DeviceName` — endpoint thread  
- `IPAddress` — network thread  
- `NetworkMessageId` — email thread  

```kql
// Example: join two tables on shared account name
TableA
| join kind=inner TableB
      on $left.UserPrincipalName == $right.AccountName
```

### Step 3 — Contextualize
Ask: is this normal for this user, device, and time?

- Does the time make sense? (03:00 UTC Sunday from a foreign IP is unusual)
- Does the parent process make sense? (Word spawning PowerShell does not)
- Does the destination make sense? (PowerShell reaching a Tor exit node does not)

### Step 4 — Construct
Build the narrative. Sort everything ascending by `TimeGenerated`. Map each event to a MITRE ATT&CK technique.

---

## Essential Syntax

### Time Filtering — Always Scope First

```kql
// Relative time
| where TimeGenerated > ago(24h)
| where TimeGenerated > ago(7d)

// Specific date range
| where TimeGenerated between (datetime(2026-01-22) .. datetime(2026-01-23))

// Specific timestamp
| where TimeGenerated > datetime(2026-01-22 15:30:00)
```

### String Matching

```kql
// Exact match — case-sensitive
| where DeviceName == "mydfir"

// Exact match — case-insensitive (use for usernames and hostnames)
| where UserPrincipalName =~ "david.book@cyberletcode.onmicrosoft.com"

// Partial match — substring
| where FileName contains "mimikatz"

// Whole word match — faster than contains on large datasets
| where ProcessCommandLine has "powershell"

// Match any value in a list
| where FileName has_any ("cmd.exe", "powershell.exe", "wscript.exe")

// Match multiple exact values
| where AccountName in ("admin", "administrator", "david.book")

// Regular expression — use for IP ranges and patterns
| where IPAddress matches regex @"185\.220\."

// NOT matching
| where DeviceName != "DC01"
| where FileName !contains "chrome.exe"
```

### Aggregation

```kql
// Count by field
| summarize Count = count() by AccountName

// Count in hourly buckets — for timeline analysis
| summarize Count = count() by bin(TimeGenerated, 1h)

// Count distinct values
| summarize UniqueIPs = dcount(IPAddress) by AccountName

// Collect values into a set
| summarize Accounts = make_set(UserPrincipalName, 20) by IPAddress
```

### Joining Tables

```kql
// Inner join — only matching rows from both tables
| join kind=inner OtherTable
      on $left.UPN == $right.UserPrincipalName

// Left outer join — keep all rows from left, match where possible
| join kind=leftouter OtherTable on SharedColumn
```

### Displaying and Sorting

```kql
// Select specific columns — remove clutter
| project TimeGenerated, AccountName, IPAddress, FileName

// Add a calculated column without removing existing ones
| extend IsEncoded = ProcessCommandLine has "-EncodedCommand"

// Sort ascending for timelines — read events in the order they happened
| sort by TimeGenerated asc

// Sort descending for most-recent-first triage
| sort by Count desc

// Limit results — use while building queries, remove for full results
| take 10
```

> **Pro Tip:** Always add `| take 10` while writing a new query. Remove it once you are satisfied the query is correct. Broad unfiltered queries against large tables can run for minutes.

---

## Common Red Flags

### Authentication

| Signal | What It Means |
|---|---|
| `ResultType == 0` + `RiskLevelDuringSignIn == "high"` | Successful sign-in that Entra flagged as suspicious — attacker got in |
| Many `ResultType != 0` from one IP, then `ResultType == 0` | Password spray that succeeded |
| `ResultType == 53003` | Authentication succeeded but CA policy blocked access — credentials are valid |
| Sign-in from `185.220.x.x` range | Tor exit node — attacker hiding origin |

### Processes

| Signal | What It Means |
|---|---|
| `ProcessCommandLine has "-EncodedCommand"` | Base64 encoded PowerShell — evasion intent |
| `winword.exe` or `excel.exe` spawning `powershell.exe` | Office macro exploit |
| `certutil.exe` with `http` in command line | File download via LOLBAS technique |
| `explorer.exe` spawning `powershell.exe` | Suspicious — user may have executed malware |

### Files

| Signal | What It Means |
|---|---|
| `.exe` created in `\Temp\` or `\AppData\Local\Temp\` | Malware staging before execution |
| `.ps1` or `.bat` in `\ProgramData\` | Persistence or staged script |

### Registry

| Signal | What It Means |
|---|---|
| Write to `\CurrentVersion\Run` from temp path | Malware persistence via Run key |
| Service installed from `\Temp\` | Malicious service installation |

### Cloud Activity

| Signal | What It Means |
|---|---|
| `InboxRuleCreated` after anomalous sign-in | Account takeover — attacker setting up email forwarding |
| Bulk `FileDownloaded` after risky authentication | Data exfiltration in progress |
| `RoleAssigned` after anomalous sign-in | Privilege escalation attempt |

---

## Cross-Domain Entity Pivots

These are the join keys that connect telemetry across domains. This is how single-domain ambiguous signals become confirmed attack chains.

```
Email → Identity
─────────────────────────────────────────────────────────────────
RecipientEmailAddress  (UrlClickEvents)
       ==  UserPrincipalName  (SignInLogs)

Question: did the user who clicked a phishing URL authenticate from an anomalous IP?


Identity → Endpoint
─────────────────────────────────────────────────────────────────
UserPrincipalName  (SignInLogs)
       ==  AccountName  (DeviceProcessEvents)

Question: did the compromised account run suspicious commands after authentication?


Endpoint → Network
─────────────────────────────────────────────────────────────────
InitiatingProcessFileName + DeviceId  (DeviceNetworkEvents)

Question: did the suspicious process reach out to an external IP?


Identity → Cloud
─────────────────────────────────────────────────────────────────
UserPrincipalName  (SignInLogs)
       ==  AccountId  (CloudAppEvents)

Question: did the compromised account access files or create forwarding rules?
```

---

*Part of the [Microsoft SOC Analyst Portfolio](../README.md) — MyDFIR 30-Day Challenge*
