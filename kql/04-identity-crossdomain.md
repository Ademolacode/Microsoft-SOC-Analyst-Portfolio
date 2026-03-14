# Phase 4 - Identity, Conditional Access and Cross-Domain Correlation

**Lab phase:** Identity and Capstone Investigation  
**Tools:** Microsoft Entra ID, Microsoft Sentinel, Defender XDR  
**Tables:** `SignInLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `CloudAppEvents`, `DeviceProcessEvents`  
**Techniques:** T1078 (Valid Accounts), T1110.003 (Password Spraying), T1059.001 (PowerShell), T1114.003 (Email Forwarding Rule)

This is where the investigation comes together.

The identity domain is the connective tissue between email and endpoint. A phishing email harvests credentials. Those credentials produce an authentication event in Entra ID. That event is the bridge. Without it, you have two ambiguous signals in different domains that look unrelated. With it, you have a confirmed attack chain. These queries go in order from initial triage through full cross-domain reconstruction.

---

## Query 4.1 - Risky Sign-In Triage

Start here when investigating a potential credential compromise. Entra ID's Identity Protection flags anomalous sign-ins automatically, and this query surfaces them for manual review.

```kql
SignInLogs
| where TimeGenerated > ago(24h)
| where RiskLevelDuringSignIn in ("medium", "high")
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location             = LocationDetails,
    RiskLevel            = RiskLevelDuringSignIn,
    RiskDetail           = RiskDetail,
    ResultType,           // 0 = success — anything else = failure
    AppDisplayName,
    DeviceDetail
| sort by TimeGenerated desc
```

**Important:** A high-risk sign-in where `ResultType == 0` is more urgent than one that failed. The attacker has valid credentials and got in. Investigate post-authentication activity immediately.

---

## Query 4.2 - Full Sign-In History for a Specific Account

After identifying a potentially compromised account, pull their complete recent sign-in history to understand the full authentication picture.

```kql
SignInLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "david.book@cyberletcode.onmicrosoft.com"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location               = LocationDetails,
    AppDisplayName,
    ResultType,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus, // Applied / NotApplied / Failure
    AuthenticationRequirement,
    DeviceDetail
| sort by TimeGenerated asc
```

**What I found in the lab:** David Book's sign-ins showed `ConditionalAccessStatus = "Failure"` with error code 53003 after the CA policy was applied, meaning the policy was blocking access at that point. But earlier sign-ins showed `NotApplied`, the account had been accessible without the policy for a window of time before it was configured.

---

## Query 4.3 - Conditional Access Block Events (Error 53003)

This confirms the CA policy fired. It also confirms that authentication *succeeded* before the policy blocked access, which means the credentials were valid and the account was compromised, even if further access was ultimately denied.

```kql
SignInLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "david.book@cyberletcode.onmicrosoft.com"
| where ResultType == 53003  // CA policy blocked token issuance
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    AppDisplayName,
    Location = LocationDetails
| sort by TimeGenerated desc
```

**Key insight:** Error 53003 means authentication succeeded but CA policy blocked access. The credentials were valid, the attacker had the password. CA policy was the only line of defence at that point. This reinforces why MFA should be the first control deployed, not a later addition. CA policy blocking after credential theft is reactive. MFA makes the credentials useless in the first place.

---

## Query 4.4 - Password Spray Pattern Detection

Many failed logons across many accounts from one source IP in a short window is the spray signature. This is what was generating the 18,163 EventID 4625 events observed in Phase 1.

```kql
SignInLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0                     // Failed sign-ins only
| summarize
    FailedAttempts = count(),
    TargetAccounts = dcount(UserPrincipalName),
    AccountList    = make_set(UserPrincipalName, 20),
    FirstAttempt   = min(TimeGenerated),
    LastAttempt    = max(TimeGenerated)
    by IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 20
    and TargetAccounts >= 5                 // Must span multiple accounts
| extend SprayDuration = datetime_diff("minute", LastAttempt, FirstAttempt)
| project
    FirstAttempt,
    LastAttempt,
    SprayDuration,
    IPAddress,
    FailedAttempts,
    TargetAccounts,
    AccountList
| sort by FailedAttempts desc
```

**Spray vs brute force:**

| Pattern | Characteristic | Why It's Harder to Detect |
|---|---|---|
| Brute force | Many attempts against **one** account | Triggers lockout after threshold |
| Spray | Few attempts against **many** accounts | Stays below per-account lockout threshold |

---

## Query 4.5 - Spray to Confirmed Compromise (3-Stage Chain)

Stage 1 identifies the spray. Stage 2 finds whether any attempt succeeded. Stage 3 confirms whether the compromised account then did anything suspicious on an endpoint. This is the query that converts 18,163 authentication events into one confirmed incident.

```kql
// Stage 1: Identify the spray source IP
let SprayIPs =
    SignInLogs
    | where TimeGenerated > ago(2h)
    | where ResultType != 0
    | summarize
        FailedAttempts = count(),
        TargetAccounts = dcount(UserPrincipalName),
        SprayStart     = min(TimeGenerated)
        by IPAddress, bin(TimeGenerated, 10m)
    | where FailedAttempts >= 20 and TargetAccounts >= 5
    | project IPAddress, SprayStart;

// Stage 2: Find any successful authentication from that same IP
let CompromisedAccounts =
    SprayIPs
    | join kind=inner (
        SignInLogs
        | where TimeGenerated > ago(4h)
        | where ResultType == 0
        | project
            SuccessTime = TimeGenerated,
            UPN         = UserPrincipalName,
            IPAddress,
            Location    = LocationDetails
    ) on IPAddress
    | where SuccessTime >= SprayStart   // Success must come AFTER the spray began
    | project
        CompromisedUPN = UPN,
        CompromiseTime = SuccessTime,
        SprayIP        = IPAddress,
        Location;

// Stage 3: Check for suspicious endpoint activity by the compromised account
CompromisedAccounts
| join kind=leftouter (
    DeviceProcessEvents
    | where TimeGenerated > ago(4h)
    | where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
    | project
        ProcessTime = TimeGenerated,
        AccountName,
        DeviceName,
        ProcessName = FileName,
        CommandLine = ProcessCommandLine
) on $left.CompromisedUPN == $right.AccountName
| where isnotempty(DeviceName)         // Only return rows where endpoint activity was found
| where ProcessTime > CompromiseTime   // Activity must come AFTER the compromise
| project
    CompromiseTime,
    ProcessTime,
    MinutesAfterCompromise = datetime_diff("minute", ProcessTime, CompromiseTime),
    CompromisedUPN,
    SprayIP,
    DeviceName,
    ProcessName,
    CommandLine
| sort by CompromiseTime asc
```

---

## Query 4.6 - Post-Authentication Cloud Activity

After confirming a compromised sign-in, check what the account actually did in Microsoft 365. File downloads and inbox rule creation are the two most common immediate post-compromise actions.

```kql
CloudAppEvents
| where TimeGenerated > ago(24h)
| where AccountId =~ "david.book@cyberletcode.onmicrosoft.com"
| where ActionType in (
    "FileDownloaded",
    "FileCopied",
    "FileShared",
    "InboxRuleCreated",        // Persistence — email forwarding
    "MailForwardingRuleSet",   // Explicit forwarding rule
    "MemberAdded",             // Added to groups
    "RoleAssigned"             // Privilege escalation
)
| project
    TimeGenerated,
    AccountId,
    ActionType,
    ObjectName,                // File or resource accessed
    IPAddress,
    Application,
    ActivityObjects
| sort by TimeGenerated asc
```

**Red flag:** `InboxRuleCreated` or `MailForwardingRuleSet` shortly after a risky sign-in is a near-certain indicator of account takeover. The attacker is setting up persistence to continue receiving forwarded emails even after a password reset. Check the forwarding destination address immediately and add it to your IOC list.

---

## Query 4.7 - Living-off-the-Land Commands with Authentication Risk Context

This is the most powerful cross-domain detection in the lab and the one that directly addresses Incident 24.

PowerShell commands that look entirely legitimate in isolation — `Get-LocalUser`, `Get-ChildItem`, `Compress-Archive` — become high-priority when they are run by an account that recently authenticated from a high-risk source. Without this correlation, these commands would never generate an alert. With it, they become the confirmation of a living-off-the-land attack in progress.

```kql
// Step 1: Identify accounts with anomalous recent authentication
let SuspectSessions =
    SignInLogs
    | where TimeGenerated > ago(4h)
    | where ResultType == 0                         // Must have succeeded
    | where RiskLevelDuringSignIn in ("medium", "high")
        or IPAddress matches regex @"185\.220\."    // Tor exit nodes
    | summarize
        LatestRiskyAuth = max(TimeGenerated),
        RiskLevel       = max(RiskLevelDuringSignIn),
        SourceIPs       = make_set(IPAddress)
        by UserPrincipalName
    | project
        SuspectUPN = UserPrincipalName,
        AuthTime   = LatestRiskyAuth,
        RiskLevel,
        SourceIPs;

// Step 2: Find LOLBAS commands executed by those accounts within 2 hours
DeviceProcessEvents
| where TimeGenerated > ago(4h)
| where FileName in~ ("powershell.exe", "cmd.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Get-LocalUser",       // User enumeration
    "Get-LocalGroup",      // Group enumeration
    "Get-ChildItem",       // Directory listing
    "net user",            // Classic enumeration
    "net localgroup",
    "whoami",
    "systeminfo",          // System fingerprinting
    "Compress-Archive",    // Data staging
    "Invoke-WebRequest",   // Download or exfiltration
    "DownloadString",
    "IEX",                 // Invoke-Expression — execute downloaded code
    "EncodedCommand"
)
| join kind=inner SuspectSessions
      on $left.AccountName == $right.SuspectUPN
| where TimeGenerated > AuthTime                  // Command ran AFTER the risky auth
| where TimeGenerated < (AuthTime + 2h)           // Within the monitoring window
| extend MinutesAfterAuth =
      datetime_diff("minute", TimeGenerated, AuthTime)
| project
    TimeGenerated,
    MinutesAfterAuth,
    AccountName,
    DeviceName,
    ProcessName       = FileName,
    CommandLine       = ProcessCommandLine,
    InitiatingProcess = InitiatingProcessFileName,
    AuthTime,
    RiskLevel,
    SourceIPs
| sort by TimeGenerated asc
```

**Why this matters:** Run `DeviceProcessEvents` alone on the same LOLBAS command list, and you get hundreds of rows — all legitimate admin activity mixed with attacker activity, with no way to distinguish them. This query returns only commands run by accounts with anomalous recent authentication. In the Incident 24 investigation, that narrowed hundreds of process events down to a handful of confirmed high-risk actions.

This is the detection that cross-domain correlation uniquely enables. It cannot be replicated from endpoint telemetry alone.

---

*← Phase 3: [Endpoint Detection and Response](03-endpoint-detection.md)*  
*Back to [Query Index](00-quick-reference.md)*
