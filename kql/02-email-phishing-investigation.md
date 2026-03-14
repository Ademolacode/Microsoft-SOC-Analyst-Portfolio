# Phase 2 - Email Security and Phishing Investigation

**Lab phase:** Email Security  
**Tool:** Microsoft Defender for Office 365  
**Tables:** `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `EmailAttachmentInfo`  
**Techniques:** T1566.002 (Spearphishing Link)

These queries were built to investigate the phishing simulation where David Book received a spoofed file-sharing email from `officence[.]com`.

The core challenge with phishing investigation: the email domain can tell you a message was delivered and a URL was clicked, but its visibility ends the moment the user leaves the inbox. For everything that happens after credential use, endpoint activity, you need the identity domain. Query 2.6 at the end of this file makes that connection.

---

## Query 2.1 - Email Delivery to a Target User

Starting point for any phishing investigation. Find the message first, then work outward.

```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where RecipientEmailAddress =~ "david.book@cyberletcode.onmicrosoft.com"
| project
    TimeGenerated,
    SenderFromAddress,
    SenderFromDomain,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    ThreatTypes,
    DetectionMethods
| sort by TimeGenerated desc
```

> **Pro Tip:** Always use `=~` (case-insensitive) for email addresses. They can be stored in mixed case depending on the source system. Using `==` will miss them.
>
> `DeliveryAction` tells you what MDO did: `Delivered`, `Blocked`, or `Quarantined`. If it shows `Delivered`, the user had access to the message regardless of what `ThreatTypes` shows.

---

## Query 2.2 - Sender Domain Investigation

Once you have a suspicious sender domain, check how many messages came from it and who else received them.

```kql
EmailEvents
| where TimeGenerated > ago(30d)
| where SenderFromDomain =~ "officence.com"
| summarize
    TotalMessages = count(),
    UniqueTargets = dcount(RecipientEmailAddress),
    Recipients    = make_set(RecipientEmailAddress, 20)
    by SenderFromAddress, SenderFromDomain
| sort by TotalMessages desc
```

**What to look for:** A newly registered lookalike domain hitting multiple recipients in a short window is a strong phishing indicator. If `UniqueTargets > 5`, this is likely a campaign, not a one-off message.

---

## Query 2.3 - URLs Embedded in Suspicious Emails

After identifying the phishing message, extract the URLs it contained. These become your IOCs for threat intelligence lookups.

```kql
EmailUrlInfo
| where TimeGenerated > ago(7d)
| where NetworkMessageId in (
    EmailEvents
    | where SenderFromDomain =~ "officence.com"
    | project NetworkMessageId
)
| project
    TimeGenerated,
    Url,
    UrlDomain,
    UrlLocation,  // Header, Body, or Attachment
    ActionType    // Whether MDO acted on it
| sort by TimeGenerated desc
```

> **Pro Tip:** Always defang URLs when documenting IOCs in reports or tickets. This prevents accidental clicks.
>
> `https://malicious.com` → `hxxps://malicious[.]com`

---

## Query 2.4 — URL Click Events (Did the User Click?)

This is the most important email query. `ClickAllowed` means the user actually followed the link; this event is what triggers the cross-domain pivot to identity logs.

```kql
UrlClickEvents
| where TimeGenerated > ago(7d)
| where RecipientEmailAddress =~ "david.book@cyberletcode.onmicrosoft.com"
| project
    TimeGenerated,
    RecipientEmailAddress,
    Url,
    UrlDomain,
    ActionType,       // ClickAllowed = followed; ClickBlocked = Safe Links stopped it
    IsClickedThrough, // true = user actually navigated to the destination page
    WorkloadName      // Email, Teams, or Office
| sort by TimeGenerated desc
```

**What I found in the simulation:**

David Book clicked at T+6 minutes after delivery. `ActionType` was `ClickAllowed` because `officence[.]com` was not yet in the threat intelligence feed at delivery time. `IsClickedThrough = true` confirmed he navigated to the page.

This `UrlClickEvents` entry is the entity that links the email investigation to the identity investigation. `RecipientEmailAddress` is the join key; it matches `UserPrincipalName` in `SignInLogs`.

---

## Query 2.5 - Campaign Scope Check

After confirming one victim, always check whether others received the same email. Phishing campaigns rarely target a single mailbox.

```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromDomain =~ "officence.com"
    or Subject has_any ("Expenses Report", "Payroll Update", "Invoice", "Shared with you")
| summarize
    RecipientCount = dcount(RecipientEmailAddress),
    Recipients     = make_set(RecipientEmailAddress, 50),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated)
    by SenderFromDomain, Subject
| sort by RecipientCount desc
```

> **Pro Tip:** `has_any()` lets you search for multiple subject keywords in a single clause without chaining `or` conditions. The subjects listed above are common social engineering patterns — file sharing urgency, financial urgency, HR actions. Adapt the list to the campaign you are investigating.

---

## Query 2.6 - Cross-Domain: Phishing Click to Authentication Anomaly

This is the query that closes the detection gap. The email domain sees the click. The identity domain sees the sign-in. Neither is individually actionable, and they confirm credential theft.

```kql
// Step 1: Capture the phishing click event
let PhishingClicks =
    UrlClickEvents
    | where TimeGenerated > ago(24h)
    | where ActionType == "ClickAllowed"
    | where IsClickedThrough == true
    | project
        ClickTime      = TimeGenerated,
        RecipientEmail = RecipientEmailAddress,
        ClickedUrl     = Url,
        ClickedDomain  = UrlDomain;

// Step 2: Find anomalous sign-ins within 30 minutes of a click
SignInLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0                                    // Successful authentication only
| where RiskLevelDuringSignIn in ("medium", "high")        // Entra ID flagged as suspicious
    or IPAddress matches regex @"185\.220\."               // Tor exit node range
| join kind=inner PhishingClicks
      on $left.UserPrincipalName == $right.RecipientEmail  // Same user in both domains
| where TimeGenerated between (ClickTime .. (ClickTime + 30m))
| extend MinutesBetweenClickAndAuth =
      datetime_diff("minute", TimeGenerated, ClickTime)
| project
    ClickTime,
    SignInTime                 = TimeGenerated,
    MinutesBetweenClickAndAuth,
    UserPrincipalName,
    ClickedUrl,
    ClickedDomain,
    IPAddress,
    RiskLevel                  = RiskLevelDuringSignIn,
    Location                   = LocationDetails
| sort by ClickTime asc
```

**What a result means:** The same person who clicked a suspicious URL authenticated from a high-risk IP within your time window. This is a likely credential compromise — escalate immediately and check `SignInLogs` for what the account did after authentication.

**Tuning:**
- Narrow the time window from `30m` to `10m` for higher precision at the cost of lower recall
- Add known corporate VPN IP ranges to an exclusion list to reduce false positives from legitimate remote workers

---

*← Phase 1: [Authentication Baseline](01-authentication-baseline.md)*  
*Phase 3 → [Endpoint Detection](03-endpoint-detection.md)*  
*Back to [Query Index](00-quick-reference.md)*
