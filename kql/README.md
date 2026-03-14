# KQL Detection and Investigation Queries

All queries used during the MyDFIR 30-Day Microsoft SOC Analyst Challenge. Written in order of the investigation phases and built to reflect exactly what was run in the lab, not templates, but documented investigations.

Each file is a markdown document with queries in `kql` code blocks. GitHub renders these with full syntax highlighting.

---

## Files

| File | Phase | What's Inside |
|---|---|---|
| [00-quick-reference.md](00-quick-reference.md) | All phases | Table reference, 4-step method, syntax cheatsheet, red flags, cross-domain pivot keys |
| [01-authentication-baseline.md](01-authentication-baseline.md) | Phase 1 — SOC Foundation | Schema check, EventID distribution, failed logon triage, timeline analysis, brute force success check |
| [02-email-phishing-investigation.md](02-email-phishing-investigation.md) | Phase 2 — Email Security | Email delivery triage, sender investigation, URL extraction, click events, campaign scope, cross-domain phishing-to-auth correlation |
| [03-endpoint-detection.md](03-endpoint-detection.md) | Phase 3 — Endpoint | Device overview, process timeline, PowerShell with evasion detection, parent-child analysis, registry persistence, file drops, network connections, ASR validation |
| [04-identity-crossdomain.md](04-identity-crossdomain.md) | Phase 4 — Identity and Capstone | Risky sign-in triage, account history, CA block events (53003), spray detection, 3-stage spray-to-compromise chain, post-auth cloud activity, LOLBAS with auth context |

---

## The Cross-Domain Join Keys

The most important queries in this collection are the ones that connect data across domains. These are the entity identifiers that make it possible.

```
Email domain          →  Identity domain
RecipientEmailAddress == UserPrincipalName

Identity domain       →  Endpoint domain
UserPrincipalName     == AccountName

Endpoint domain       →  Network domain
DeviceId + Process       DeviceNetworkEvents

Identity domain       →  Cloud domain
UserPrincipalName     == AccountId (CloudAppEvents)
```

Without these joins, each domain produces ambiguous signals. With them, an isolated phishing click and an isolated risky sign-in become a confirmed credential compromise.

---

## Key Finding

> Running `DeviceProcessEvents` alone with a list of suspicious PowerShell commands returns hundreds of rows — all mixed legitimate admin activity with no way to distinguish it from attacker activity.
>
> Joining those same results to `SignInLogs` and filtering to accounts with recent anomalous authentication reduces hundreds of rows to a handful of confirmed high-risk actions.
>
> That reduction is only possible with cross-domain correlation. It is the core finding that this query set was built to demonstrate.

---

*Part of the [Microsoft SOC Analyst Portfolio](../README.md)*
