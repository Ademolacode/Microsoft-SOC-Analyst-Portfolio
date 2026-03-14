# Phase 3 - Endpoint Detection and Response

**Lab phase:** Endpoint Security  
**Tool:** Microsoft Defender for Endpoint  
**Tables:** `DeviceInfo`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceEvents.`  
**Techniques:** T1059.001 (PowerShell), T1547.001 (Registry Run Keys), ASR rule validation

These queries were built to investigate the `mydfir` test endpoint after onboarding it to Defender for Endpoint and running Atomic Red Team simulations.

The most important lesson from this phase: endpoint telemetry is powerful but context-dependent. A PowerShell execution looks identical whether it belongs to a legitimate administrator or an attacker using stolen credentials and that ambiguity is the problem that the cross-domain queries in Phase 4 solve — and why endpoint analysis alone is never enough.

---

## Query 3.1 - Device Overview

Run this immediately after onboarding any device. Check its risk level, onboarding status, and who is currently logged on before running any detections.

```kql
DeviceInfo
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    DeviceName,
    OSPlatform,
    OSBuild,
    OnboardingStatus,
    IsAzureADJoined,
    LoggedOnUsers
| sort by TimeGenerated desc
| take 5
```

**What I found:** The device already had a Medium risk classification when I checked it, 2 active alerts, and 1 incident before I had deliberately run any attack simulations. This was expected because the device had been generating authentication telemetry in earlier phases that MDE had already classified as suspicious. Rather than dismissing this, I used it as a first investigation exercise and reviewed the device timeline immediately.

---

## Query 3.2 -  Process Execution Timeline Baseline

Run this early in any endpoint investigation to understand what normal activity on this device looks like before narrowing to suspicious processes.

```kql
DeviceProcessEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

> **Pro Tip:** Sort ascending (`asc`) when building timelines. You want to read events in the order they happened, not most-recent-first.
>
> `InitiatingProcessFileName` shows the parent process — this is how you spot suspicious parent-child chains like `winword.exe` spawning `powershell.exe`.

---

## Query 3.3 - PowerShell Execution with Evasion Flag Detection

PowerShell is the most common attacker tool in Windows environments. This query finds all PowerShell executions and adds an `IsEncoded` flag for commands that show evasion indicators.

```kql
DeviceProcessEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| extend IsEncoded = ProcessCommandLine has_any (
    "-EncodedCommand", "-enc", "-e ",  // Base64 encoded execution
    "-NonInteractive",                  // Suppresses interactive prompts
    "-WindowStyle Hidden",              // Hidden window — evasion
    "iex",                              // Invoke-Expression
    "DownloadString",                   // Download and execute
    "DownloadFile"                      // File download
)
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    AccountName,
    InitiatingProcessFileName,
    IsEncoded
| sort by TimeGenerated asc
```

**What I found in the Atomic Red Team simulation:** T1059.001 generated a PowerShell execution with an `-EncodedCommand` flag. The command itself was part of the test and benign, but the encoding pattern is exactly what MDE flagged for the alert.

**Important nuance:** Encoded PowerShell is not automatically malicious — many legitimate enterprise tools encode commands for safe transmission. Look at the decoded command and the initiating process to make the call. To decode base64 PowerShell:

```kql
// Decode the base64 string in-query using KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-EncodedCommand"
| extend Base64String = extract(@"-[Ee]nc(?:odedCommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend DecodedCommand = base64_decode_tostring(Base64String)
| project TimeGenerated, AccountName, ProcessCommandLine, DecodedCommand
```

---

## Query 3.4 - Suspicious Parent-Child Process Relationships

Office applications spawning shells, browsers spawning scripts, or anything unexpected launching PowerShell is a strong indicator of macro exploitation or drive-by compromise.

```kql
DeviceProcessEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe",   // Word macro execution
    "excel.exe",     // Excel macro execution
    "outlook.exe",   // Outlook script execution
    "explorer.exe",  // User executed something suspicious
    "mshta.exe",     // HTML application host — common dropper
    "wscript.exe",   // Windows Script Host
    "cscript.exe"    // Command-line Script Host
)
| where FileName in~ (
    "powershell.exe", "cmd.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "certutil.exe"
)
| project
    TimeGenerated,
    InitiatingProcessFileName,  // Parent
    FileName,                   // Child
    ProcessCommandLine,
    AccountName,
    FolderPath
| sort by TimeGenerated asc
```

> **Pro Tip:** `explorer.exe` spawning `powershell.exe` is not always malicious — users do run things from Explorer. However, `winword.exe` or `excel.exe` spawning any shell process is almost always suspicious unless you have a confirmed VBA macro development environment. Treat it as high-priority until proven otherwise.

---

## Query 3.5 - Registry Run Key Modifications (Persistence Detection)

This is what T1547.001 tests. Attackers write to Run keys to survive reboots and maintain access. ASR rules blocked this in the lab — but this is the query that would catch it if ASR was disabled or not yet propagated.

```kql
DeviceRegistryEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| where RegistryKey has_any (
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\SYSTEM\\CurrentControlSet\\Services"         // Service installation
)
| project
    TimeGenerated,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,              // What was written — often a file path or command
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**What to look for in `RegistryValueData`:**
- Paths to temp directories: `\Temp\`, `\AppData\Local\Temp\`, `\ProgramData\`
- Base64 encoded strings — long random-looking character sequences
- PowerShell or cmd commands embedded directly

Legitimate software rarely writes to Run keys from temp directories.

---

## Query 3.6 - Files Created in Suspicious Locations

Malware almost always stages files to temp or world-writable directories before executing. This query catches the drop step before execution happens.

```kql
DeviceFileEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath has_any (
    @"\Temp\",
    @"\AppData\Local\Temp\",
    @"\AppData\Roaming\",
    @"\ProgramData\",
    @"\Users\Public\"
)
| where FileName endswith ".exe"
    or FileName endswith ".dll"
    or FileName endswith ".ps1"
    or FileName endswith ".bat"
    or FileName endswith ".vbs"
    or FileName endswith ".zip"   // Data staging
| project
    TimeGenerated,
    FileName,
    FolderPath,
    FileSize,
    SHA256,                       // Primary hash — use for VirusTotal lookup
    AccountName,
    InitiatingProcessFileName
| sort by TimeGenerated asc
```

> **Pro Tip:** SHA256 is your primary hash for threat intelligence lookups. Once you have it, search it in VirusTotal, MDE's threat intelligence, or your SOAR platform.
>
> A clean VirusTotal result does not mean the file is safe — it may be newly compiled or purpose-built for this specific target.

---

## Query 3.7 - Outbound Network Connections from Suspicious Processes

After finding a suspicious process, pivot to network activity. Did it reach out to an external IP? That is your C2 or exfiltration confirmation.

```kql
DeviceNetworkEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ (
    "powershell.exe", "cmd.exe", "pwsh.exe",
    "certutil.exe", "bitsadmin.exe",      // Native download tools
    "mshta.exe", "wscript.exe"
)
| where RemoteIPType == "Public"          // External connections only
| project
    TimeGenerated,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    AccountName
| sort by TimeGenerated asc
```

**What to look for in `RemoteIP`:**
- Tor exit node ranges (`185.220.x.x`)
- IPs with no reverse DNS resolution — common for malware infrastructure
- Connections on unusual ports: `4444`, `8080`, `443` from non-browser processes
- Periodic connections at regular intervals (beaconing behaviour)

---

## Query 3.8 - ASR Rule Enforcement Validation

After deploying ASR rules via Intune, this query confirms they are actually generating block events on the device. A policy showing as applied in Intune is not the same as a policy being enforced on the endpoint.

```kql
DeviceEvents
| where DeviceName =~ "mydfir"
| where TimeGenerated > ago(7d)
| where ActionType has "AsrBlocked"
| project
    TimeGenerated,
    ActionType,
    FileName,
    FolderPath,
    ProcessCommandLine = AdditionalFields,
    AccountName
| sort by TimeGenerated desc
```

**Note from the lab:** ASR block events did not appear until after a device reboot following the Intune policy sync. If you deploy ASR rules and see no block events after simulating the relevant techniques, check whether the device has completed a full policy cycle sync, and a reboot is required before enforcement becomes visible in telemetry.

---

*← Phase 2: [Email Security and Phishing Investigation](02-email-phishing-investigation.md)*  
*Phase 4 → [Identity and Cross-Domain Correlation](04-identity-crossdomain.md)*  
*Back to [Query Index](00-quick-reference.md)*
