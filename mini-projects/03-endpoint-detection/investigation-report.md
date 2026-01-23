# 🖥️ Endpoint Detection & Response Investigation Report  
**Mini Project #3 – Defender for Endpoint**

---

## Findings (What did you find)

- **Time Window:** 2026-01-22 02:16:36 UTC – 04:09:20 UTC  
- **Device:** mydfir (Windows 11 test VM)  
- **User Accounts Observed:**  
  - david.book@CyberLetcode.onmicrosoft.com  
  - mydfir@CyberLetcode.onmicrosoft.com  
- **Primary Alerts:**
  - Suspicious PowerShell command line  
  - Compromised account conducting hands-on-keyboard attack  
  - Sensitive information theft activity via Security Account Manager  
  - Registry-based persistence attempt  
- **Severity:** Medium to High  
- **Detection Source:** Microsoft Defender for Endpoint  
- **Status:** Activity blocked, no persistence established  

---

## Investigation Summary (What happened)

On January 22, 2026, Microsoft Defender for Endpoint generated multiple alerts on a Windows 11 test endpoint following controlled adversary simulation.

The activity included encoded PowerShell execution, attempted registry-based persistence, and credential access behavior consistent with hands-on-keyboard attack techniques. Attack Surface Reduction (ASR) rules successfully blocked the malicious actions, preventing persistence and lateral movement.

Device timeline analysis confirmed the activity was contained to a single endpoint, with no evidence of follow-on compromise or spread to other assets.

---

## Who, What, When, Where, Why, How

### Who  
- User accounts: david.book@CyberLetcode.onmicrosoft.com, mydfir@CyberLetcode.onmicrosoft.com  
- Device: mydfir (Windows 11 test VM)  

### What  
- Attempted PowerShell-based execution and registry persistence  
- Credential access behavior targeting the Security Account Manager  

### When  
- January 22, 2026 between 02:16 UTC and 04:09 UTC  
- Activity is no longer ongoing  

### Where  
- Single Windows 11 endpoint onboarded to Defender for Endpoint  

### Why  
- Controlled adversary simulation to validate endpoint detection and response capabilities  

### How  
- PowerShell executed with encoded command-line arguments  
- Attempted modification of registry Run keys for persistence  
- ASR rules detected and blocked the activity  

---

## Validation Steps Performed

- Reviewed Defender for Endpoint alert details and severity context  
- Analyzed device timeline for process, registry, and authentication activity  
- Confirmed ASR rule enforcement through block events  
- Queried for similar PowerShell activity across other devices  
- Verified no lateral movement or additional compromised endpoints  

---

## Recommendations

- Maintain ASR rules in block mode for execution and persistence-related techniques.
- Review PowerShell usage baselines to distinguish administrative activity from abuse.
- Restrict PowerShell execution to approved users or scripts where feasible.
- Periodically validate endpoint security controls using controlled simulations.
- Expand hunting queries to include lateral movement techniques such as RDP, WMI, and PsExec.

---

## Conclusion

This investigation confirmed that Defender for Endpoint telemetry and ASR controls functioned as intended. The simulated attack was detected early, blocked before persistence could be established, and fully contained to a single endpoint.

The exercise reinforced the importance of validating endpoint controls through direct testing and correlating multiple telemetry sources during investigations.

---
## Notes

ASR policies showed as applied in Intune but did not immediately generate block events. Enforcement became visible after policy sync and device reboot, highlighting expected propagation delays in endpoint control validation.
