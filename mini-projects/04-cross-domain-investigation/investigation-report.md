# 🔗 Cross-Domain Incident Investigation Report  
## **Mini Project #4 – Capstone SOC Investigation**

---

## Findings (What did you find)

- **Incident ID:** INC-2026-01-22-001  
- **Time Window:** 2026-01-22 02:11:34 UTC – 04:09:20 UTC  
- **Impacted User:** david.book@CyberLetcode.onmicrosoft.com  
- **Impacted Device:** mydfir (Windows 11 test VM)  
- **Initial Vector:** Phishing email with credential harvesting link  
- **Subsequent Activity:** Risky sign-in, PowerShell execution, persistence attempt  
- **Severity:** High  
- **Detection Sources:** Defender for Office 365, Entra ID, Defender for Endpoint, Microsoft Sentinel  
- **Current Status:** Contained, no persistence or lateral movement detected  

---

## Investigation Summary (What happened)

On January 22, 2026, Microsoft Sentinel correlated multiple security signals across email, identity, and endpoint domains involving a single user and endpoint in the CyberLetcode tenant.

The incident began with a phishing email containing a credential harvesting link. Shortly after, identity telemetry recorded a risky sign-in from an unfamiliar network. Endpoint telemetry then revealed suspicious PowerShell execution and an attempted registry-based persistence mechanism.

Attack Surface Reduction (ASR) rules successfully blocked the persistence attempt. Correlation across telemetry sources confirmed that the attack chain was disrupted before persistence or lateral movement could occur.

---

## Who, What, When, Where, Why, How

### Who  
- User account: david.book@CyberLetcode.onmicrosoft.com  
- Endpoint: mydfir (Windows 11 VM)  

### What  
- Multi-stage attack involving phishing, identity compromise signals, and endpoint execution attempts  

### When  
- January 22, 2026 between 02:11 UTC and 04:09 UTC  
- Activity is no longer ongoing  

### Where  
- Microsoft 365 email environment  
- Entra ID authentication services  
- Defender for Endpoint onboarded device  

### Why  
- Controlled adversary simulation to test cross-domain detection and response capabilities  

### How  
- Phishing email delivered with credential harvesting link  
- Credentials potentially exposed and used for authentication  
- Suspicious PowerShell execution on endpoint  
- Registry-based persistence attempt blocked by ASR  

---

## Attack Chain Reconstruction

| Stage | Technique | Description |
|-----|---------|-------------|
| Initial Access | T1566.002 | Phishing email with malicious link |
| Credential Access | T1056.003 | Credential harvesting via spoofed page |
| Initial Access | T1078 | Valid account authentication |
| Execution | T1059.001 | PowerShell execution |
| Persistence | T1547.001 | Registry Run Keys (blocked) |

---

## Validation Steps Performed

- Reviewed Defender for Office 365 telemetry for phishing delivery and Safe Links actions  
- Analyzed Entra ID sign-in logs for risk level, IP reputation, and authentication context  
- Investigated Defender for Endpoint alerts and device timeline  
- Correlated email, identity, and endpoint telemetry using Sentinel queries  
- Verified no additional impacted users or devices  

---

## Recommendations

- Enforce Conditional Access policies in block mode for high-risk sign-ins.
- Implement MFA enforcement for all user accounts.
- Automate account disablement and device isolation through Sentinel playbooks.
- Expand cross-domain correlation rules for similar attack patterns.
- Continue periodic validation of detection controls using controlled simulations.

---

## Notes

Identity telemetry proved critical in linking the phishing email to endpoint activity. Without cross-domain correlation, the alerts would have appeared isolated and lower risk. This investigation highlighted the importance of time-based correlation and identity signals in modern SOC workflows.

## Conclusion

This capstone investigation demonstrated the ability to correlate email, identity, and endpoint telemetry to reconstruct a complete attack chain. The simulated attack was detected early, contained effectively, and blocked before persistence or lateral movement could occur.

The exercise validated the effectiveness of Microsoft Sentinel and Defender XDR when used together and reinforced the importance of cross-domain visibility in SOC operations.
