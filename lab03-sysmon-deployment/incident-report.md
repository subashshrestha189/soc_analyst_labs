# SOC Incident Report

**Alert Name:** Suspicious Process Chain - WINWORD.EXE spawning powershell.exe on FIN-LAPTOP-07

**Date/Time:** 2:47 PM

**Severity:** Critical (WINWORD launching PowerShell, all three evasion flags together, a pattern consistent
with known macro-based phishing attack.

**Affected Host:** FIN-LAPTOP-07

**Affected User:** k.chen

**Source/Destination IP:** Unknown (not captured by this Sysmon event; not yet investigated)

**Indicators of Compromise:** 
  - Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  - ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  - CommandLine: powershell.exe -nop -w hidden -enc [Base64 payload]

**Timeline:** 2:47 PM

**Investigation Findings:** Sysmon event ID 1 was observed on host FIN-LAPTOP-07, user k.chen on normal day
time 2:47 PM. Looking at Image and ParentImage, it suggests WINWORD.EXE launching powershell.exe which is
a direct red flag and also CommandLine has three known attack flags -nop, -w hidden and -enc which normal
user don’t need. Source IP was not yet confirmed and also whether user clicks any email attachment after
2:47 PM is pending.  

**MITRE ATT&CK Mapping:** 

| Stage | Tactic | Technique | ID |
| :--- | :--- | :--- | :--- |
| **Attachment delivered via email (hypothesized, unconfirmed)** | Initial Access | Spearphishing Attachment | T1566.001 |
| **User opens attachment, enables macro** | Execution | User Execution: Malicious File | T1204.002 |
| **Macro runs** | Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 |
| **Macro spawns PowerShell** | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| **Encoded/hidden command line** | Stealth | Obfuscated Files or Information | T1027 |

**Impact:** If user had clicked the malicious attachment then it would lead to initial access and privilege access further.

**Recommended Actions:** 
- Decode the Base64 – EncodedCommand to determine the PowerShell payload’s actual intent.
-	Verify whether the user clicks any attachment after 2:47 PM.
-	Isolate the host from the network.
-	Disable/Restrict the user k.chen account if decoding/verification confirms malicious intent.

**Final Conclusion:** This activity is directly suggesting the attacker tries to gain initial access by
spawning PowerShell from Word document. Need to verify whether the user clicked any attachment afterwards.
Escalated to Tier 2 for deeper investigation. 

*This report is prepared as part of a home SOC lab (lab03-sysmon-deployment) which focuses on the case-
study scenario, distinct from the hands-on Sysmon deployment documented in this lab's README.*
