**Objective**

Implementing Sysmon with a production-style configuration (SwiftOnSecurity's community maintained config) to
get process visibility beyond the capabilities of Windows auditing, and then use that visibility to detect a
simulated "living off the land" attack chain: a legitimate application spawning PowerShell with evasion flags -
the same execution pattern used in real-world macro-based phishing attacks.

**Lab Environment**

VM: Windows 10 (reused from lab01)
Tools: Sysmon64 (Microsoft Sysinternals), SwiftOnSecurity sysmonconfig-export.xml)

_Screeshots are available_

**Skills Gained**

Sysmon deployment and configuration. process chain/parent-child analysis. living-off-the-land (LOTL) technique
recognition. Base64 command-line decoding. multi-stage MITRE ATT&CK mapping. 

_You can see incident-report.md for the complete case-study report (FIN-LAPTOP-07)_
