**SOC Incident Report**

**Alert Name:** Multiple Failed Logon Attempts Followed by Successful Authentication – WKSTN-042
**Date/Time:** 09:14:02 AM – 09:14:51 AM
**Severity:** Critical (pending verification)
**Affected Host:** WKSTN-042
**Affected User:** j.martinez
**Source and Destination IP:** Unknown
**Indicators of Compromise:** 5 Event ID 4625 (all with sub status 0xC000006A followed by one Event ID 4624 (logon type 2)
**Timeline:** | Time | Event |
| :--- | :--- |
| **09:14:02 – 09:14:47** | 5 consecutive failed logon attempts (Event ID 4625) against account `j.martinez` |
| **09:14:51** | Successful logon (Event ID 4624), Logon Type 2 |
**Investigation Findings:** 5 successful Event ID 4625 failures were observed against account j.martinez, 
all with sub-status 0xC000006A (incorrect password), indicating brute forcing.
This was followed by successful Event ID 4624 with Logon Type 2 (interactive/console).
The console logon type is inconsistent with a typical remote brute force pattern, which would normally present as Logon Type 3 or 10. Source/Workstation field was not yet examined to confirm whether the successful logon originated locally at WKSTN-042. User contact and end verification are pending.
**MITRE ATT&CK Mapping:** 5 failed logon attempts suggest Tactic (credential access) & Technique (brute-force) and final successful login suggests Tactic (initial access) & Technique (valid account)
**Impact:** this access can lead to privilege access (if it is legitimate attack)
**Recommended Actions:** Disable the user account and isolate the affected host and reach out to the user to confirm whether he is the one who logged in after 14 attempts
**Final Conclusion:** Activity is consistent with either (a) a brute-force attempt that succeeded, or (b) legitimate user error (e.g., forgotten password/Caps Lock) with no malicious intent. Escalated to Tier 2 for host-level verification and user contact. Account will remain under close monitoring until confirmed benign.
