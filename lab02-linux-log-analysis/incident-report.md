# SOC Incident Report

**Alert Name:** Multiple Failed Logon Attempts on Different Usernames – webserver-03

**Date/Time:** 03:14:02 AM – 03:15:50 AM

**Severity:** Rated Low due to zero successful authentications observed; would escalate to Medium if this IP is later associated with a successful login or appears in threat intel as known-malicious.

**Affected Host:** webserver-03

**Affected User:** NULL

**Source IP:** 203.0.113.55

**Destination port:** 22 

**Indicators of Compromise:** Failed password for 40+ usernames from same IP

**Timeline:** between 03:14:02 AM – 03:15:50 AM

**Investigation Findings:** Failed password for 40+ usernames, all with same IP, were observed indicating either password spraying (credential access) or account discovery/gather victim identity information (reconnaissance). We couldn’t confirm which one the attacker tried as we can’t see the password value in the log. There was no successful login though.  

**MITRE ATT&CK Mapping:** Tactic: Credential Access, Technique: Password Spraying OR Tactic: Reconnaissance, Technique: Gather victim identity information.

**Impact:** If the attacker gain successful login, then it could lead to privilege access or lateral movement.

**Recommended Actions:** 
-	Verify no successful login occurred for any of 40+ attempted usernames 
-	Check 203.0.113.55 against threat intel (VirusTotal, AbuseIPDB) for known malicious history.
-	Consider adding firewall rule or Fail2ban block if this source continues generating failed attempts across future days.

**Final Conclusion:** This activity is either (a) credential access attempt with password spraying, or (b) account discovery/gather victim account information. Escalated to Tier 2 for deeper investigation on source IP 203.0.113.55. 

*This report is prepared as part of a home SOC lab (lab02-linux-log-analysis) which focuses on the case-study provided, distinct from the hands-on brute-force attack lab documented in this lab's README.*
