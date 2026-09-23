# SOC Incident Report

**Alert Name:** Custom Rule 100010 — Possible Brute Force Attack (5+ Failed Windows Logons in 60 Seconds)

**Date/Time:** September 23, 2026

**Severity:** High (Rule Level 12) - custom-tuned threshold, escalated above Wazuh's default correlation
  sensitivity for this event type

**Affected Host:** windows-victim

**Affected User:** Windows 10 x64

**Source IP:** 127.0.0.1 

**Indicators of Compromise:**
  - 4 times Windows Event ID 4625 (logon failure - unknown user or bad password, Wazuh rule 60122) against
    the same target account within a 60 second window.
  - 1 time Wazuh custom correlation alert (rule 100010, level 12) fired as a result
  - Followed by 1 time successful logon (Wazuh rule 60118).

**Timeline:** Multiple failed logon attempts (rule 60122) recorded at level 5 each between 15:44:12 to
  15:44:20 and at 15:44:25, successful logon (rule 60118) recorded at level 3. Custom rule 100010 recorded
  at 15:44:23, correlating the failed attempts.

**Investigation Findings:** 
This activity was created as a controlled test of a custom Wazuh detection rule designed to fix the gap
identified in Wazuh's default ruleset: individual failed Windows logons (rule 60122) are logged at a low 
severity (level 5) and do not, by default, escalated to high severity alert unless the higher frequency
threshold than 5 attempts is met.

The custom rule (ID 100010) correlates repeated 60122 events against the same targetUserName field within
a 60-second window, firing at level 12. Wazuh promotes the triggering event directly into the correlated
100010 alert rather than logging it separately, so the Dashboard event sequence correctly shows 4
standalone 60122 entries followed by the alert — not 5 plus the alert.

The source IP field shows 127.0.0.1 since the attack happened using the local console logon (logon to the
VM through direct access) and not remotely through the network as seen in the Logon Type 2 attack
investigated manually in Lab 01. That is why the correlation is based on targetUserName and not source IP 
since source IP is unreliable when it comes to local logon attacks.

MITRE ATT&CK framework of the alert was automatically generated through the configuration of the rule using
<mitre>.

**MITRE ATT&CK Mapping:** 

Tactic | Technique | ID |
| :--- | :--- | :--- |
| Credential Access  | Brute Force: Password Guessing | T1110.001 |

**Impact:** 
This lab is done in a controlled environment as there was no actual intrusion because the system was not
breached in any way. In a real-world scenario, this pattern should be immediately verified as to whether
the successful login was conducted by the owner of the account as per the findings in Lab 01 incident report.

**Recommended Actions:** 
- In a real deployment, verify that the account owner was the one who logged on successfully after
  unsuccessful logins.
- Always validate the default SIEM ruleset thresholds using attacker's real behavior rather than thinking
  that the OOTB rules are enough for all cases.
  
**Final Conclusion:** This report highlights that a detection rule has been successfully validated which
addresses a gap in the existing brute force alerting sensitivity. The rule will fire accurately at the
configured threshold level of 5 failures in 60 seconds. It also auto-populates the MITRE ATT&CK Tactic
technique mapping (T1110.001, Credential Access). No further steps are required to be done as far as the 
rule is considered validated and ready for use in other labs.

_This report has been prepared in my own home SOC Lab environment. Unlike labs 02-04, this report documents
a real alert generated from my own environment and custom detection rule, not a provided case-study scenario._
