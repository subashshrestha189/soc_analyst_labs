**Objective**

Until now, I have collected different IOCs across Labs 1-9 such as IP addresses, suspicious domains, and file
hashes. In this lab, we focus on what to do with those IOCs and determine how reliable the answer is. We
will conduct searches on public threat intelligence platforms and evaluate whether external security teams
have observed these indicators previously and assess the reliability and confidence score of those findings.
Also, we map all the techniques I practiced to MITRE ATT&CK, measure how well my home SOC detected each one
and decide which gaps to close first. 


**Lab Environment**

This lab is solely performed in Browser, no new VMs needed. VirusTotal, AbuseIPDB, urlscan.io, MITRE
ATT&CK Navigator are used. 

  IOCs (Labs 1-9)       -> enrichment (VirusTotal, AbuseIPDB, urlscan, WHOIS)
  Techniques (Labs 1-9) -> ATT&CK Navigator layer (alerted / logged only / hypothesized)
  Gaps                  -> prioritized detection backlog
      
**Methodology**

1.  IOCs enrichment
  • Looked up EICAR test file on VirusTotal. Most engines flag it as malicious, yet it is a harmless, so a
  high detection ratio alone is not an incident. Context decides whether it is an legitimate test or not?
  • Looked up 8.8.8.8 as a clean baseline (owned by Google). Clean reputation only tells you about ownership,
  not the activities on that address on the network.
  • Looked up the fictional indicators from my case studies. These returned no results since they are reserved
  (such as .example domain names and documentation IPs (198.51.100.0/24, 203.0.113.0/24 and these addresses
  will never actually be used in the internet).
2. Pivot reasoning. The same fictional IP appears in two case studies. In a real SOC this overlap means we have
   to look every log source but should not conclude "it's the same attacker" because shared hosting, VPNs, and
   reused infrastructure might put multiple actors on one IP.
3. Labs 1-9 were mapped to ATT&CK and each technique was scored according to how it was discovered: alerted
   (an automated alert fired), logged only (evidence in logs, no alert), or hypothesized (inferred, not
   observed). Built an ATT&CK Navigator layer from the result.
4. Prioritized detections by impact, fidelity, and feasibility and wrote specifications for the top items
   (see _detection-backlog.md)._

**Key Findings**

1. Clean is not safe. No reputation data can mean a brand new or targeted indicator. Reputation is
   supporting evidence, never the verdict.
2. Detection status must be recorded per technique, by the tool that detected it. Wireshark and Zeek recorded
   traffic but produced no alerts, Suricata alerted on the scan, Sysmon only saw PowerShell and encoded-command
   steps, while three other Lab 3 techniques were inferred.
3. Coverage is uneven. Brute force and scanning (T1110.001, T1595.002) were alerted. The Lab 9 account
   takeover chain (T1078, T1114.003, T1564.008) was visible in logs but produced no alert and the detection
   was a user report.
4. Set priorities based on impact, fidelity and feasibility, not only by "no alert". T1592.002 was a weak
   candidate because its traffic is already covered under T1595.002 Lab 8 scan activity. T1566.002, T1078
   were stronger.
5. A correlation beats a single signal. Signing in from a foreign country is noisy on its own but it is
   crucial if it comes after POST to phishing domain.

**Limitations**

1. Detection specifications for T1078 are designs only. The home lab has no identity-provider or mailbox
   audit logs to test them.
2. Some case-study techniques are hypothesized, not observed, and are shown separately in the layer.
3. Reputation lookups use fictional indicators for the case studies, so they demonstrate method, not
   real intelligence.

**Skills Demonstrated**

Indicator enrichment and reputation reasoning. Pyramid of Pain. Reserved versus private address ranges.
MITRE ATT&CK mapping. ATT&CK Navigator layers. Detection prioritization. Detection specification writing 
(data source, condition, severity, false positives, response).

_The enrichment and the coverage mapping are hands-on work on my own lab data. No provided case-study
scenario was used in this lab, the case-study indicators come from Labs 2, 4, 8, and 9._



