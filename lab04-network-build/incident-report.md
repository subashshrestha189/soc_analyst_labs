# SOC Incident Report

**Alert Name:** Microsoft SQL Server OPEN in Firewall log on host DB-SRV-01

**Date/Time:** 03:02:11 to 03:02:14

**Severity:** Critical (Microsoft SQL Server database is reachable from internet)

**Affected Host:** DB-SRV-01

**Affected User:** Unknown

**Source IP:** 198.51.100.23

**Destination IP:** 10.20.5.15

**Indicators of Compromise:** Port 1433 (Microsoft SQL Server) is being reached from the Internet

**Timeline:** Scan burst across 6 ports observed 03:02:11–03:02:12; port 1433 (SQL Server) allowed at 
03:02:12, immediately following the scan.

**Investigation Findings:** Active scanning was observed on host DB-SRV-01 (10.20.5.15) from IP 
198.51.100.23 which is public internet IP and port 1433 (Microsoft SQL Server) was allowed which is 
concerning because the role of this server is aligned with the functionality of host. User is yet to be 
investigated. 

**MITRE ATT&CK Mapping:** 

| Stage | Tactic | Technique | ID |
| :--- | :--- | :--- | :--- |
| Scanning  | Reconnaissance | Vulnerability scanning | T1595.002 |

**Impact:** After scanning, if there was any authentication to SQL Server, then it could lead to 
compromise of the information and access to the network. 

**Recommended Actions:** 
- Immediately verify whether there was any authentication to SQL Server from 198.51.100.23.
- Check on Threat Intel about the source IP’s status.
- Should apply firewall/security group rule change to remove port 1433 from public internet exposure.
-	Escalate to Tier 2 as the SQL Server port is reachable from the internet.

**Final Conclusion:** This activity is suggesting the attacker is able to know the open port that aligns with the 
functionality of host. Verifying whether there was any authentication to SQL Server from source IP 
198.51.100.23 after scan is yet to be investigated. Although the open port 1433 suggests this is 
concerning matter, thus, escalated to Tier 2 to investigate more deeply.

*This report is prepared as part of a home SOC lab (lab04-network-build) which focuses on the case-
study scenario, distinct from the hands-on nmap scan documented in this lab's README.*
