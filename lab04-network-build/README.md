**Objective**

Build an isolated attacker/victim network setup (Kali + Windows, static IPs), which can act as a common
infrastructure for all future labs, and perform real Nmap port scanning against three separate Windows logs - 
Security log, Sysmon, and Windows Firewall logs to get a better understanding of what is visible from each one
of them.

**Lab Environment**

Attacker machine: Kali Linux

Victim/Target machine: Windows 10

Platform: VMware Workstation, Custom network (VMnet8) with NAT enabled

_Screenshots are also available in this file_

**Skills Gained**

VMware network configuration (static IPs, NAT/Custom networking). Nmap scanning. Windows Firewall logging 
configuration and analysis. TCP SYN-flag pattern recognition. 

_You can see incident-report.md for the complete case-study report (DB-SRV-01 case study)_

_You can see case-study-alert-data.md for provided alert data used_

_NOTE: As with previous labs, this combines hands-on work (my own Nmap scan and multi-source log investigation)
with a separate written case study (the DB-SRV-01 scenario)._
