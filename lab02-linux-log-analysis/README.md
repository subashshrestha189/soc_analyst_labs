**Objective**

Investigate Linux authentication logs (/var/log/auth.log) to detect and analyze a simulated SSH
brute-force attempt, using native command-line tools (grep, awk, tail) rather than a GUI or SIEM. The
purpose of this lab is to be familiar with Linux logs like we did Windows Event Log in Lab01.

**Lab Environment**

  Attacker machine: Kali Linux VM
  
  Target machine: Ubuntu Server 22.04 LTS VM, OpenSSH server installed

_Screenshots are also available in this file_

**Skills Gained**

Linux authentication log analysis. grep, awk, tail command-line log filtering. SSH protocol behavior
(connection limits which is 3, port reuse: same port for one session). log deduplication awareness.
incident report writing for a written case study scenario.

_You can see incident-report.md for the complete case-study report (webserver-03 account enumeration
scenario)_


