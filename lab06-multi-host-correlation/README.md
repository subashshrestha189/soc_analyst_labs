**Objective**

Extend the single agent Wazuh deployment from Lab 05 to monitor multiple hosts (Kali, a Windows 10 victim via
RDP, and a Linux SSH victim), and attempt to build a cross-host correlation rule detecting the same source
IP failing authentication against two different hosts within a short window. This is a kind of mini-version of
correlation that SOC does to detect lateral movement.

**Lab Environment**

Wazuh Manager: Ubuntu Server + Docker

Kali Linux: Attacker, Wazuh agent

Windows 10: RDP victim, Wazuh agent

Another Ubuntu Server: SSH victim, Wazuh agent

**Methodology**

1. Installed Wazuh agents on Kali and another Ubuntu server victim (used in Lab 02's SSH lab), increasing
   the number of monitored hosts to three.

2. Enabled RDP on Windows victim (only for lab purposes; never allow RDP to connect from an untrusted
   network) to create a genuine remote authentication, contrasting with Lab 01/05's local console logons.

3. Confirmed failed RDP attempts log as Logon Type 3, not Type 10, as I have assumed at first - Windows
   does NLA (Network Level Authentication) credential checks before establishing a full RemoteInteractive
   session, so failed attempts never reach Type 10. Only successful RDP logon (rule 92657, "Successful
   Remote Logon Detected") showed Type 10.

4. It is validated that RDP failure path correctly populates data.win.eventdata.ipAddress with the real
   attacker IP (192.168.11.10), not just 127.0.0.1 as shown in Lab 05's console test.

5. Built a three-rule structure for cross-source correlation: two low-severity "listener" rules (100020 for
   Windows RDP failures, 100021 for Linux SSH failures) tagging events into a shared group _mulit_host_auth_fail_
   and one correlation rule (100022) using _if_matched_group_ with frequency 2 to fire when both listener rules
   matched within 120 seconds.

6. Diagnosed and resolved a rules-file XML syntax error during manual editing (<group name>="...." instead
   of <group name="....">), which had cascaded into a Wazuh Dashboard authentication failure and Manager's
   API service didn't start up. Also, there was a second issue where I faced VM resource starvation (4 GB
   RAM insufficient once monitoring all three agents plus running Wazuh manager), confirmed via _docker stats_
   showing all containers capped at a shared 4.1 GB VM ceiling. And, I resolved this problem by temporarily
   stopping other lab VMs to free host RAM rather than permanently reconfiguring the Wazuh Manager VM to 6 GB.

**Key Findings**

1. **Wazuh's Windows eventchannel decoder does not normalize** _win.eventdata.ipAddress_ to the common srcip field,
   while Linux SSH/PAM decoders use srcip out of the box. It was impossible to use the tag <same_source_ip/> to
   correlate Windows/Linux login events because of that.

2. **Cross-agent frequency is not available by default in this Wazuh version (4.9.2)** even when both
   contributing rules are firing successfully and have been included in a tag together within a designated
   time window. Two tags (different_agent and count_all_agent) appear to be valid, based on documentation
   references but were invalid or unsupported in this version. **Different_agent** was refused by wazuh-analysisd
   during initialization and **count_all_agent** was not present in any of the provided rules (checked by grep).

3. **A malformed XML edit in one rule can cascade into an apparantly unrelated failure** (Dashboard authentication)
   because of dependency among other services (analysisd failed to load rules -> Manager did not initialize
   fully -> API service did not start -> Dashboard could not authenticate).

**Limitation**

Rule 100022 (cross-host correlation) doesn't successfully fire in this environment. Both listener rules 100020
100021 succeeded individually and correctly tagged into a shared group within desired timeframe, but Wazuh
4.9.2 seems to assume that both must run on same agent by default. To solve the problem, a custom decoder that
would normalize Windows' source IP into srcip followed by correlation or an integration-layer solution
(e.g., an external script correlating alerts via Wazuh API) outside the rules engine itself. 

**Skills Gained**

Multi-agent Wazuh deployment. RDP/NLA behavior analysis. multi-rule correlation design (listener rules +
group-based correlation). XML syntax debugging with cascading service failures. VM resource capacity planning
across a 4-host lab topology.

_Screenshots are also available in this file_

_You can see incident-report.md for the complete report, documenting how two individual rules succeeded but
correlation rule doesn't, which is not a failure for me but a technical finding instead._
