**Technical Report: Multi-Host Authentication Correlation**

**Objective**

Determine whether a single source IP that fails authentication against two different OS (Windows RDP and
Linux SSH) within a short time window could be detected as a single correlated alert, using Wazuh's native
rule correlation engine.

**Summary of Findings**

Authentication failures on both victims Windows and Linux were confirmed to generate correctly and independently:

**Windows RDP failure:** Wazuh rule 60122, capturing the source IP correctly (192.168.11.10) in _data.win.eventdata.ipAddress_
field, Logon Type 3 (not 10, because of NLA pre-authentication process).

**Linux SSH failure:** Wazuh rule 5760, capturing the source IP correctly in _srcip_ normalized field.

Two custom "listener" rules (100020, 100021) were created to tag each other into a shared rule group (multi_
host_auth_fail), and both were success individually in Dashboard. While third rule (100022) using _<if_matched_group>_
with frequency "2" and timeframe "120" did not fire when both "listener" rules fired.

**Reason why third rule failed**

1. **Field normalization asymmetry:** Wazuh's windows eventchannel decoder does not map _win.eventdata.ipAddress_
   into the standard _srcip_ field used by <same_source_ip />, while Linux SSH/PAM decoders do. This has
   prevented the IP-based correlation between two event types impossible without a custom decoder, and the
   _<same_source_ip />_ field has been deleted from the correlation rule.

2. **Cross-agent correlation limitation:** Despite removing IP-matching requirement, frequency/timeframe
   correlation did not count matches from two different agents (windows-victim and ubuntu-victim-ssh). Two
   candidate tags _<different_agent /> and <count_all_agent />_ were tested but both of them failed to succeed
   as well.

**Conclusion**

Cross-host authentication correlation, which is theoretically strong and can even be successfully simulated
at the "listener rule" level, could not be fully implemented as a single native correlation rule in this
environment due to a combination of decoder field normalization gaps and a cross-agent frequency-counting
limitation in Wazuh 4.9.2.

_Report prepared as part of a home SOC lab exercise (Lab 06: Multi-Host Log Forwarding & Correlation).
Unlike prior labs incident reports, this report documents about a tool limitation rather than a confirmed
security alert._
