**Objective**

Deploy Suricata as a network IDS, validate what the default ruleset can and cannot detect against traffic
I generated, and create custom signatures to close a confirmed detection gap. This builds on Lab 07 where 
Wireshark provided ground truth, Zeek provided a summary, and Suricata automated matching against known bad
patterns.

**Lab Environment**

Sensor + victim: Ubuntu Server 22.04 (192.168.11.40)

Attacker: Kali Linux: 192.168.11.10

Suricata: 8.0.7 version, Emerging Threats Open ruleset via _suricata-update_, IDS mode

**Methodology**

1. Installed Suricata from the project's official repository and downloaded ET Open signatures.

2. Set HOME_NET to the three protected hosts only (192.168.11.20, .30, .40), not the whole /24 because
   EXTERNAL_NET is defined as "not HOME_NET", listing the full subnet would have made Kali "internal" and
   silently suppressed most signatures. Also, set _af-packet_ interface to ens33.

3. Verified whether the sensor was actually capturing and not just running by resolving _af-packet: eth0:
   No such device error_. Confirmed _capture.kernel_packets_ in stats.log.

4. Performed three attacks from Kali and triaged the alerts:
   - SYN scan (_nmap -sS_): alerts for database and remote-access ports.
   - Nmap scripting engine (_nmap -sV -sC_): alerted on Nmap's identifying User-Agent in its HTTP requests.
   - Hydra SSH password guessing: alerted as an SSH scan and as frequent SSH connections consistent with
     brute force.

5. Triaged noise: alerts on the banner of the Python web server were triggered by responses from my own
   throwaway web server (source = victim), thus I classified them as expected behavior, rather than
   malicious behavior.

6. Detection gap confirmed. A scan of 201 boring ports (20000 to 20200) resulted in a big spike in Suricata's
   packet counter, proving the sensor saw the traffic, but produced no new alerts. However, scanning in one
   of the ports covered by the ruleset (3306) triggered an alert, proving alerts were being written. The
   silence therefore meant "no signature matched", not "sensor blind".

7. Wrote custom signature 1000001 (more than 50 SYNs from a single source within 10 seconds). The
   signature was triggered for the 201-port scan but not for five legitimate HTTP requests.

8. Tested evasion: A scan limited to 3 packets per second (approximately 30 SYNs in 10 seconds) evaded
   detection by 1000001. Created signature 1000002 (40+ SYNs within 120 seconds).

9. Worked a provided case study related to matching alerts between Suricata and Zeek conn.log
   (incident-report.md).

**Key Findings**

1. Port-based and behavior-based signatures differ from content-based signatures. The SYN scan was detected
   by signatures depending on what ports were probed, not on the payload. A scan of ordinary ports (port like
   80, 443) produced no alerts.

2. Any fixed threshold can be evaded by slowing down. 3 packets per second is not enough for the 10-second
   rule, while a larger time window eliminates this problem but increases false positives.

3. Alerts show attempts, not outcomes. Suricata flagged probes of closed ports. If combined with Zeek (conn_state),
   it is possible to see connections that succeeded.

4. Severity scales differ by tool. In Suricata, severity 1 is the highest priority. In Wazuh (Lab 05),
   a higher level is worse.

5. Alert direction matters. Checking source vs. destination separates attacker activity from the sensor's
   own noise.

**Skills Demonstrated**

Suricata deployment. signature (rule) reading and writing. HOME_NET/EXTERNAL_NET design. eve.json analysis
with jq. threshold evasion testing. correlating IDS alerts with Zeek metadata.


_You can check out screenshots, incident-report.md, and case-study-alert-data.md. Screenshots are provided
from my own lab._
