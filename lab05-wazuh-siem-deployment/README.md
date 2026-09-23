**Objective**

Deploy a centralized SIEM (Wazuh) to replace the existing method of investigating logs manually on each tool
in Labs 01-04, connect it to the Windows endpoint as a monitoring agent, and create a custom correlation rule
to close a real gap in Wazuh's default detection threshold for the exact brute-force attack case from Lab 01.

**Lab Environment**

Wazuh Manager/Indexer/Dashboard: Ubuntu Server, Docker Compose (single node deployment)

Monitored endpoint: Windows 10 (Wazuh Agent v4.92)

Attacker/test machine: Kali Linux (not directly used in this lab)

**Deployment Journey**

The journey of this lab to a fully functional SIEM was not smooth and was actually very complicated, which is
the reason why I have described it in detail in this document since SIEM implementation often involves exactly
this kind of multi-layer diagnosis. 

1. **Native Ubuntu install (wazuh install.sh -a) failed repeatedly** due to inconsistent connection to
  packages.wazuh.com (verified using the apt error messages as well as packet loss during ping test) along
  with the existing state of broken packages.

2. **Decided to move towards official Docker Compose installation for Wazuh** cosidering Docker's resumable,
  layer-based image pulls would be more reliable against an unstable network connection compared to
  downloading an entire apt package - which turned out to be right.

3. **Fixed an issue with disk space exhaustion (no space left on device)** causing the Indexer container to
  crash-loop. This issue was a result of incorrect disk size allocation for the virtual machine (24 GB instead
  of 50 GB limit); fixed via LVM physical volume resize, logical volume extension, and filesystem resize
  (pvresize, lvresize, resize2fs) rather than simply reprovisioning the VM.

5. **Changed the default admin credential via direct edit of _internal_users.yml_ and the OpenSearch
   securityadmin.sh tool** (the Dashboard UI blocks changing this specific reserved account), resolving
   a Java/JAVA_HOME environment issue and a TLS hostname verification mismatch (-nhnv flag) along the way.

6. **Resolved a silent Manager-to-Indexer sync failure after the password change** - the Manager's own stored
  Indexer credential (in _docker-compose.yml_) had not been updated alongside the Indexer's actual password,
  causing agent data to be accepted by the Manager but never indexed or displayed on the Dashboard. This was
  fixed by updating the Manager's environment variable and recreating the container.

7. **Windows Agent was deployed and successfully verified, confirming Active status and live data flow**

**Key Findings**

1. A SIEM's default ruleset is a starting point, not a finished detection strategy - Wazuh's built-in
  brute-force correlation requires more failed attempts than a cautious manual test produces, specially to
  avoid false-positives on ordinary mistyped passwords. Initially, I tried to test with Wazuh's built-in
  detection rule with failing login attempt 5 times and succeeded in 6th attempt intentionally. However, the
  Wazuh dashboard didn't show anything. Then I resolved this problem by developing my own rule.

2. Changes in the credentials in multi-service architecture need to be updated for all services that use
  these credentials for authentication - changing the Indexer's password without updating the Manager's
  stored copy caused a silent data pipeline failure that was easy to mistake for an agent connectivity problem.

3. The ability to troubleshoot infrastructure is just as important as being able to detect issues — all
  issues in the lab were traced through the output of logs/errors (wazuh-install.log, ossec.log, Docker
  exec output). 


_Screenshots are also available in this file_

**Skills Gained**

Wazuh SIEM architecture (Manager/Indexer/Dashboard/Agent). Docker and Docker Compose deployment.
multi-layer infrastructure troubleshooting (network, package management, disk/LVM, TLS, credential
propagation). Wazuh custom rule authoring (XML, frequency/timeframe correlation). 

_You can see incident-report.md for the complete report, documenting the custom-rule alert generated
from my own environment._




  
