# Case Study — Provided Alert Data

> **Note:** This file contains the raw alert data as provided for this case
> study. It does not represent logs generated on infrastructure I personally
> own or operate. It is included for reference only, so the investigation in
> `incident-report.md` can be reviewed against the original data.

**Scenario:** A monitoring script flagged unusual SSH activity on host
`webserver-03`.

```
Sep 6 03:14:02 webserver-03 sshd[8821]: Failed password for root from 203.0.113.55 port 41221 ssh2
Sep 6 03:14:04 webserver-03 sshd[8823]: Failed password for admin from 203.0.113.55 port 41230 ssh2
Sep 6 03:14:06 webserver-03 sshd[8825]: Failed password for oracle from 203.0.113.55 port 41244 ssh2
Sep 6 03:14:08 webserver-03 sshd[8827]: Failed password for postgres from 203.0.113.55 port 41255 ssh2
Sep 6 03:14:10 webserver-03 sshd[8829]: Failed password for test from 203.0.113.55 port 41267 ssh2
... (pattern continues for 40+ distinct usernames over ~90 seconds,
    all from 203.0.113.55, zero successful authentications observed)
```
