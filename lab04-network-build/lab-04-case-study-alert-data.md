# Case Study — Provided Alert Data

> **Note:** This file contains the raw alert data as provided for this case
> study. It does not represent firewall logs generated on my own environment. It is included for reference only, so the
> investigation in `incident-report.md` can be reviewed against the
> original data.

**Scenario:** Firewall log on host `DB-SRV-01` (10.20.5.15).

```
2026-09-14 03:02:11 DROP TCP 198.51.100.23 10.20.5.15 51201 21 44 S - - - RECEIVE
2026-09-14 03:02:11 DROP TCP 198.51.100.23 10.20.5.15 51202 22 44 S - - - RECEIVE
2026-09-14 03:02:11 DROP TCP 198.51.100.23 10.20.5.15 51203 23 44 S - - - RECEIVE
2026-09-14 03:02:12 DROP TCP 198.51.100.23 10.20.5.15 51204 80 44 S - - - RECEIVE
2026-09-14 03:02:12 DROP TCP 198.51.100.23 10.20.5.15 51205 443 44 S - - - RECEIVE
2026-09-14 03:02:12 DROP TCP 198.51.100.23 10.20.5.15 51206 3389 44 S - - - RECEIVE
2026-09-14 03:02:12 ALLOW TCP 198.51.100.23 10.20.5.15 51207 1433 44 S - - - RECEIVE
... (pattern continues, 20 ports total scanned in 4 seconds, only port 1433 ALLOWed)
```

For comparison, the real firewall log data I generated in my own lab
is documented separately in `README.md` and
`screenshots/pfirewall-log-file.png` — that data reflects an
actual Nmap scan I ran from my own Kali VM against my own Windows VM,
distinct from this provided scenario.
