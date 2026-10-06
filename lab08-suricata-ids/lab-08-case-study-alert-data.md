# Case Study: Provided Alert Data

> **Note:** This file contains the raw data as provided for this case
> study. It was not generated on infrastructure I operate. It is included
> so `incident-report.md` can be reviewed against the original data.

**Scenario:** Sensor `SENSOR-DMZ-01` protects `10.20.5.0/24` with ET Open
plus local rules. `10.20.5.15` is `DB-SRV-01` (SQL Server) and
`10.20.5.16` is `WEB-SRV-02`. Date: 10/04/2026, about 02:14 AM.

## Suricata alerts (condensed from eve.json)

```
02:14:07  ET SCAN Suspicious inbound to MSSQL port 1433        198.51.100.77 -> 10.20.5.15:1433   sev 2
02:14:07  ET SCAN Suspicious inbound to mySQL port 3306        198.51.100.77 -> 10.20.5.15:3306   sev 2
02:14:07  ET SCAN Suspicious inbound to PostgreSQL port 5432   198.51.100.77 -> 10.20.5.15:5432   sev 2
02:14:08  ET SCAN Suspicious inbound to Oracle SQL port 1521   198.51.100.77 -> 10.20.5.15:1521   sev 2
02:14:08  LOCAL SCAN Possible TCP SYN port scan - 50+ SYNs...  198.51.100.77 -> 10.20.5.16:8080   sev 2
02:14:10  SURICATA Applayer Detect protocol only one direction 10.20.5.22:443  -> 10.20.5.40:50122 sev 3
```

## Zeek conn.log (abbreviated excerpt)

Fields: `ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes conn_state`

```
02:14:07  198.51.100.77  10.20.5.15  3306   -       -        -        REJ
02:14:07  198.51.100.77  10.20.5.15  5432   -       -        -        REJ
02:14:07  198.51.100.77  10.20.5.15  1521   -       -        -        S0
02:14:08  198.51.100.77  10.20.5.16  8080   -       -        -        S0
02:14:07  198.51.100.77  10.20.5.15  1433   0.8     214      187      SF
02:14:31  198.51.100.77  10.20.5.15  1433   38.6    9422     4180     SF
02:19:12  198.51.100.77  10.20.5.15  1433   412.3   52110    3302418  S1
```

The excerpt is abbreviated. A real scan of 50+ SYNs would produce 50+
rows.
