# Case Study — Provided Alert Data

> **Note:** This file contains the raw alert data as provided for this case
> study. It does not represent Sysmon telemetry generated on infrastructure I
> personally own or operate. It is included for reference only, so the
> investigation in `incident-report.md` can be reviewed against the original
> data.

**Scenario:** Sysmon Event ID 1 (Process Creation) on host `FIN-LAPTOP-07`,
user `k.chen`.

```
Image:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage:  C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
CommandLine:  powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdw...
User:         FIN-LAPTOP-07\k.chen
Time:         2:47 PM
```

For comparison, the real Sysmon Event ID 1 I generated in my own lab
is documented separately in `README.md` and
the data you see on screenshots folder reflects an
actual `cmd.exe → powershell.exe` chain I executed on my own VM, distinct
from this provided scenario.
