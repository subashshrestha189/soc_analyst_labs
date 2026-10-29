**Detection Backlog (from the ATT&CK coverage layer)**

Techniques below are design specifications. Only T1566.002 can be tested in this lab (phish_triage2.py), the
others need identity provider or mailbox audit logs that the home lab does not have.

**1. T1566.002: Phishing: Spearphishing Link**

| Field | Content |
| :--- | :--- |
| **Data source** | Mail gateway log (`Authentication-Results`), domain-age lookup, web proxy log for click follow-up |
| **Condition** | Inbound email where DMARC fails AND (link text domain differs from real destination, OR From domain is a lookalike of a known brand, OR sending domain was registered recently) |
| **Severity** | High on delivery; Critical if the proxy shows a `POST` to the linked domain |
| **False positives** | Legitimate bulk mail with normal mismatches (mitigated by requiring DMARC fail); vendors with misconfigured DMARC; mailing lists and forwarders that break SPF/DKIM |
| **First response** | Quarantine and purge from all mailboxes; identify other recipients; search proxy for clicks and `POST`s; block the domain; if a `POST` exists, reset credentials, revoke sessions, check mailbox rules; escalate |
| **Lab support** | `phish_triage2.py` already implements the DMARC and link-mismatch conditions; domain age would be new work |

**2. T1078: Valid Accounts**

| Field | Content |
| :--- | :--- |
| **Data source** | Identity-provider sign-in log (IP, country, client protocol, MFA result); per-user baseline of usual countries; web proxy log for correlation |
| **Condition** | Successful sign-in from a country not in the user's baseline AND (legacy protocol OR no MFA prompt) |
| **Severity** | Medium for new location alone; High with legacy protocol or no MFA; Critical if it follows a proxy `POST` to a phishing domain within a set window (for example 24 hours; tune) |
| **False positives** | Traveling employees; VPN or mobile-carrier IPs with wrong geolocation; new devices; old mail apps that still use legacy protocols |
| **First response** | Disable sign-in, reset the password, revoke sessions; review mailbox activity after the `POST`; verify containment; escalate |
