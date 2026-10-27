# SOC Incident Report

**Alert Name:** Credential-Harvesting Phishing Campaign ("Invoice Overdue") with Confirmed Account 
Takeover — a.lopez

**Date/Time:** 14:02:11 to 14:53:10 UTC

**Severity:** Critical. A credendial POST, a sign-in from a different country within 45 minutes and then
a mail-forwarding rule created 39 seconds after are clear signs of account takeover, not just a phishing
delivery.

**Affected Host:** None compromised at host level. Endpoints that reached the phishing site: a.lopez (10.20.1.31),
b.chen (10.20.1.44), c.okafor (10.20.1.52, blocked).

**Affected User:** a.lopez (confirmed compromise). b.chen exposed, no confirmed submission. c.okafor blocked.
d.nguyen no evidence of click. e.silva not delivered (quarantined).

**Source IP:** 203[.]0[.]113[.]88 (phishing email, per our own gateway's Received line), 
198[.]51[.]100[.]77 (hostile sign-in, RO)

**Destination IP** Not available for the phishing site (the proxy log records the hostname only).

**Indicators of Compromise:**
  - Sending IP 203[.]0[.]113[.]88 (email source)
  - Sign-in source IP 198[.]51[.]100[.]77 (attacker source)
  - Phishing site invoice-portal-secure[.]example
  - Spoofed From domain acc0unts-payable[.]example (zero for "o")
  - Return-Path domain mailer-77[.]bulk-send[.]test
  - Forwarding destination a.lopez.backup@gmail-secure-mail[.]example
  - Email authentication: SPF pass (for bulk-send[.]test only), DKIM none, DMARC fail
  - Mailbox audit: New-InboxRule, forward all mail externally and delete from Inbox

**Timeline:** 

| Time (UTC) | Event |
| :--- | :--- |
| **14:02:11 – 14:02:13** | Email delivered to `a.lopez`, `b.chen`, `c.okafor`, `d.nguyen`; `e.silva` quarantined (spam score 9.1) |
| **14:07:12** | `a.lopez` `GET /pay?id=7731` returns `200` |
| **14:07:19** | `a.lopez` `POST /login` returns `200`, 412 bytes out |
| **14:09:40** | `b.chen` `GET /pay?id=7732` returns `200` (page loaded, no POST) |
| **14:12:00** | Proxy recategorizes the domain as **PHISHING** (blocked) |
| **14:15:03** | `c.okafor` `GET /pay?id=7733` returns `403` (blocked) |
| **14:21:00** | `c.okafor` reports the email |
| **14:52:31** | `a.lopez` sign-in from `198[.]51[.]100[.]77` (RO), IMAP (legacy), MFA not prompted |
| **14:53:10** | Inbox rule created: forward all mail externally, delete from Inbox |

**Investigation Findings:** 
The email failed DMARC. SPF passed only for attacker's own Return-Path domain which does not match From
domain. There is a differ in visible link test and real destination: users see an invoice link, but it leads
to a lookalike portal.

The proxy shows the page loaded for a.lopez and b.chen before the block at 14:12:00, and a 403 error for
c.okafor after it. a.lopez then sent a POST to the login form 7 seconds after opening the page. 45 minutes
12 seconds later her account signed in from a foreign IP over IMAP without an MFA prompt. The forwarding 
rule was created 39 seconds after that. 

**MITRE ATT&CK Mapping:** 

| Stage | Tactic | Technique |
| :--- | :--- | :--- |
| **Phishing email with link** | Initial Access | `T1566.002` Phishing: Spearphishing Link |
| **User opens the link** | Execution | `T1204.001` User Execution: Malicious Link |
| **Sign-in with stolen password** | Initial Access | `T1078` Valid Accounts |
| **Forwarding rule to external address** | Collection | `T1114.003` Email Collection: Email Forwarding Rule |
| **Rule deletes mail from Inbox** | Stealth | `T1564.008` Hide Artifacts: Email Hiding Rules |

**Impact:** 
The mailbox of a.lopez is compromised by attacker, and all emails received between 14:53 and removal of
the rule has been copied outside the organization. Potential exposure includes invoices, password-reset
messages for other services, and and use of her mailbox to phish others. 

**Recommended Actions:** 
- Contain a.lopez. Disable sign-in, reset the password, and revoke sessions for a.lopez.
- Remove the forwarding rule.
- Block the IOCs, then purge the email.
- Reset b.chen’s password as a precaution.
- Check a.lopez’s mailbox activity since 14:52, and check d.nguyen.
- Verify containment, then escalate to Tier 2 with the evidence.
- Request that legacy authentication be disabled.
  
**Final Conclusion:** Confirmed account takeover of a.lopez, campaign blocked at the proxy from 14:12. The 
activity appears to be a credential harvesting phish where mailbox was accessed via legacy IMAP and an
exfiltration rule. Escalated to Tier 2 for deeper investigation.

_This report has been prepared as part of a home SOC lab (lab09-phishing-email-analysis) and this incident
report addresses a provided case-study scenario using fictional domains and IP ranges._
