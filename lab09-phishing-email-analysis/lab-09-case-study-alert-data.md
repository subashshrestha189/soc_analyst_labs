# Lab 09 Case Study: "Invoice Overdue" Phishing Campaign

All domains and IPs are fictional (`.example`/`.test`, documentation IP ranges).
All times are UTC. Corporate egress IP: `192.0.2.10`. Internal range: `10.20.1.0/24`.

## Ticket

> **14:21** User `c.okafor` reports a suspicious email: "Invoice Overdue - Action
> Required". She says she clicked the link but "nothing loaded." She is worried.
> Please investigate scope and impact.

## Sample email (headers summarized)

- From: `"Accounts Payable" <billing@acc0unts-payable.example>`
- Return-Path: `<bounce@mailer-77.bulk-send.test>`
- Authentication: SPF pass (bulk-send.test) / DKIM none / DMARC fail
- Link text: `View invoice` -> `http://invoice-portal-secure.example/pay?id=<n>`
  (unique `id` per recipient)
- Sending IP (from your own gateway's Received line): `203.0.113.88`

## Log 1: Mail gateway (delivery log)

| time | recipient | sender_ip | action |
|---|---|---|---|
| 14:02:11 | a.lopez@corp-victim.example | 203.0.113.88 | delivered |
| 14:02:11 | b.chen@corp-victim.example | 203.0.113.88 | delivered |
| 14:02:12 | c.okafor@corp-victim.example | 203.0.113.88 | delivered |
| 14:02:12 | d.nguyen@corp-victim.example | 203.0.113.88 | delivered |
| 14:02:13 | e.silva@corp-victim.example | 203.0.113.88 | quarantined (spam score 9.1) |

## Log 2: Web proxy (outbound)

Fields: `time | user | src_ip | method | url | status | bytes_out`

```
14:07:12 | a.lopez  | 10.20.1.31 | GET  | http://invoice-portal-secure.example/pay?id=7731 | 200 | 380
14:07:19 | a.lopez  | 10.20.1.31 | POST | http://invoice-portal-secure.example/login       | 200 | 412
14:09:40 | b.chen   | 10.20.1.44 | GET  | http://invoice-portal-secure.example/pay?id=7732 | 200 | 380
14:12:00 | (proxy admin) category update: invoice-portal-secure.example -> PHISHING (blocked)
14:15:03 | c.okafor | 10.20.1.52 | GET  | http://invoice-portal-secure.example/pay?id=7733 | 403 | 380
```

(No proxy entries for `d.nguyen` or `e.silva` for this domain.)

## Log 3: Identity provider sign-ins

Fields: `time | user | src_ip | country | client | result`

```
08:55:02 | a.lopez  | 192.0.2.10    | CA | Chrome/Windows | success
08:58:40 | b.chen   | 192.0.2.10    | CA | Chrome/Windows | success
14:52:31 | a.lopez  | 198.51.100.77 | RO | IMAP (legacy)  | success (MFA: not prompted)
```

## Log 4: Mailbox audit

```
14:53:10 | a.lopez | New-InboxRule | Forward all incoming mail to a.lopez.backup@gmail-secure-mail.example; delete from Inbox
```


