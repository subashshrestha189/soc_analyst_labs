**Objective**

Learn to triage a potential phishing email the way a Tier 1 SOC analyst does: review the headers, authenticate
the sender, identify the true destination of any URLs contained within the email, extract defanged indicators,
and then automate the repeatable process using a small script. The lab ends with a case study that combines 
mail gateway, web proxy, identity provider, and mailbox logs to determine who was exposed and what to contain
first.

**Lab Environment**

Analysis host: Kali Linux (emails handled as plain text only)

Samples: a legitimate email (baseline), a sample phishing email (phish-sample.eml) which uses reserved fake
domains (.example, .test) and another legitimate bulk email (an Amazon welcome message) used to test the script

Tools: less/cat, python 3 standard library (phish_triage.py)

**Methodology**

1. Baseline first. Analyzed the headers from a real email to understand what "normal" looks like: SPF, DKIM,
   and DMARC all pass, domains align, and the Received headers.
2. Analyzed a training phishing email (phish-sample.eml) by hand: compared From, Return-Path, and Reply-To domains;
   read Authentication-Results; read Received header chain bottom-up; compared visible link text with real href;
   checked X-Mailer, Message-ID, and timestamps converted to UTC.
3. Built phish_triage.py, a standard-library Python script that parses an .eml as text and generates a list
   of sender domain mismatches, authentication results, the Received header chain with private/public IP
   labels and UTC times, link text versus real destination.
4. Tested the script on a real email and it produced a false positive (score 25, higher than phishing
   sample's 15). Found out why (see Key Findings), modified the scoring algorithm to be alignment-aware, and
   re-ran both: now the legitimate email scores 0, and the phishing email stays at 15.
5. Conducted a study on four logs (mail gateway, proxy, identity provider, mailbox audit), classified each
   recipient by exposure, identified an account takeover, and wrote an incident report.

**Key Findings**

1. SPF pass does not mean safe. In phishing sample, SPF passed for the attacker's own Return-Path domain,
   not the domain shown in From. DMARC failed because both SPF and DKIM were not aligned with From domain.
   DMARC pass means SPF or DKIM passed and matched the From domain.
2. Read the Received chain bottom-up and trust only your own servers. A private address (RFC 1918) in the
   chain is the sender's own network, not the public origin. The first hop written by your own gateway gives
   the sending public IP.
3. The visible link text is bait; the href is the destination. The phishing sample showed a Microsoft URL
   while linking a lookalike domain (micros0ft, zero for "o").
4. A detection that flags every mismatch is a bad detection. My first script scored a legitimate Amazon
   email at 25 because bulk senders typically have different Return-Path and Message-ID, and because plain-
   word link text ("your account") was wrongly compared to hostnames. Introducing alignment-awareness
   (DMARC pass as proof of legitimacy and comparing only text that claims a domain) fixed the false
   positive without lowering the phishing score.
5. Absence of a log entry is not absence of activity. The proxy had no entry for one recipient, which
   confirms "no evidence of a click", not "did not click" (a phone or off-network device would now appear).
6. Read status codes and timestamps, not just order. One user's page was loaded (HTTP 200) before the
   proxy block; another got 403 after it. The POST to login page, not the GET, is what indicates submitted
   data.
7. Legacy protocols can bypass MFA. The malicious sign-in used IMAP with no MFA prompt, followed 39 seconds
   later by an external forwarding rule which also deleted mail from the inbox.
8. Time to containment mattered. The user report arrived 31 minutes before the malicious sign-in. Responding
   to the first report might have prevented the takeover.

**Skills Gained**

Email header analysis. SPF/DKIM/DMARC interpretation. Received-chain tracing and private/public IP reasoning.
link inspection and IOC defanging. multi-source log correlation (gateway, proxy, identity, mailbox). 
containment prioritization. MITRE ATT&CK mapping

_Screeshots are also available in this lab_

_The header analysis and the script are hands-on work performed on my own test emails. The incident report
is performed on the fictional case-study scenario which is distinct from the hands-on perfomed in this lab._
