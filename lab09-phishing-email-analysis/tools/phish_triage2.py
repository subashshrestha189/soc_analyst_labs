#!/usr/bin/env python3
"""
phish_triage.py - first-pass phishing email triage (Lab 9)

Usage:  python3 phish_triage.py suspicious.eml

Reads the .eml as TEXT only (never renders HTML, never fetches links),
then reports: sender mismatches, auth results, Received chain,
link text vs real href, and defanged IOCs.
"""
import sys
import re
import ipaddress
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlparse


def defang(s: str) -> str:
    """Make an IOC safe to paste in tickets/chat."""
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return s.replace(".", "[.]")


RFC1918 = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def is_internal(ip: str) -> bool:
    """True only for RFC1918/loopback. (Python's is_private also flags the
    documentation ranges 192.0.2.0/24 and 203.0.113.0/24 used in this lab.)"""
    a = ipaddress.ip_address(ip)
    return any(a in n for n in RFC1918)


def ips_in(text: str):
    """Bracketed IPs in order, de-duplicated."""
    seen = []
    for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", text):
        if ip not in seen:
            seen.append(ip)
    return seen


SLD = {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"}


def reg_domain(host: str) -> str:
    """Rough registrable domain: www.amazon.co.jp -> amazon.co.jp"""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


URL_IN_TEXT = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def domain_of(addr: str) -> str:
    return parseaddr(addr)[1].rpartition("@")[2].lower()


class LinkExtractor(HTMLParser):
    """Collect (visible_text, href) for every <a> tag."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(("".join(self._text).strip(), self._href))
            self._href = None


def main(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    flags = []  # (severity, message)

    print("=" * 60)
    print("PHISHING TRIAGE REPORT:", path)
    print("=" * 60)

    # ---- 1. Identity ----
    frm = msg["From"] or ""
    rp = msg["Return-Path"] or ""
    rt = msg["Reply-To"] or ""
    d_from, d_rp, d_rt = domain_of(frm), domain_of(rp), domain_of(rt)
    print("\n[1] SENDER IDENTITY")
    print(f"  From        : {frm}   -> {defang(d_from)}")
    print(f"  Return-Path : {rp}   -> {defang(d_rp)}")
    print(f"  Reply-To    : {rt}   -> {defang(d_rt) if rt else '(none)'}")

    # ---- 2. Authentication ----
    ar = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    print("\n[2] AUTHENTICATION")
    results = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", ar)
        results[mech] = m.group(1) if m else "missing"
        print(f"  {mech.upper():6}: {results[mech]}")
    # DMARC pass = SPF or DKIM passed AND aligned with the From domain.
    # This is the strongest legitimacy signal, so it changes how we read the rest.
    trusted = results["dmarc"] == "pass"
    mismatch_sev = "INFO" if trusted else "HIGH"
    note = " (normal for bulk senders / ESPs; DMARC aligned)" if trusted else ""

    if trusted:
        flags.append(("GOOD", "DMARC pass - authenticated and aligned with From domain"))
    else:
        flags.append(("HIGH", f"DMARC {results['dmarc']}"))
        if results["dkim"] in ("none", "fail", "missing"):
            flags.append(("MED", f"DKIM {results['dkim']}"))
    if results["spf"] == "pass" and d_from != d_rp and not trusted:
        flags.append(("INFO", "SPF passed for the Return-Path domain, NOT the From domain "
                              "(pass is misleading - no alignment)"))
    if d_from and d_rp and reg_domain(d_from) != reg_domain(d_rp):
        flags.append((mismatch_sev, "From domain != Return-Path domain" + note))
    if rt and reg_domain(d_rt) != reg_domain(d_from):
        flags.append((mismatch_sev, "Reply-To domain != From domain" + note))
    # lookalike check only matters when authentication does NOT vouch for the domain
    first_label = d_from.split(".")[0]
    if not trusted and re.search(r"[a-z][0-9][a-z]|[a-z]0|0[a-z]", first_label):
        flags.append(("MED", f"Possible lookalike characters in From domain ({d_from})"))

    # ---- 3. Received chain (oldest first) ----
    received = msg.get_all("Received", [])
    print("\n[3] RECEIVED CHAIN (oldest -> newest)")
    for i, hop in enumerate(reversed(received), 1):
        hop = " ".join(str(hop).split())
        tag = ""
        for ip in ips_in(hop):
            if is_internal(ip):
                tag += f" (private {defang(ip)})"
            else:
                tag += f" (public {defang(ip)})"
        ts = hop.rpartition(";")[2].strip()
        try:
            ts_utc = parsedate_to_datetime(ts).astimezone(
                __import__("datetime").timezone.utc)
            ts_show = ts_utc.strftime("%H:%M:%S UTC")
        except Exception:
            ts_show = "?"
        print(f"  hop {i}: {ts_show}{tag}")
    print("  NOTE: only lines written by YOUR servers are trustworthy.")

    # ---- 4. Mail-client fingerprints ----
    print("\n[4] OTHER FINGERPRINTS")
    print("  X-Mailer  :", msg["X-Mailer"] or "(none)")
    mid = msg["Message-ID"] or ""
    mid_dom = mid.strip("<>").rpartition("@")[2].lower()
    print("  Message-ID:", defang(mid))
    if mid_dom and d_from and reg_domain(mid_dom) != reg_domain(d_from):
        flags.append(("INFO" if trusted else "MED",
                      f"Message-ID domain ({mid_dom}) unrelated to From domain" + note))
    print("  Subject   :", msg["Subject"])

    # ---- 5. Links ----
    print("\n[5] LINKS (visible text vs real href)")
    html = msg.get_body(preferencelist=("html",))
    iocs = set()
    if html:
        parser = LinkExtractor()
        parser.feed(html.get_content())
        seen_flags = set()
        for text, href in parser.links:
            print(f"  shows : {defang(text)}")
            print(f"  goes  : {defang(href)}")
            real_host = urlparse(href).hostname
            # Only compare when the visible text CLAIMS to be a URL/domain.
            # Plain words like "your account" make no destination claim.
            m = URL_IN_TEXT.search(text)
            if m and real_host:
                vis, real = reg_domain(m.group(1)), reg_domain(real_host)
                if vis != real and (vis, real) not in seen_flags:
                    seen_flags.add((vis, real))
                    flags.append(("HIGH", f"Link text claims {vis} but goes to {real}"))
            if real_host:
                iocs.add(real_host)
                if (d_from and reg_domain(real_host) != reg_domain(d_from)
                        and ("off-domain", reg_domain(real_host)) not in seen_flags):
                    seen_flags.add(("off-domain", reg_domain(real_host)))
                    flags.append(("INFO" if trusted else "MED",
                                  f"Link goes to {reg_domain(real_host)}, unrelated to sender {reg_domain(d_from)}"))
    else:
        print("  (no HTML part)")

    # ---- 6. IOCs ----
    for h in ("Received",):
        pass
    # received[0] is the newest hop, written by OUR gateway: not an attacker IOC
    for hop in received[1:]:
        for ip in ips_in(str(hop)):
            if not is_internal(ip):
                iocs.add(ip)
    for d in (d_from, d_rp, d_rt):
        if d:
            iocs.add(d)
    print("\n[6] DEFANGED IOCs (for ticket / blocklist / VirusTotal)")
    for ioc in sorted(iocs):
        print("  ", defang(ioc))

    # ---- Verdict ----
    print("\n[7] FLAGS")
    weight = {"HIGH": 3, "MED": 1, "INFO": 0, "GOOD": -4}
    score = 0
    for sev, text in flags:
        print(f"  [{sev}] {text}")
        score += weight[sev]
    score = max(score, 0)
    verdict = "LIKELY PHISHING" if score >= 5 else "SUSPICIOUS" if score >= 2 else "NO STRONG INDICATORS"
    print(f"\n  SCORE {score} -> {verdict}")
    print("  Reminder: a script assists triage, it never replaces analyst judgment.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: phish_triage.py file.eml")
    main(sys.argv[1])
