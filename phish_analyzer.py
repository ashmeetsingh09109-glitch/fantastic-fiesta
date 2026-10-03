#!/usr/bin/env python3
"""
phish_analyzer.py - heuristic phishing analyzer for URLs and .eml files.

Usage:
    python phish_analyzer.py url "http://paypa1-secure.xyz/login"
    python phish_analyzer.py email suspicious.eml
    python phish_analyzer.py email suspicious.eml --json

Heuristics only: a high score means "look closer", a low score does NOT
prove safety. Pair with reputation services (VirusTotal, Google Safe
Browsing, PhishTank) for real-world use.
"""
import argparse
import ipaddress
import json
import re
import sys
from email import policy, message_from_binary_file
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# Brand name -> legitimate registered domain. Extend with brands you care about.
BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "google": "google.com",
    "apple": "apple.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "linkedin": "linkedin.com",
    "dropbox": "dropbox.com", "fedex": "fedex.com", "dhl": "dhl.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com",
}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
MULTI_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.cn"}
RISKY_EXTENSIONS = {"exe", "scr", "js", "vbs", "bat", "cmd", "com", "jar", "msi", "ps1", "lnk", "iso", "img", "hta", "docm", "xlsm"}
URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "unusual activity",
    "confirm your identity", "action required", "within 24 hours", "password expires",
    "security alert", "click here", "limited time", "final notice", "locked",
]
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("5", "s")]


def registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_homoglyphs(s):
    for fake, real in HOMOGLYPHS:
        s = s.replace(fake, real)
    return s


def analyze_url(url, display_text=None):
    """Return (score, [findings]) for one URL."""
    findings = []

    def flag(points, msg):
        findings.append((points, msg))

    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    if not host:
        return 0, [(0, "Could not parse a hostname")]
    reg = registered_domain(host)
    label = reg.split(".")[0]
    tld = host.rsplit(".", 1)[-1]
    full = host + parsed.path.lower()

    try:
        ipaddress.ip_address(host)
        flag(30, "Host is a raw IP address instead of a domain name")
    except ValueError:
        pass

    if parsed.scheme == "http":
        flag(10, "Uses unencrypted HTTP")
    if "@" in parsed.netloc:
        flag(30, "Contains '@' in the authority section (can hide the real destination)")
    if "xn--" in host:
        flag(25, "Punycode/IDN hostname (possible lookalike characters)")
    if host in SHORTENERS:
        flag(15, "URL shortener hides the final destination")
    if tld in SUSPICIOUS_TLDS:
        flag(15, f"TLD '.{tld}' is frequently abused")
    if parsed.port not in (None, 80, 443):
        flag(10, f"Non-standard port {parsed.port}")
    extra_labels = len(host.split(".")) - len(reg.split("."))
    if extra_labels >= 3:
        flag(15, f"Excessive subdomains ({extra_labels})")
    if host.count("-") >= 3:
        flag(10, "Many hyphens in hostname")
    if len(raw) > 100:
        flag(10, f"Very long URL ({len(raw)} characters)")
    if raw.count("%") >= 5:
        flag(10, "Heavy percent-encoding (possible obfuscation)")

    for brand, legit in BRANDS.items():
        if reg == legit:
            continue
        if brand in full:
            flag(30, f"Mentions '{brand}' but the real domain is '{reg}', not '{legit}'")
            break
    for brand, legit in BRANDS.items():
        if reg == legit or len(brand) < 5:
            continue
        if label != brand and (normalize_homoglyphs(label) == brand or levenshtein(label, brand) == 1):
            flag(40, f"Domain '{reg}' looks like a typosquat of '{legit}'")
            break

    if display_text:
        t = display_text.strip().lower()
        if re.match(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?$", t):
            shown = urlparse(t if "://" in t else "http://" + t).hostname or ""
            if registered_domain(shown) != reg:
                flag(40, f"Link text shows '{shown}' but actually goes to '{host}'")

    return min(sum(p for p, _ in findings), 100), findings


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def analyze_email(path):
    with open(path, "rb") as f:
        msg = message_from_binary_file(f, policy=policy.default)

    findings = []

    def flag(points, msg_):
        findings.append((points, msg_))

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    from_reg = registered_domain(from_domain) if from_domain else ""

    # Display-name spoofing
    lname = from_name.lower()
    if "@" in from_name:
        flag(25, f"Display name contains an email address: '{from_name}'")
    for brand, legit in BRANDS.items():
        if brand in lname and from_reg != legit:
            flag(30, f"Display name claims '{brand}' but sender domain is '{from_reg or 'unknown'}'")
            break

    # Header mismatches
    for header, pts in (("Reply-To", 15), ("Return-Path", 10)):
        _, addr = parseaddr(str(msg.get(header, "")))
        if "@" in addr and from_reg:
            dom = registered_domain(addr.rsplit("@", 1)[-1].lower())
            if dom != from_reg:
                flag(pts, f"{header} domain '{dom}' differs from From domain '{from_reg}'")

    # Authentication results
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", [])).lower()
    if auth:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mech}=(\w+)", auth)
            if m and m.group(1) in ("fail", "softfail", "permerror"):
                flag(20, f"{mech.upper()} check result: {m.group(1)}")
    else:
        flag(5, "No Authentication-Results header (SPF/DKIM/DMARC unverified)")

    # Body, links, language
    body = msg.get_body(preferencelist=("html", "plain"))
    content = body.get_content() if body else ""
    links = []
    if body and body.get_content_type() == "text/html":
        lp = LinkParser()
        lp.feed(content)
        links = [(h, t) for h, t in lp.links if h and h.lower().startswith(("http://", "https://"))]
    else:
        links = [(u, None) for u in re.findall(r"https?://[^\s<>\"')]+", content)]

    text = (str(msg.get("Subject", "")) + " " + re.sub(r"<[^>]+>", " ", content)).lower()
    hits = [w for w in URGENCY_WORDS if w in text]
    if hits:
        flag(min(5 * len(hits), 20), f"Pressure/urgency language: {', '.join(hits[:5])}")

    # Attachments
    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        parts = name.split(".")
        if len(parts) > 2 and parts[-1] in RISKY_EXTENSIONS:
            flag(35, f"Attachment '{name}' uses a double extension")
        elif parts[-1] in RISKY_EXTENSIONS and len(parts) > 1:
            flag(30, f"Attachment '{name}' has a risky file type")

    # URLs
    url_results = []
    for href, text_ in links:
        score, f = analyze_url(href, text_)
        url_results.append({"url": href, "score": score, "findings": f})
    url_results.sort(key=lambda r: r["score"], reverse=True)
    if url_results and url_results[0]["score"] >= 30:
        flag(min(url_results[0]["score"], 40), "Contains a high-risk link (see URL details)")

    score = min(sum(p for p, _ in findings), 100)
    return {
        "from": f"{from_name} <{from_addr}>",
        "subject": str(msg.get("Subject", "")),
        "score": score,
        "verdict": verdict(score),
        "findings": findings,
        "urls": url_results,
    }


def verdict(score):
    return "HIGH RISK" if score >= 50 else "SUSPICIOUS" if score >= 20 else "LOW RISK"


def print_findings(findings, indent="  "):
    if not findings:
        print(f"{indent}(no indicators found)")
    for pts, msg in sorted(findings, reverse=True):
        print(f"{indent}[+{pts:>2}] {msg}")


def main():
    ap = argparse.ArgumentParser(description="Heuristic phishing analyzer")
    sub = ap.add_subparsers(dest="mode", required=True)
    u = sub.add_parser("url", help="analyze one or more URLs")
    u.add_argument("urls", nargs="+")
    e = sub.add_parser("email", help="analyze .eml files")
    e.add_argument("files", nargs="+")
    for p in (u, e):
        p.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    results = []
    if args.mode == "url":
        for url in args.urls:
            s, f = analyze_url(url)
            results.append({"url": url, "score": s, "verdict": verdict(s), "findings": f})
    else:
        for path in args.files:
            r = analyze_email(path)
            r["file"] = path
            results.append(r)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    for r in results:
        if args.mode == "url":
            print(f"\n{r['url']}\n  Score {r['score']}/100 -> {r['verdict']}")
            print_findings(r["findings"])
        else:
            print(f"\n{r['file']}\n  From: {r['from']}\n  Subject: {r['subject']}")
            print(f"  Score {r['score']}/100 -> {r['verdict']}")
            print_findings(r["findings"])
            for ur in r["urls"]:
                if ur["score"] > 0:
                    print(f"  Link: {ur['url'][:80]} (score {ur['score']})")
                    print_findings(ur["findings"], indent="      ")


if __name__ == "__main__":
    sys.exit(main())
