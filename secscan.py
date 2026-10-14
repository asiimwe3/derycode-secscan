#!/usr/bin/env python3
"""
Derycode SecScan — defensive vulnerability scanner for websites you OWN.
Checks security headers, exposed sensitive files, open admin panels,
directory listings, mixed content, cookie flags, and information leaks.

USAGE
    python3 secscan.py https://your-site.com
    python3 secscan.py https://a.com https://b.com --html report.html

LEGAL: Only scan systems you own or have written permission to test.
Passive checks + safe GET probes only — no exploitation, no payloads.
"""

import sys, ssl, json, urllib.request, urllib.error, socket, hashlib, re
from urllib.parse import urlparse, urljoin

PASSIVE_PATHS = [
    ("/.git/config", "critical", "Git repository exposed — full source code can be downloaded"),
    ("/.env", "critical", "Environment file exposed — secrets/credentials may be public"),
    ("/.htaccess", "high", ".htaccess exposed — server config is public"),
    ("/.DS_Store", "low", "macOS directory file exposed — file names leak"),
    ("/db.sql", "critical", "SQL database dump exposed"),
    ("/backup.sql", "critical", "SQL backup dump exposed"),
    ("/database.sql", "critical", "Database file exposed"),
    ("/composer.json", "medium", "composer.json exposed — dependency versions leak"),
    ("/package.json", "medium", "package.json exposed — dependency versions leak"),
    ("/phpinfo.php", "critical", "phpinfo page exposed — full server configuration leak"),
    ("/info.php", "high", "PHP info page exposed"),
    ("/server-status", "medium", "Apache server-status exposed"),
    ("/.svn/entries", "high", "SVN repository metadata exposed"),
    ("/admin.php", "medium", "Admin entry point is publicly reachable at a guessable URL"),
    ("/.well-known/security.txt", "info", "security.txt present (good practice)"),
    ("/robots.txt", "info", None),
    ("/sitemap.xml", "info", None),
]

ADMIN_HINTS = ["/admin", "/admin.html", "/dashboard", "/panel", "/manage", "/administrator"]

HEADERS_WANTED = [
    ("strict-transport-security", "high", "HSTS missing — browsers can be downgraded to HTTP"),
    ("content-security-policy", "medium", "CSP missing — weaker defense against XSS"),
    ("x-frame-options", "medium", "X-Frame-Options missing — clickjacking possible"),
    ("x-content-type-options", "high", "X-Content-Type-Options missing — MIME sniffing possible"),
    ("referrer-policy", "low", "Referrer-Policy missing"),
    ("permissions-policy", "low", "Permissions-Policy missing"),
]

REVEAL_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]

SECSCORE = {"critical": 40, "high": 20, "medium": 10, "low": 4, "info": 0}

def fetch(url, timeout=15, method="GET"):
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "DerycodeSecScan/1.0 (+defensive scan)",
        "Accept": "*/*",
    })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(500_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, ValueError) as e:
        return None, {}, str(e)

class Scan:
    def __init__(self, base):
        self.base = base.rstrip("/") + "/"
        self.host = urlparse(self.base).hostname
        self.findings = []

    def add(self, sev, title, detail):
        self.findings.append({"sev": sev, "title": title, "detail": detail})

    def run(self):
        print(f"\n=== Scanning {self.base} ===")
        st, headers, body = fetch(self.base)

        # 1. HTTPS enforcement
        if st is None:
            self.add("critical", "Site unreachable", f"Could not connect: {body[:120]}")
            return self
        if self.base.startswith("http://"):
            st2, _, _ = fetch("https://" + self.host)
            if st2 is None:
                self.add("high", "No HTTPS at all", "The site only works over plain HTTP — traffic and logins are readable by anyone on the network")
            else:
                self.add("high", "HTTPS not enforced", "Site served over HTTP; HTTPS exists but is not enforced (use a redirect + HSTS)")

        # 2. Security headers
        hl = {k.lower(): v for k, v in headers.items()}
        for h, sev, msg in HEADERS_WANTED:
            if h not in hl:
                self.add(sev, f"Missing header: {h}", msg)

        # 3. Technology/version disclosure
        for h in REVEAL_HEADERS:
            if h in hl:
                self.add("low", f"Technology disclosed: {h}", f"Value: {hl[h]} — helps attackers pick exploits. Consider hiding it")

        # 4. Passive path probes
        for path, sev, msg in PASSIVE_PATHS:
            st2, h2, b2 = fetch(urljoin(self.base, path), timeout=10)
            if st2 == 200 and len(b2) > 0:
                looks = not re.search(r"(?i)<html|<head|<!doctype|404|not found|<title>error", b2[:400])
                if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                    self.add("info", f"Found {path}", "Informational — review that it does not reveal private paths")
                elif looks or path in ("/.git/config", "/.env", "/phpinfo.php"):
                    self.add(sev, f"Exposed: {path}", msg or "Sensitive file is publicly downloadable")

        # 5. Admin panels — do they protect themselves?
        for path in ADMIN_HINTS:
            st2, h2, b2 = fetch(urljoin(self.base, path), timeout=10)
            if st2 == 200:
                if re.search(r"(?i)password|login|sign in|sign-in|passcode", b2[:20_000]):
                    self.add("medium", f"Admin/login page public: {path}", "Ensure strong passwords, rate limiting, and consider hiding or renaming the entry point")
                else:
                    self.add("high", f"Panel reachable without login: {path}", "A protected-looking page returned 200 with content — verify it cannot be used without authentication")
            elif st2 in (301, 302):
                self.add("info", f"{path} redirects", "Likely protected — good")
            elif st2 in (401, 403):
                self.add("info", f"{path} requires auth (good)", "Server refuses unauthenticated access")

        # 6. Directory listing
        for path in ["/", "/uploads/", "/images/", "/backups/"]:
            st2, _, b2 = fetch(urljoin(self.base, path), timeout=10)
            if st2 == 200 and re.search(r"(?i)<title>index of /", b2[:500]):
                self.add("high", f"Directory listing open: {path}", "Anyone can browse and download files — disable autoindex")

        # 7. Mixed content on the homepage
        if self.base.startswith("https"):
            mixed = re.findall(r"(?:src|href)=[\"'](http:)(?!//schemas)[^\"']+", body)
            if mixed:
                self.add("medium", f"Mixed content ({len(mixed)} links)", "HTTP resources on an HTTPS page can be blocked or tampered with")

        # 8. Cookie flags
        setc = headers.get("Set-Cookie", "")
        if setc:
            if "secure" not in setc.lower():
                self.add("high", "Cookie without Secure flag", "Session cookie can travel over HTTP and be stolen")
            if "httponly" not in setc.lower():
                self.add("medium", "Cookie without HttpOnly flag", "Cookie readable by JavaScript — XSS can steal the session")

        # 9. Forms over HTTP
        if self.base.startswith("http://"):
            if re.search(r"(?i)<input[^>]+type=[\"']?password", body):
                self.add("critical", "Password field on non-HTTPS page", "Credentials are sent in plain text — install TLS immediately")

        # 10. CORS misconfiguration
        acao = hl.get("access-control-allow-origin", "")
        if acao.strip() == "*" and hl.get("access-control-allow-credentials", "").lower() == "true":
            self.add("high", "CORS: any origin + credentials", "Any website can read authenticated responses from this site")

        # 11. Open API endpoints leaking data
        for path in ["/api", "/api/users", "/api/admin", "/api/config", "/api/keys"]:
            st2, h2, b2 = fetch(urljoin(self.base, path), timeout=8)
            if st2 == 200 and re.match(r"^[{\[]", b2.strip()[:2]) and len(b2) > 30:
                self.add("high", f"Open API endpoint: {path}", "Returns JSON without authentication — make sure no private data is exposed")

        return self

def grade(score):
    if score >= 60: return "F — critical risk"
    if score >= 35: return "D — high risk"
    if score >= 20: return "C — medium risk"
    if score >= 8:  return "B — low risk"
    return "A — hard target"

def report(scans, html_path=None):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_html = []
    for s in scans:
        s.findings.sort(key=lambda f: order[f["sev"]])
        score = sum(SECSCORE[f["sev"]] for f in s.findings)
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        print(f"\n──── {s.base} — score {score} ({grade(score)}) ────")
        for f in s.findings:
            print(f"  {icon[f['sev']]} [{f['sev'].upper():8}] {f['title']}")
            print(f"      {f['detail']}")
        if not s.findings:
            print("  ✅ No issues found by the safe checks.")
        if html_path:
            all_html.append(f"<h2>{s.base} — score {score} ({grade(score)})</h2><ul>" +
                "".join(f"<li class='{f['sev']}'><b>{f['title']}</b><br>{f['detail']}</li>" for f in s.findings) +
                "</ul>")
    if html_path:
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Derycode SecScan Report</title>
<style>body{{font-family:system-ui;max-width:820px;margin:24px auto;padding:0 16px;background:#0d1117;color:#e6edf3}}
li{{margin:10px 0;list-style:none;padding:10px 14px;border-radius:8px;background:#161b22;border:1px solid #30363d}}
li.critical{{border-color:#f85149}}li.high{{border-color:#fb8500}}li.medium{{border-color:#e3b341}}li.low{{border-color:#58a6ff}}li.info{{border-color:#8b949e}}
h1{{color:#58a6ff}}.b{{color:#8b949e}}</style></head><body>
<h1>Derycode SecScan Report</h1><p class='b'>Generated by Derycode SecScan · scan your own sites only</p>
{''.join(all_html)}</body></html>"""
        with open(html_path, "w") as fh:
            fh.write(html)
        print(f"\nHTML report saved: {html_path}")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(1)
    html_path = None
    if "--html" in args:
        i = args.index("--html"); html_path = args[i + 1]; del args[i:i + 2]
    scans = []
    for url in args:
        if not url.startswith("http"): url = "https://" + url
        scans.append(Scan(url).run())
    report(scans, html_path)
    worst = min((f["sev"] for s in scans for f in s.findings),
                key=lambda x: order[x], default="info")
    sys.exit(0 if worst in ("info",) else 2)

if __name__ == "__main__":
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    main()
