#!/usr/bin/env python3
"""
 ██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗  ██████╗ ██████╗ ██████╗  ██╗
██╔═══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██╔══██╗███║
██║   ██║█████╗  ██████╔╝██║██████╔╝█████╗  ██║   ██║██║   ██║██║  ██║██████╔╝╚██║
██║   ██║██╔══╝  ██╔══██╗██║██╔═══╝ ██╔══╝  ██║   ██║██║   ██║██║  ██║██╔═══╝ ╚██║
╚██████╔╝███████╗██║  ██║██║██║     ███████╗╚██████╔╝╚██████╔╝██████╔╝██║     ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝
Derycode SecScan v2.0 — defensive attack-surface scanner for sites you OWN.
Terminal aesthetic, 8 modules, safe passive + canary probes only.
No password attacks. No WiFi. No exploitation. Your sites only.
"""

import sys, ssl, socket, re, json, time, hashlib
import urllib.request, urllib.error
from urllib.parse import urlparse, urljoin, parse_qs

G   = "\033[32m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
D   = "\033[2m"; W = "\033[97m"; B = "\033[94m"; X = "\033[0m"; BOLD = "\033[1m"

REVEAL_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]

HEADERS_WANTED = [
    ("strict-transport-security", "high"),
    ("content-security-policy", "medium"),
    ("x-frame-options", "medium"),
    ("x-content-type-options", "high"),
    ("referrer-policy", "low"),
    ("permissions-policy", "low"),
]

SENSITIVE_PATHS = [
    ("/.git/config", "critical", "GIT REPO EXPOSED — full source downloadable"),
    ("/.git/HEAD", "high", "Git metadata exposed"),
    ("/.env", "critical", "ENV FILE EXPOSED — secrets may be public"),
    ("/.env.local", "critical", "Local env file exposed"),
    ("/.htaccess", "high", ".htaccess exposed"),
    ("/.DS_Store", "low", "macOS index exposed"),
    ("/db.sql", "critical", "SQL dump exposed"),
    ("/backup.sql", "critical", "SQL backup exposed"),
    ("/database.sql", "critical", "Database file exposed"),
    ("/backup.zip", "high", "Backup archive exposed"),
    ("/site.zip", "high", "Site archive exposed"),
    ("/phpinfo.php", "critical", "phpinfo page exposed"),
    ("/info.php", "high", "PHP info page exposed"),
    ("/server-status", "medium", "Apache server-status exposed"),
    ("/.svn/entries", "high", "SVN metadata exposed"),
    ("/composer.json", "medium", "composer.json exposed — dependency versions leak"),
    ("/package.json", "medium", "package.json exposed — dependency versions leak"),
    ("/admin/config", "high", "Admin config path reachable"),
    ("/.well-known/security.txt", "info", "security.txt present (good practice)"),
    ("/config.js", "medium", "Frontend config file reachable — check for hardcoded secrets"),
    ("/secrets.json", "critical", "secrets file exposed"),
    ("/credentials.json", "critical", "credentials file exposed"),
    ("/keys.json", "critical", "keys file exposed"),
    ("/.gitignore", "low", ".gitignore exposed — reveals internal file structure"),
]

BACKUP_SUFFIXES = [".bak", ".old", ".orig", "~", ".save"]
BACKUP_TARGETS = ["index.html", "index.php", "admin.html", ".env", "config.js"]

ADMIN_HINTS = ["/admin", "/admin.html", "/admin.php", "/dashboard", "/panel",
               "/manage", "/administrator", "/console", "/cpanel"]

API_PATHS = ["/api", "/api/users", "/api/admin", "/api/config", "/api/keys",
             "/api/orders", "/api/bookings", "/graphql"]

# benign marker used to test for unescaped reflection (XSS surface)
CANARY = "derScanqx7marker"

SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"sk_live_[0-9a-zA-Z]{20,}", "Stripe LIVE secret key"),
    (r"pk_live_[0-9a-zA-Z]{20,}", "Stripe live publishable key"),
    (r"ghp_[0-9A-Za-z]{36}", "GitHub personal access token"),
    (r"eyJhbGciOi[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT token"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "Private key block"),
    (r"AIzaSy[0-9A-Za-z_\-]{33}", "Google API key"),
    (r"(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", "Generic API key assignment"),
    (r"supabase\.co.*(anon|service_role)[^\"']*", "Supabase key reference"),
]

KNOWN_VULN_JS = {
    "jquery": {"1.11.0": "XSS", "1.11.1": "XSS", "2.1.0": "XSS", "2.1.1": "XSS", "1.9.0": "XSS"},
    "bootstrap": {"3.3.5": "XSS", "3.3.6": "XSS"},
    "angular": {"1.2.0": "XSS", "1.3.0": "XSS"},
    "moment": {"2.15.0": "ReDoS", "2.18.0": "ReDoS"},
    "lodash": {"4.17.4": "prototype pollution", "4.17.15": "prototype pollution"},
}

SECSCORE = {"critical": 40, "high": 20, "medium": 10, "low": 4, "info": 0}

def fetch(url, timeout=12, method="GET", data=None, hdrs=None):
    h = {"User-Agent": "DerycodeSecScan/2.0 (defensive scan)", "Accept": "*/*"}
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, data=data, headers=h)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(800_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception as e:
        return None, {}, str(e)

def type_line(txt, delay=0.012):
    print(txt + X, flush=True)
    time.sleep(delay)

class Scan:
    def __init__(self, base):
        self.base = base.rstrip("/") + "/"
        self.host = urlparse(self.base).hostname
        self.findings = []
        self.body, self.headers, self.status = "", {}, None

    def hit(self, sev, title, detail):
        self.findings.append({"sev": sev, "title": title, "detail": detail})

    def banner(self, mod, name):
        print(f"\n{G}{BOLD}┌──[{X}{B}{self.host}{X}{G}{BOLD}]─[{X}{B}module {mod}/8{X}{G}{BOLD}]{X}")
        print(f"{G}{BOLD}└─$ {X}{W}{BOLD}{name}{X}", flush=True)

    def ok(self, msg):   type_line(f"{G}  [✓] {X}{msg}")
    def warn(self, msg): type_line(f"{Y}  [~] {X}{msg}")
    def bad(self, sev, msg):
        color = {"critical": R, "high": R, "medium": Y, "low": B, "info": D}[sev]
        type_line(f"{color}  [!] [{sev.upper():8}] {X}{W}{BOLD}{msg}{X}")

    # ── MODULE 1: RECON ─────────────────────────────────────
    def m1_recon(self):
        self.banner(1, "RECON — server, TLS, technology fingerprint")
        st, headers, body = fetch(self.base)
        self.status, self.headers, self.body = st, headers, body
        if st is None:
            self.hit("critical", "Target unreachable", body[:150]); return
        self.ok(f"target answered HTTP {st}")
        # TLS
        if self.base.startswith("https://"):
            self.ok("transport: TLS active")
        else:
            st2, _, _ = fetch("https://" + self.host)
            self.bad("high", "plain HTTP in use" + (" — HTTPS unavailable!" if st2 is None else " — HTTPS exists, enforce redirect + HSTS"))
            self.hit("high", "HTTPS not enforced", "Serve over HTTPS with a redirect and HSTS header")
        # headers
        for h, sev in HEADERS_WANTED:
            if h not in headers:
                self.bad(sev, f"missing header: {h}")
                self.hit(sev, f"Missing header: {h}", "Standard security header absent")
            else:
                self.ok(f"header present: {h}")
        # disclosure
        for h in REVEAL_HEADERS:
            if h in headers:
                self.warn(f"technology disclosed: {h} = {headers[h]}")
                self.hit("low", f"Technology disclosed: {h}", f"Value: {headers[h]} — helps attackers pick exploits")
        # cookies
        sc = headers.get("set-cookie", "")
        if sc:
            if "secure" not in sc.lower():
                self.bad("high", "cookie missing Secure flag"); self.hit("high", "Cookie without Secure flag", "Can be stolen over HTTP")
            else: self.ok("cookie has Secure flag")
            if "httponly" not in sc.lower():
                self.bad("medium", "cookie missing HttpOnly flag"); self.hit("medium", "Cookie without HttpOnly", "XSS can read the session")
            else: self.ok("cookie has HttpOnly flag")

    # ── MODULE 2: EXPOSED FILES ─────────────────────────────
    def m2_files(self):
        self.banner(2, "EXPOSED FILES — git, env, dumps, backups")
        found = 0
        for path, sev, msg in SENSITIVE_PATHS:
            st, _, b2 = fetch(urljoin(self.base, path), timeout=8)
            if st == 200 and b2:
                junk = re.search(r"(?i)<html|<head|<!doctype|404|not found|<title>error", b2[:300])
                if path == "/.well-known/security.txt":
                    self.ok("security.txt present"); self.hit("info", "security.txt present", "Good practice")
                elif not junk or path in ("/.git/config", "/.env", "/phpinfo.php"):
                    self.bad(sev, f"{path} — {msg}"); self.hit(sev, f"Exposed: {path}", msg); found += 1
        for name in BACKUP_TARGETS:
            for suf in BACKUP_SUFFIXES:
                st, _, b2 = fetch(urljoin(self.base, name + suf), timeout=8)
                if st == 200 and b2 and not re.search(r"(?i)<html|404|not found", b2[:200]):
                    self.bad("high", f"backup file: {name}{suf}"); self.hit("high", f"Backup file exposed: {name}{suf}", "Delete server-side backups from web roots"); found += 1
        if not found: self.ok(f"no exposed sensitive files ({len(SENSITIVE_PATHS)+len(BACKUP_TARGETS)*len(BACKUP_SUFFIXES)} probes)")
        # dir listing
        for path in ["/", "/uploads/", "/images/", "/backups/"]:
            st, _, b2 = fetch(urljoin(self.base, path), timeout=8)
            if st == 200 and re.search(r"(?i)<title>index of /", b2[:400]):
                self.bad("high", f"directory listing open: {path}"); self.hit("high", f"Directory listing: {path}", "Disable autoindex")

    # ── MODULE 3: ACCESS CONTROL ────────────────────────────
    def m3_access(self):
        self.banner(3, "ACCESS CONTROL — admin panels, auth gates, open APIs")
        for path in ADMIN_HINTS:
            st, h2, b2 = fetch(urljoin(self.base, path), timeout=8)
            if st == 200:
                if re.search(r"(?i)password|login|sign in|passcode", b2[:20_000]):
                    self.warn(f"public login at {path} — needs rate limiting + strong password policy")
                    self.hit("medium", f"Public login page: {path}", "Add rate limiting, 2FA if possible, and strong password requirements")
                else:
                    self.bad("high", f"panel responds WITHOUT login: {path}")
                    self.hit("high", f"Panel reachable without login: {path}", "Verify this page cannot be used unauthenticated")
            elif st in (301, 302):
                self.ok(f"{path} redirects (likely protected)")
            elif st in (401, 403):
                self.ok(f"{path} requires auth (good)")
        for path in API_PATHS:
            st, h2, b2 = fetch(urljoin(self.base, path), timeout=8)
            if st == 200 and re.match(r"^[{\[]", (b2 or "").strip()) and len(b2) > 30:
                self.bad("high", f"open API endpoint: {path} returns JSON to anyone")
                self.hit("high", f"Open API endpoint: {path}", "Returns data without authentication — verify no private data leaks")

    # ── MODULE 4+5: INJECTION & XSS SURFACE ─────────────────
    def m45_surface(self):
        self.banner("4+5", "INJECTION & XSS SURFACE — forms, params, CSRF, reflection")
        forms = re.findall(r"<form[^>]*>(.*?)</form>", self.body, re.S | re.I)
        inputs = re.findall(r"<(input|textarea|select)[^>]*name=[\"']([^\"']+)[\"'][^>]*>", self.body, re.I)
        self.ok(f"{len(forms)} form(s), {len(inputs)} input field(s) discovered")
        # CSRF tokens
        for i, f in enumerate(forms):
            has_csrf = re.search(r"(?i)csrf|_token|token", f)
            has_pass = re.search(r"(?i)type=[\"']?password", f)
            if has_pass and not has_csrf:
                self.warn(f"form #{i+1} has a password field but no visible CSRF token")
                self.hit("medium", f"Form #{i+1}: no CSRF token", "Add CSRF protection to state-changing forms")
        # URL parameters
        q = parse_qs(urlparse(self.base).query)
        params = self.body and [] or []
        urls = re.findall(r"href=[\"']([^\"']*\?[^\"']+)=[\"']", self.body)
        if urls: self.warn(f"{len(urls)} in-page URL parameters — validate them server-side")
        # reflection canary on own form action (safe, benign string)
        for f in forms:
            action = re.search(r"action=[\"']([^\"']+)[\"']", f, re.I)
            if not action: continue
            target = urljoin(self.base, action.group(1))
            st, _, b2 = fetch(target + ("&" if "?" in target else "?") + f"scan={CANARY}", timeout=8)
            if st == 200 and CANARY in (b2 or ""):
                esc = CANARY not in re.sub(r"&#\d+;|&lt;|&gt;|&#x[0-9a-f]+;", "", b2 or " ")
                if re.search(rf"<[^>]*>{CANARY}", b2) or re.search(rf"[\"']>{CANARY}", b2):
                    self.bad("high", f"UNESCAPED REFLECTION at {target} — XSS surface confirmed")
                    self.hit("high", f"XSS surface: {target}", "Parameter reflected unescaped — encode output server-side")
                else:
                    self.ok(f"parameter reflected at {target} (appears encoded — verify)")
            break  # first form only, keep scan light
        if not forms: self.ok("no forms on entry page — injection surface minimal")

    # ── MODULE 6: SECRETS ───────────────────────────────────
    def m6_secrets(self):
        self.banner(6, "SECRETS — API keys, tokens, private data in source")
        found = 0
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, self.body):
                s = m.group(0)
                if len(s) > 12:
                    self.bad("critical", f"{label} found in page source!")
                    self.hit("critical", f"Secret exposed: {label}", f"Value found in HTML source ({s[:18]}…) — rotate this key and move it server-side"); found += 1
        emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", self.body))
        person_emails = [e for e in emails if not re.search(r"(?i)(sentry|wixpress|example|domain|your?e?mail)", e)]
        if len(person_emails) > 0:
            self.warn(f"{len(person_emails)} email address(es) in source (normal for contact, watch for internal ones)")
        if not found: self.ok("no hardcoded API keys or tokens detected")

    # ── MODULE 7: SUPPLY CHAIN ──────────────────────────────
    def m7_chain(self):
        self.banner(7, "SUPPLY CHAIN — outdated JS libraries, missing SRI")
        scripts = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", self.body, re.I)
        vuln = 0
        for src_url in scripts:
            for lib, vers in KNOWN_VULN_JS.items():
                m = re.search(rf"/{lib}[@/-]?(\d+\.\d+\.\d+)?", src_url, re.I)
                if m and m.group(1) and m.group(1) in vers:
                    self.bad("high", f"outdated {lib} {m.group(1)} — known {vers[m.group(1)]}")
                    self.hit("high", f"Outdated library: {lib} {m.group(1)}", f"Known {vers[m.group(1)]} issue — upgrade")
                    vuln += 1
            if "cdn" in src_url and "integrity=" not in src_url:
                m = re.search(r"src=[\"']([^\"']+cdn[^\"']+)[\"']", self.body, re.I)
        no_sri = [s for s in scripts if "cdn" in s.lower() and not re.search(r"integrity=", self.body)]
        if no_sri: self.warn(f"{len(no_sri)} CDN script(s) without SubResource Integrity")
        if not vuln: self.ok(f"{len(scripts)} script(s) checked — no known-vulnerable library versions")

    # ── MODULE 8: TRANSPORT & FRAMING ───────────────────────
    def m8_transport(self):
        self.banner(8, "TRANSPORT — mixed content, clickjacking, HTTP methods")
        if self.base.startswith("https://"):
            mixed = re.findall(r"(?:src|href)=[\"']http:[\"']?[^\"']*", self.body)
            mixed = re.findall(r"(?:src|href)=[\"'](http:)(?!//schemas)[^\"']+", self.body)
            if mixed:
                self.bad("medium", f"{len(mixed)} mixed-content HTTP resources")
                self.hit("medium", "Mixed content", "HTTP resources on HTTPS page can be blocked or tampered")
            else: self.ok("no mixed content on entry page")
        if re.search(r"(?i)<input[^>]+type=[\"']?password", self.body) and self.base.startswith("http://"):
            self.bad("critical", "password field on plain-HTTP page")
            self.hit("critical", "Password over HTTP", "Credentials travel in clear text — install TLS")
        st, h2, _ = fetch(self.base, method="OPTIONS", timeout=8)
        allow = h2.get("allow", "") or h2.get("access-control-allow-methods", "")
        if allow:
            risky = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if risky:
                self.warn(f"risky HTTP methods allowed: {', '.join(risky)}")
                self.hit("medium", f"Risky HTTP methods: {', '.join(risky)}", "Disable unneeded methods on the server")
            else: self.ok(f"methods allowed: {allow}")
        acao = self.headers.get("access-control-allow-origin", "")
        if acao.strip() == "*" and "true" in self.headers.get("access-control-allow-credentials", "").lower():
            self.bad("high", "CORS: any origin + credentials allowed")
            self.hit("high", "CORS misconfigured", "Any site can read authenticated responses")
        elif acao.strip() == "*":
            self.warn("CORS open to any origin — fine for public data, dangerous for private data")

def run(base, html_path=None):
    print(f"""{G}{BOLD}
 ██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗  ██████╗ ██████╗ ██████╗  ██╗
██╔═══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██╔══██╗███║
██║   ██║█████╗  ██████╔╝██║██████╔╝█████╗  ██║   ██║██║   ██║██║  ██║██████╔╝╚██║
██║   ██║██╔══╝  ██╔══██╗██║██╔═══╝ ██╔══╝  ██║   ██║██║   ██║██║  ██║██╔═══╝ ╚██║
╚██████╔╝███████╗██║  ██║██║██║     ███████╗╚██████╔╝╚██████╔╝██████╔╝██║     ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝{X}
{D}  defensive attack-surface scanner · owned targets only · no payloads · no credentials{X}
{B}  target: {W}{BOLD}{base}{X}
""")
    s = Scan(base)
    for mod in (s.m1_recon, s.m2_files, s.m3_access, s.m45_surface, s.m6_secrets, s.m7_chain, s.m8_transport):
        try: mod()
        except Exception as e: s.warn(f"module error: {e}")
    # results
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    s.findings.sort(key=lambda f: order[f["sev"]])
    score = sum(SECSCORE[f["sev"]] for f in s.findings)
    grade = ("F — critical risk" if score >= 60 else "D — high risk" if score >= 35
             else "C — medium risk" if score >= 20 else "B — low risk" if score >= 8 else "A — hard target")
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    print(f"\n{G}{BOLD}┌──[RESULTS]───────────────────────────────────────{X}")
    print(f"{G}{BOLD}│{X} {W}risk score {BOLD}{score}{X} · grade {BOLD}{grade}{X}")
    for f in s.findings:
        c = {"critical": R, "high": R, "medium": Y, "low": B, "info": D}[f["sev"]]
        print(f"{G}{BOLD}│{X} {icon[f['sev']]} {c}[{f['sev'].upper():8}]{X} {W}{f['title']}{X}")
        print(f"{G}{BOLD}│{X}        {D}{f['detail']}{X}")
    if not s.findings:
        print(f"{G}{BOLD}│{X} {G}✓ clean — no issues found by safe checks{X}")
    print(f"{G}{BOLD}└──────────────────────────────────────────────────{X}{X}")
    return s, score, grade

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
        s, score, grade = run(url)
        scans.append((s, score, grade))
    if html_path:
        blocks = []
        for s, score, grade in scans:
            blocks.append(f"<h2>{s.base}</h2><p>score {score} — {grade}</p><ul>" + "".join(
                f"<li class='{f['sev']}'><b>{f['title']}</b><br>{f['detail']}</li>" for f in s.findings) + "</ul>")
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>SecScan Report</title>
<style>body{{font-family:ui-monospace,Consolas,monospace;background:#0d1117;color:#39ff14;padding:30px}}
h1,h2{{color:#39ff14}}p{{color:#8b949e}}li{{margin:10px 0;list-style:none;padding:10px 14px;border:1px solid #30363d;border-radius:8px}}
li.critical{{border-color:#f85149}}li.high{{border-color:#fb8500}}li.medium{{border-color:#e3b341}}li.low{{border-color:#58a6ff}}</style></head>
<body><h1>Derycode SecScan v2.0 — Report</h1>{''.join(blocks)}</body></html>"""
        with open(html_path, "w") as fh: fh.write(html)
        print(f"{G}[*] HTML report saved: {X}{html_path}")

if __name__ == "__main__":
    main()
