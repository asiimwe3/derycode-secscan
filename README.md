# Derycode SecScan

**Defensive security scanner for websites you own.** Run it before hackers do — it checks for the weaknesses attackers look for first: exposed files, open admin panels, missing security headers, and information leaks.

## Quick start (no installation needed — pure Python)

```bash
python3 secscan.py https://your-site.com
```

Scan several sites and save an HTML report:

```bash
python3 secscan.py https://site-a.com https://site-b.com --html report.html
```

## What it checks

1. HTTPS enforcement and TLS availability
2. Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
3. Exposed sensitive files (`.git/`, `.env`, SQL dumps, `phpinfo`, `composer.json`, `package.json`, `.htaccess`, `.DS_Store`, SVN metadata)
4. Open admin panels (`/admin`, `/admin.html`, `/dashboard`, `/panel`, `/manage`, `/administrator`) — and whether they demand login
5. Open directory listings
6. Mixed content (HTTP resources on HTTPS pages)
7. Cookie flags (Secure, HttpOnly)
8. Password fields on non-HTTPS pages (critical)
9. CORS misconfiguration (any origin + credentials)
10. Open API endpoints returning JSON without authentication
11. Technology/version disclosure in response headers

Each finding is scored and the site gets a letter grade from **A (hard target)** to **F (critical risk)**. Exit code is non-zero when something worse than informational is found, so it can run in CI pipelines.

## Reading results

Severity levels and what to do:

* CRITICAL — fix today (exposed secrets, open database files, passwords over HTTP)
* HIGH — fix this week (unprotected panels, missing anti-sniffing headers, cookie theft paths)
* MEDIUM — plan a fix (CSP, clickjacking protection, mixed content)
* LOW / INFO — hardening and hygiene

## Notes

* Static GitHub Pages sites cannot set custom security headers (platform limitation) — those findings are expected there and can't be fixed at the site level.
* The scanner performs passive checks and safe GET requests only. It never sends attack payloads, never attempts credential guessing, and never modifies anything.

## Legal

Use this tool only on systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.

## Platform

Part of the Derycode software suite — web, mobile, fintech, and security tools built in Uganda.
