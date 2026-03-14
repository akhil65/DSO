# NodeGoat — OWASP Vulnerable Node.js Application (Source Excerpts)

These files are adapted from [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)
for SAST training purposes. Each file demonstrates real vulnerability patterns
found in production Node.js/Express applications.

## How to scan these

```bash
# Semgrep — with JavaScript and OWASP rules
semgrep --config p/owasp-top-ten --config p/javascript .

# CodeQL — scans automatically when pushed (GitHub Actions)
```

## Vulnerabilities included

| File | Vulnerability | OWASP Top 10 |
|------|--------------|--------------|
| server.js | Insecure config, no security headers | A05:2021 Misconfig |
| routes/user.js | SQL/NoSQL injection, IDOR | A03:2021 Injection |
| routes/session.js | Broken auth, weak sessions | A07:2021 Auth Failures |
| routes/contributions.js | XSS, mass assignment | A03:2021 Injection |

Original repo: https://github.com/OWASP/NodeGoat (Apache 2.0 License)
