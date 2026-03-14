# PyGoat — OWASP Vulnerable Django Application (Source Excerpts)

These files are excerpted from [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat)
for SAST training purposes. Each file demonstrates a real vulnerability pattern
found in production Django/Python applications.

## How to scan these

```bash
# Bandit — Python SAST
bandit -r . -ll

# Semgrep — with Django-specific rules
semgrep --config p/django --config p/python .
```

## Vulnerabilities included

| File | Vulnerability | OWASP Top 10 |
|------|--------------|--------------|
| sql_injection.py | Raw SQL with user input | A03:2021 Injection |
| xss_views.py | Unescaped HTML output | A03:2021 Injection |
| command_injection.py | os.system() with user input | A03:2021 Injection |
| ssrf.py | Server-Side Request Forgery | A10:2021 SSRF |
| insecure_deserialization.py | pickle.loads on user data | A08:2021 Integrity |
| broken_auth.py | Weak session, no rate limiting | A07:2021 Auth Failures |
| crypto_failures.py | MD5 passwords, hardcoded keys | A02:2021 Crypto |
| idor.py | Insecure Direct Object Reference | A01:2021 Broken Access |

Original repo: https://github.com/adeyosemanputra/pygoat (MIT License)
