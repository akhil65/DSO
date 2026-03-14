# ============================================================
# VULNERABILITY: Cryptographic Failures
# Source: Adapted from OWASP PyGoat
# OWASP: A02:2021 — Cryptographic Failures
# ============================================================

import hashlib
import base64
from django.contrib.auth.models import User


# VULNERABILITY: Hardcoded secret key
# In production Django, SECRET_KEY should come from env vars
SECRET_KEY = "django-insecure-!k3y-th4t-sh0uld-n3v3r-b3-c0mm1tt3d"
DATABASE_PASSWORD = "admin123"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"


# VULNERABLE: MD5 for password hashing (Bandit: B303)
# MD5 is cryptographically broken — rainbow tables exist for it
def store_password_md5(username, password):
    # THIS IS THE VULNERABLE LINE
    hashed = hashlib.md5(password.encode()).hexdigest()
    # Storing MD5 hash in database — trivially crackable
    return {"username": username, "password_hash": hashed}


# VULNERABLE: SHA1 for password hashing (also broken)
def store_password_sha1(username, password):
    # THIS IS THE VULNERABLE LINE
    hashed = hashlib.sha1(password.encode()).hexdigest()
    return {"username": username, "password_hash": hashed}


# VULNERABLE: Base64 "encryption" — this is encoding, NOT encryption
# Developers sometimes think base64 provides confidentiality
def encrypt_token(token):
    # THIS IS THE VULNERABLE LINE
    # base64 is trivially reversible — it's NOT encryption
    return base64.b64encode(token.encode()).decode()


def decrypt_token(encoded_token):
    return base64.b64decode(encoded_token.encode()).decode()


# VULNERABLE: Weak comparison that leaks timing information
# An attacker can use timing attacks to guess the token
def verify_reset_token(user_token, stored_token):
    # THIS IS THE VULNERABLE LINE
    # String comparison short-circuits on first mismatch
    # leaking information about how many characters are correct
    if user_token == stored_token:
        return True
    return False


# SECURE VERSION (for comparison):
# import bcrypt
# import hmac
#
# def store_password_safe(username, password):
#     # bcrypt: salted, slow by design, resistant to rainbow tables
#     hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
#     return {"username": username, "password_hash": hashed}
#
# def verify_token_safe(user_token, stored_token):
#     # hmac.compare_digest: constant-time comparison
#     return hmac.compare_digest(user_token, stored_token)
