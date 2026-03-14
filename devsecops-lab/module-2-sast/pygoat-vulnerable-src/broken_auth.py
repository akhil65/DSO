# ============================================================
# VULNERABILITY: Broken Authentication
# Source: Adapted from OWASP PyGoat
# OWASP: A07:2021 — Identification and Authentication Failures
# ============================================================

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login


# VULNERABLE: No rate limiting on login — allows brute force
# An attacker can try millions of password combinations
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        # THIS IS THE VULNERABLE CODE
        # No rate limiting, no account lockout, no CAPTCHA
        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("/dashboard")
        else:
            # VULNERABLE: Tells attacker whether the username exists
            from django.contrib.auth.models import User
            if User.objects.filter(username=username).exists():
                error = "Invalid password"  # leaks that username exists
            else:
                error = "User not found"  # leaks that username doesn't exist

            return render(request, "lab/login.html", {"error": error})

    return render(request, "lab/login.html")


# VULNERABLE: Weak password reset — predictable token
import random
import time

def password_reset(request):
    if request.method == "POST":
        email = request.POST.get("email", "")

        # THIS IS THE VULNERABLE LINE
        # Token is based on timestamp + small random number
        # An attacker can predict or brute force this
        token = str(int(time.time())) + str(random.randint(1000, 9999))

        # Store token and send email...
        return JsonResponse({"message": "Reset email sent", "debug_token": token})

    return render(request, "lab/reset.html")


# VULNERABLE: Session fixation — session ID not regenerated after login
def insecure_login(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    user = authenticate(username=username, password=password)
    if user:
        # THIS IS THE VULNERABLE CODE
        # Session ID is NOT regenerated after authentication
        # An attacker who knows the pre-auth session ID
        # can hijack the authenticated session
        request.session["user_id"] = user.id
        request.session["is_authenticated"] = True
        # Missing: request.session.cycle_key()
        return redirect("/dashboard")


# SECURE VERSION (for comparison):
# from django.contrib.auth import login
# from django_ratelimit.decorators import ratelimit
#
# @ratelimit(key="ip", rate="5/m", block=True)
# def login_view_safe(request):
#     username = request.POST.get("username", "")
#     password = request.POST.get("password", "")
#     user = authenticate(username=username, password=password)
#     if user:
#         login(request, user)  # Django's login() regenerates session
#         return redirect("/dashboard")
#     # Generic error — doesn't reveal if username exists
#     return render(request, "login.html", {"error": "Invalid credentials"})
