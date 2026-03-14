# ============================================================
# VULNERABILITY: OS Command Injection
# Source: Adapted from OWASP PyGoat
# OWASP: A03:2021 — Injection
# ============================================================

import os
import subprocess
from django.shortcuts import render
from django.http import HttpResponse


# VULNERABLE: os.system() with user-controlled input
# An attacker can submit: 127.0.0.1; cat /etc/passwd
# to execute arbitrary commands on the server
def ping_view(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip", "")

        # THIS IS THE VULNERABLE LINE
        # User input goes directly into a shell command
        os.system("ping -c 3 " + ip_address)

        return HttpResponse("Ping executed for " + ip_address)

    return render(request, "lab/ping.html")


# VULNERABLE: subprocess with shell=True
# Same issue as above but using subprocess module
def nslookup_view(request):
    if request.method == "POST":
        domain = request.POST.get("domain", "")

        # THIS IS THE VULNERABLE LINE
        # shell=True with unsanitized input = command injection
        result = subprocess.check_output(
            "nslookup " + domain,
            shell=True,
            stderr=subprocess.STDOUT
        )

        return HttpResponse(result.decode())

    return render(request, "lab/nslookup.html")


# VULNERABLE: subprocess.Popen with shell=True
def traceroute_view(request):
    host = request.GET.get("host", "")

    # THIS IS THE VULNERABLE LINE
    proc = subprocess.Popen(
        "traceroute " + host,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    return HttpResponse(stdout.decode())


# SECURE VERSION (for comparison):
# def ping_view_safe(request):
#     ip_address = request.POST.get("ip", "")
#     # Validate input — only allow IP-like patterns
#     import re
#     if not re.match(r'^[\d.]+$', ip_address):
#         return HttpResponse("Invalid IP address", status=400)
#     # Use list form (no shell interpretation)
#     result = subprocess.run(
#         ["ping", "-c", "3", ip_address],
#         capture_output=True, text=True
#     )
#     return HttpResponse(result.stdout)
