# ============================================================
# VULNERABILITY: Server-Side Request Forgery (SSRF)
# Source: Adapted from OWASP PyGoat
# OWASP: A10:2021 — Server-Side Request Forgery
# ============================================================

import requests
from django.shortcuts import render
from django.http import HttpResponse


# VULNERABLE: Fetching a URL provided by the user without validation
# An attacker can request internal services:
#   url=http://169.254.169.254/latest/meta-data/   (AWS metadata)
#   url=http://localhost:6379/                       (internal Redis)
#   url=http://192.168.1.1/admin                     (internal router)
def fetch_url(request):
    if request.method == "POST":
        url = request.POST.get("url", "")

        # THIS IS THE VULNERABLE LINE
        # The server fetches whatever URL the user provides
        # including internal network resources
        response = requests.get(url)

        return HttpResponse(
            f"Status: {response.status_code}\n\n{response.text}"
        )

    return render(request, "lab/ssrf.html")


# VULNERABLE: SSRF via image download
# An attacker uses this to scan internal ports or exfiltrate data
def download_image(request):
    image_url = request.GET.get("src", "")

    # THIS IS THE VULNERABLE LINE
    # No validation on the URL — attacker controls the destination
    response = requests.get(image_url, stream=True)

    return HttpResponse(
        response.content,
        content_type=response.headers.get("Content-Type", "image/png")
    )


# SECURE VERSION (for comparison):
# import urllib.parse
# ALLOWED_HOSTS = ["example.com", "cdn.example.com"]
#
# def fetch_url_safe(request):
#     url = request.POST.get("url", "")
#     parsed = urllib.parse.urlparse(url)
#
#     # Validate scheme is HTTPS only
#     if parsed.scheme != "https":
#         return HttpResponse("Only HTTPS URLs allowed", status=400)
#
#     # Validate host is in allowlist
#     if parsed.hostname not in ALLOWED_HOSTS:
#         return HttpResponse("Domain not allowed", status=403)
#
#     response = requests.get(url, timeout=5)
#     return HttpResponse(response.text)
