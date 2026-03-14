# ============================================================
# VULNERABILITY: Insecure Direct Object Reference (IDOR)
# Source: Adapted from OWASP PyGoat
# OWASP: A01:2021 — Broken Access Control
# ============================================================

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required


# VULNERABLE: IDOR — any authenticated user can view any other user's data
# by simply changing the user_id in the URL
# e.g., /api/user/1/profile → /api/user/2/profile
@login_required
def user_profile(request, user_id):
    # THIS IS THE VULNERABLE CODE
    # No check that request.user.id == user_id
    # Any logged-in user can access any other user's profile
    from django.contrib.auth.models import User

    user = User.objects.get(id=user_id)

    return JsonResponse({
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
    })


# VULNERABLE: IDOR in file download
# An attacker changes invoice_id to download other users' invoices
@login_required
def download_invoice(request, invoice_id):
    import os

    # THIS IS THE VULNERABLE CODE
    # No ownership check — any user can download any invoice
    invoice_path = f"/var/app/invoices/{invoice_id}.pdf"

    if os.path.exists(invoice_path):
        with open(invoice_path, "rb") as f:
            from django.http import FileResponse
            return FileResponse(f, content_type="application/pdf")

    return JsonResponse({"error": "Invoice not found"}, status=404)


# VULNERABLE: Mass assignment / parameter tampering
# An attacker adds "is_admin=True" to the POST data to escalate privileges
@login_required
def update_profile(request):
    if request.method == "POST":
        user = request.user

        # THIS IS THE VULNERABLE CODE
        # Blindly updating all submitted fields
        # An attacker can add is_staff=True or is_superuser=True
        for key, value in request.POST.items():
            if hasattr(user, key):
                setattr(user, key, value)

        user.save()

        return JsonResponse({"status": "Profile updated"})

    return render(request, "lab/edit_profile.html")


# SECURE VERSION (for comparison):
# @login_required
# def user_profile_safe(request, user_id):
#     # Check ownership — users can only view their own profile
#     if request.user.id != int(user_id):
#         return JsonResponse({"error": "Forbidden"}, status=403)
#
#     return JsonResponse({
#         "username": request.user.username,
#         "email": request.user.email,
#     })
#
# @login_required
# def update_profile_safe(request):
#     # Allowlist — only permit safe fields to be updated
#     ALLOWED_FIELDS = ["first_name", "last_name", "email"]
#     for key, value in request.POST.items():
#         if key in ALLOWED_FIELDS:
#             setattr(request.user, key, value)
#     request.user.save()
