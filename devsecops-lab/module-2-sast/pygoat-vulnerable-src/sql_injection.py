# ============================================================
# VULNERABILITY: SQL Injection in Django views
# Source: Adapted from OWASP PyGoat
# OWASP: A03:2021 — Injection
# ============================================================

from django.shortcuts import render
from django.db import connection


# VULNERABLE: Raw SQL query with string concatenation
# An attacker can submit: ' OR '1'='1' --
# to dump all users from the database
def search_user(request):
    if request.method == "POST":
        username = request.POST.get("username", "")

        # THIS IS THE VULNERABLE LINE
        # User input goes directly into the SQL query
        query = "SELECT * FROM auth_user WHERE username = '" + username + "'"

        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()

        return render(request, "lab/search_results.html", {"users": rows})

    return render(request, "lab/search_user.html")


# VULNERABLE: f-string SQL injection — same issue, different syntax
def get_user_profile(request, user_id):
    query = f"SELECT * FROM user_profile WHERE id = {user_id}"

    with connection.cursor() as cursor:
        cursor.execute(query)
        row = cursor.fetchone()

    return render(request, "lab/profile.html", {"profile": row})


# SECURE VERSION (for comparison):
# def search_user_safe(request):
#     username = request.POST.get("username", "")
#     with connection.cursor() as cursor:
#         cursor.execute(
#             "SELECT * FROM auth_user WHERE username = %s",
#             [username]  # parameterized query — safe
#         )
#         rows = cursor.fetchall()
#     return render(request, "lab/search_results.html", {"users": rows})
