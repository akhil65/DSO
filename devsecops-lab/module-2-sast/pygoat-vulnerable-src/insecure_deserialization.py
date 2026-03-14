# ============================================================
# VULNERABILITY: Insecure Deserialization
# Source: Adapted from OWASP PyGoat
# OWASP: A08:2021 — Software and Data Integrity Failures
# ============================================================

import pickle
import yaml
import base64
from django.http import HttpResponse, JsonResponse


# VULNERABLE: Unpickling user-supplied data
# An attacker crafts a malicious pickle payload that executes code:
#   import pickle, os
#   class Exploit:
#       def __reduce__(self):
#           return (os.system, ("rm -rf /",))
#   payload = base64.b64encode(pickle.dumps(Exploit())).decode()
def load_session(request):
    session_data = request.COOKIES.get("session_data", "")

    # THIS IS THE VULNERABLE LINE
    # Unpickling data from a cookie = remote code execution
    decoded = base64.b64decode(session_data)
    user_session = pickle.loads(decoded)

    return JsonResponse({"session": str(user_session)})


# VULNERABLE: YAML deserialization with yaml.load (not safe_load)
# yaml.load can instantiate arbitrary Python objects
def import_config(request):
    if request.method == "POST":
        yaml_content = request.POST.get("config", "")

        # THIS IS THE VULNERABLE LINE
        # yaml.load without Loader=yaml.SafeLoader is dangerous
        config = yaml.load(yaml_content)

        return JsonResponse({"config": config})

    return HttpResponse("POST a YAML config")


# VULNERABLE: eval() on user-supplied JSON-like data
# Developers sometimes use eval() instead of json.loads()
def parse_data(request):
    raw_data = request.GET.get("data", "{}")

    # THIS IS THE VULNERABLE LINE
    # eval() executes arbitrary Python code
    parsed = eval(raw_data)

    return JsonResponse({"parsed": str(parsed)})


# SECURE VERSION (for comparison):
# import json
# import yaml
#
# def load_session_safe(request):
#     # Use signed cookies (Django's built-in session framework)
#     # or JSON-based session data — NEVER pickle from user input
#     session_data = request.session.get("user_data", {})
#     return JsonResponse({"session": session_data})
#
# def import_config_safe(request):
#     yaml_content = request.POST.get("config", "")
#     config = yaml.safe_load(yaml_content)  # safe_load blocks code execution
#     return JsonResponse({"config": config})
#
# def parse_data_safe(request):
#     raw_data = request.GET.get("data", "{}")
#     parsed = json.loads(raw_data)  # json.loads is safe
#     return JsonResponse({"parsed": parsed})
