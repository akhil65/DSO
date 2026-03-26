
"""
mitmproxy addon: LLM API traffic interceptor for Exercise 7.10
Save this file and run: mitmproxy -s scripts/mitmproxy/llm_interceptor.py
Or let Exercise 7.10 write it automatically.
"""
import json
import time
from pathlib import Path
from mitmproxy import http, ctx

LLM_ENDPOINTS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "openrouter.ai",
]

REPORT_DIR = Path("reports/7.10-prompt-injection")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

captured_requests = []

class LLMInterceptor:

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if not any(ep in host for ep in LLM_ENDPOINTS):
            return

        ctx.log.info(f"[LLM] Request to {host}{flow.request.path}")

        try:
            body = json.loads(flow.request.content.decode("utf-8", errors="replace"))
        except Exception:
            body = {"raw": flow.request.content.decode("utf-8", errors="replace")[:500]}

        capture = {
            "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%S"),
            "host":       host,
            "path":       flow.request.path,
            "method":     flow.request.method,
            "headers":    dict(flow.request.headers),
            "body":       body,
        }

        # Extract and log prompt structure
        messages = body.get("messages", [])
        system_prompt = next(
            (m.get("content","") for m in messages if m.get("role") == "system"),
            body.get("system", "")  # Anthropic format
        )
        user_messages = [m for m in messages if m.get("role") == "user"]

        if system_prompt:
            ctx.log.warn(f"[LLM] SYSTEM PROMPT: {system_prompt[:200]}...")
        if user_messages:
            last_user = user_messages[-1].get("content", "")
            ctx.log.info(f"[LLM] USER INPUT: {last_user[:200]}")

        # Check for injection risk: is user input concatenated into system prompt?
        if system_prompt and user_messages:
            last_user = user_messages[-1].get("content", "")
            if last_user and any(frag in system_prompt for frag in
                                  ["{user_input}", "{message}", "{{", "{{"]):
                ctx.log.error(
                    f"[LLM] INJECTION RISK: system prompt contains template "
                    f"placeholder that may receive unescaped user input"
                )
                capture["injection_risk"] = "template_injection"

        captured_requests.append(capture)

        # Save incrementally
        out = REPORT_DIR / f"request_{len(captured_requests):04d}.json"
        out.write_text(json.dumps(capture, indent=2))
        ctx.log.info(f"[LLM] Saved to {out}")

    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if not any(ep in host for ep in LLM_ENDPOINTS):
            return

        try:
            resp_body = json.loads(flow.response.content.decode("utf-8", errors="replace"))
        except Exception:
            return

        # Extract response text
        response_text = ""
        choices = resp_body.get("choices", [])
        if choices:
            response_text = choices[0].get("message", {}).get("content", "")
        content_block = resp_body.get("content", [])
        if content_block and isinstance(content_block, list):
            response_text = content_block[0].get("text", "")

        if response_text:
            ctx.log.info(f"[LLM] RESPONSE: {response_text[:300]}")

            # Check if system prompt was leaked
            if any(phrase in response_text.lower() for phrase in
                   ["you are", "your role", "your task", "as an ai", "system:"]):
                ctx.log.error(
                    f"[LLM] SYSTEM PROMPT LEAK DETECTED in response: "
                    f"{response_text[:200]}"
                )

addons = [LLMInterceptor()]
