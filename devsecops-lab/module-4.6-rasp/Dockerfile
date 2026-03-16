# ── Stage 1: builder ──────────────────────────────────────────────────────
# Use a shell-equipped Node.js image to prepare the RASP hook file.
# Juice Shop's final image is distroless (no /bin/sh), so we can't run
# RUN commands there — we use a multi-stage build instead.
FROM node:20-alpine AS builder

WORKDIR /build

# Copy our custom RASP hook into the builder stage
COPY rasp-hook.js /build/rasp-hook.js

# ── Stage 2: final ────────────────────────────────────────────────────────
# Start from the official Juice Shop image (distroless — no shell)
FROM bkimminich/juice-shop:latest

# Copy the RASP hook JS file from the builder stage into Juice Shop's directory.
# --chmod=644 sets read permissions for all users including the non-root user
# (uid 65532 / nobody) that Juice Shop's distroless image runs as.
COPY --from=builder --chmod=644 /build/rasp-hook.js /juice-shop/rasp-hook.js

# NODE_OPTIONS --require loads rasp-hook.js as the VERY FIRST thing Node.js
# does — before any app code runs. This patches sqlite3 internals at startup.
# No shell needed — this is a Node.js flag, not a shell command.
ENV NODE_OPTIONS="--require /juice-shop/rasp-hook.js"

EXPOSE 3000
