# TrustGate — Decision API daemon.
#
# Runs `trustgate serve` for adapters that prefer a warm process to a per-call
# CLI invocation (the voice gateway, or a coding adapter on a busy repo).

FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Dependencies first so a source edit does not invalidate the layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --extra server --extra judge

COPY trustgate/ ./trustgate/
RUN uv sync --frozen --extra server --extra judge


FROM python:3.12-slim

# The gate decides whether privileged actions may run, so it does not run as
# root itself.
RUN useradd --create-home --uid 10001 trustgate

COPY --from=builder --chown=trustgate:trustgate /build/.venv /app/.venv
COPY --from=builder --chown=trustgate:trustgate /build/trustgate /app/trustgate

WORKDIR /app
USER trustgate

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TRUSTGATE_CONSTITUTION=/policy/trustgate.constitution.yaml \
    TRUSTGATE_AUDIT_PATH=/audit/audit.jsonl

# Mount your policy read-only and the audit directory writable:
#   docker run --rm -p 8000:8000 \
#     -v "$PWD/trustgate.constitution.yaml:/policy/trustgate.constitution.yaml:ro" \
#     -v "$PWD/audit:/audit" trustgate
VOLUME ["/audit"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2).status==200 else 1)"

# Bound to 0.0.0.0 only because a container has its own network namespace;
# publish the port deliberately and keep it off untrusted networks.
ENTRYPOINT ["trustgate"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
