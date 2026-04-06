FROM python:3.12-slim

# ── Labels ──────────────────────────────────────────────────────────────────
LABEL maintainer="David King Boison"
LABEL system="SANKƆFA-BRIDGE"
LABEL version="1.0.0"
LABEL framework="Visionary Prompt Framework (VPF)"
LABEL description="Sovereign Data Orchestration System — African Digital Finance Corridor"

# ── System dependencies ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ────────────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies ──────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ─────────────────────────────────────────────────────────
COPY . .

# ── Non-root user for security ───────────────────────────────────────────────
RUN useradd -m -u 1001 sankofa && \
    mkdir -p /app/logs && \
    chown -R sankofa:sankofa /app
USER sankofa

# ── Runtime configuration ────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LOG_LEVEL=INFO

# ── Health check ─────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── Ports ────────────────────────────────────────────────────────────────────
EXPOSE 8000

# ── Entrypoint ───────────────────────────────────────────────────────────────
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--log-level", "info"]
