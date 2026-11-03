# PR Security Reviewer — FastAPI webhook + Semgrep
FROM python:3.12-slim

# git is needed by semgrep for some operations; curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY app.py .
COPY analyzers/ ./analyzers/
COPY rules/ ./rules/

# Run as a non-root user
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/secrets && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
