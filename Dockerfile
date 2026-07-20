FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl python3.12 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system cybershield \
    && useradd --system --gid cybershield --create-home --home-dir /home/cybershield cybershield

WORKDIR /app

COPY requirements.txt ./
RUN python3.12 -m pip install --break-system-packages --requirement requirements.txt

COPY --chown=cybershield:cybershield backend ./backend
COPY --chown=cybershield:cybershield frontend ./frontend
COPY --chown=cybershield:cybershield models ./models
COPY --chown=cybershield:cybershield security ./security
COPY --chown=cybershield:cybershield services ./services
COPY --chown=cybershield:cybershield static ./static
COPY --chown=cybershield:cybershield templates ./templates
COPY --chown=cybershield:cybershield utils ./utils

USER cybershield
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:8000/health || exit 1

CMD ["python3.12", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
