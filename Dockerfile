FROM node:22-bookworm-slim@sha256:53ada149d435c38b14476cb57e4a7da73c15595aba79bd6971b547ceb6d018bf AS web-build

WORKDIR /app/apps/web
COPY apps/web/package*.json ./
RUN npm ci
COPY apps/web ./
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

ARG TRACEHAWK_VERSION=0.9.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="TraceHawk" \
      org.opencontainers.image.description="Local-first security log investigation assistant" \
      org.opencontainers.image.source="https://github.com/0zB0/Security-Log-Analyzer" \
      org.opencontainers.image.version="${TRACEHAWK_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TRACEHAWK_DB_PATH=/data/tracehawk.db
ENV TRACEHAWK_WEB_DIST=/app/apps/web/dist
ENV TRACEHAWK_LLM_PROVIDER=mock
ENV TRACEHAWK_OLLAMA_URL=http://localhost:11434
ENV TRACEHAWK_OLLAMA_MODEL=gpt-oss:20b

WORKDIR /app
COPY apps/api/pyproject.toml ./apps/api/pyproject.toml
COPY apps/api/requirements.lock ./apps/api/requirements.lock
COPY apps/api/alembic.ini ./apps/api/alembic.ini
COPY apps/api/migrations ./apps/api/migrations
COPY apps/api/tracehawk_api ./apps/api/tracehawk_api
COPY packages/correlation ./packages/correlation
COPY packages/rules ./packages/rules
COPY packages/sample-data ./packages/sample-data
COPY tools/sqlite_backup.py ./tools/sqlite_backup.py
COPY --from=web-build /app/apps/web/dist ./apps/web/dist

RUN pip wheel --no-cache-dir --constraint ./apps/api/requirements.lock \
        --wheel-dir /tmp/wheels ./apps/api \
    && pip install --no-cache-dir --constraint ./apps/api/requirements.lock /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels \
    && useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data

USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health/ready', timeout=3)"]
CMD ["uvicorn", "tracehawk_api.main:app", "--app-dir", "apps/api", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
