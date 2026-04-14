# Leetha — network host identification engine
# Multi-stage build: build frontend, compile wheel, install into slim runtime

# ── Stage 1: Build frontend ─────────────────────────────────────
FROM oven/bun:1 AS frontend

WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock* ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
COPY src/leetha/ui/web/ /app/src/leetha/ui/web/
RUN bun run build

# ── Stage 2: Build wheel ────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim AS compile

WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
COPY docs/wiki docs/wiki
COPY --from=frontend /app/src/leetha/ui/web/dist/ src/leetha/ui/web/dist/

RUN uv build --wheel --out-dir /src/wheels

# ── Stage 3: Runtime ────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="leetha" \
      description="Network host identification and threat surface analysis"

# libpcap + setcap for baking capture privileges into the image
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 iproute2 curl libcap2-bin \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=compile /src/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Grant packet capture capabilities to the Python interpreter so
# capture works even without docker run --cap-add (e.g., Dockhand).
RUN setcap 'cap_net_raw,cap_net_admin,cap_net_bind_service+eip' /usr/local/bin/python3.11

# Non-root user for safety
RUN useradd --system --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /home/appuser/.leetha/cache \
    && chown -R appuser:appuser /home/appuser/.leetha
USER appuser
ENV HOME=/home/appuser

# Persistent storage — DB, tokens, cache, settings all under ~/.leetha
VOLUME /home/appuser/.leetha
ENV LEETHA_DATA_DIR=/home/appuser/.leetha

EXPOSE 443

COPY --chown=appuser:appuser docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--web"]
