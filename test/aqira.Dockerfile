FROM ghcr.io/astral-sh/uv:trixie-slim

ARG DEBIAN_FRONTEND
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates cmake gcc git g++ libjson-c-dev ninja-build uuid-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

WORKDIR /app
RUN uv sync --locked

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/.venv/bin/aqira"]
