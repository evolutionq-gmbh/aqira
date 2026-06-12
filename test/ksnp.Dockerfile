FROM ghcr.io/astral-sh/uv:trixie-slim

ARG DEBIAN_FRONTEND
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates cmake gcc git g++ libjson-c-dev ninja-build uuid-dev \
    && rm -rf /var/lib/apt/lists/*

RUN uv venv && uv pip install "ksnp@git+https://github.com/evolutionq-gmbh/ksnp.git@v0.4#subdirectory=python"

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["uv", "run", "pyksnp-server"]
