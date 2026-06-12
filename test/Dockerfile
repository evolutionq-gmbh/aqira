FROM ghcr.io/astral-sh/uv:trixie-slim

ARG DEBIAN_FRONTEND
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    iproute2 iptables netcat-openbsd pv wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
