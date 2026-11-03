# syntax=docker/dockerfile:1
# Aplomb, niveau d'assurance 3 : l'agent (Claude Code) dans un conteneur sans accès direct
# au réseau. Le superviseur reste sur l'hôte, hors de portée de l'agent. Contexte de
# construction : la racine du dépôt (voir compose.yaml).

# Binaire aplomb pour Linux (le hook, dans le conteneur de l'agent).
FROM rust:1.91-slim-bookworm AS construction
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p aplomb && cp target/release/aplomb /aplomb

# Relais : seule passerelle entre le réseau isolé et l'hôte, une destination fixe par relais.
FROM alpine:3.20 AS relais
RUN apk add --no-cache socat
USER nobody
ENTRYPOINT ["socat"]

# L'agent.
FROM node:22-bookworm-slim AS agent
ARG CLAUDE_CODE_VERSION=latest
RUN apt-get update \
 && apt-get install -y --no-install-recommends git python3 python3-pip python3-venv ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force
# Hook et paramètres gérés appartiennent à root : l'agent ne peut ni les modifier, ni les
# remplacer, ni ajouter ses propres hooks (allowManagedHooksOnly).
COPY --from=construction /aplomb /usr/local/bin/aplomb
COPY conteneur/managed-settings.json /etc/claude-code/managed-settings.json
RUN chmod 755 /usr/local/bin/aplomb && chmod 644 /etc/claude-code/managed-settings.json \
 && useradd --create-home --uid 1001 agent
USER agent
ENV APLOMB_URL=http://aplomb-decision:7700 \
    HTTPS_PROXY=http://aplomb-gate:7702 \
    HTTP_PROXY=http://aplomb-gate:7702 \
    NO_PROXY=aplomb-decision,aplomb-llm \
    ANTHROPIC_BASE_URL=http://aplomb-llm:7703 \
    ANTHROPIC_AUTH_TOKEN=aplomb-injecte-le-vrai-jeton \
    DISABLE_TELEMETRY=1 \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENTRYPOINT ["claude"]
