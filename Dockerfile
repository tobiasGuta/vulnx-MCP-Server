# Stage 1: build the vulnx binary from the revision in shared build metadata.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

RUN apk add --no-cache git ca-certificates jq
COPY config/vulnx.json /tmp/vulnx.json
RUN VULNX_REF="$(jq -er '.revision' /tmp/vulnx.json)" \
    && git clone https://github.com/projectdiscovery/vulnx.git /src/vulnx \
    && cd /src/vulnx \
    && git checkout --detach "$VULNX_REF"

WORKDIR /src/vulnx
RUN go build -trimpath -ldflags="-s -w" -o /usr/local/bin/vulnx ./cmd/vulnx

# Stage 2: run only Node.js, certificates, the server, and the vulnx binary.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293

RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/local/bin/vulnx /usr/local/bin/vulnx

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
    && npm cache clean --force

COPY --chown=node:node server.js config.js cache.js operations.js vulnerability.js ./
COPY --chown=node:node config ./config

# MCP servers communicate over stdio; no network port is exposed.
USER node
CMD ["node", "server.js"]
