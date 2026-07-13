# Stage 1: build the vulnx binary from an immutable upstream revision.
FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder

ARG VULNX_REF=2bea077946026d06814ad5c0f82f6e4291dda93f

RUN apk add --no-cache git ca-certificates
RUN git clone https://github.com/projectdiscovery/vulnx.git /src/vulnx \
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

COPY --chown=node:node server.js ./

# MCP servers communicate over stdio; no network port is exposed.
USER node
CMD ["node", "server.js"]
