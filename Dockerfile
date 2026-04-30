# Stage 1: Build vulnx binary from source
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

RUN git clone https://github.com/projectdiscovery/vulnx.git /src/vulnx
WORKDIR /src/vulnx

RUN go build -o /usr/local/bin/vulnx ./cmd/vulnx

# ─────────────────────────────────────────────
# Stage 2: MCP server runtime (Node.js)
# ─────────────────────────────────────────────
FROM node:20-alpine

# System certs needed for HTTPS calls from vulnx
RUN apk add --no-cache ca-certificates

# Copy the compiled vulnx binary
COPY --from=builder /usr/local/bin/vulnx /usr/local/bin/vulnx

WORKDIR /app

# Install Node dependencies
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copy MCP server source
COPY server.js ./

# MCP servers communicate over stdio — no exposed port needed
CMD ["node", "server.js"]
