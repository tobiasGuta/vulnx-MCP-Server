# vulnx MCP Server (Docker)

A fully self-contained [MCP](https://modelcontextprotocol.io/) server that wraps
[ProjectDiscovery vulnx](https://github.com/projectdiscovery/vulnx) — all inside Docker, nothing installed on your host.

## What is vulnx?

vulnx is a modern CLI for exploring vulnerability data: search CVEs, look up
specific identifiers, filter by severity, vendor, product, CVSS score, KEV
status, PoC availability, and more.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (desktop or engine)
- [Claude Desktop](https://claude.ai/download) (or any MCP-compatible client)
- *(Optional)* A free ProjectDiscovery API key from https://cloud.projectdiscovery.io
  — works without one but subject to rate limits

---

## Quick Start

### 1. Build the image

```bash
cd vulnx-mcp
docker build -t vulnx-mcp .
```

The multi-stage build:
- **Stage 1 (Go)** — clones the vulnx repo and compiles the binary
- **Stage 2 (Node.js)** — copies the binary and runs the MCP stdio server

No Go, Node.js, or any other tool needed on your host.

### 2. Test it manually (optional)

```bash
# Should print the MCP handshake JSON on stdout
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | docker run --rm -i vulnx-mcp
```

---

## Connect to Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```jsonc
{
  "mcpServers": {
    "vulnx": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "PDCP_API_KEY=YOUR_KEY_HERE",
        "vulnx-mcp"
      ]
    }
  }
}
```

> **Without an API key** — just remove the two `-e` lines. Works out of the box
> but may be rate-limited.

Restart Claude Desktop. The three vulnx tools will appear in the tool picker.

---

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `vulnx_search` | Full-text & structured CVE search with boolean operators, field filters, limit, detailed mode |
| `vulnx_cve` | Fetch complete details for a specific CVE ID (e.g. `CVE-2021-44228`) |
| `vulnx_filters` | List every searchable field, its type, operators, and example values |

### Example prompts for Claude

```
Search for critical remote-exploitable CVEs from 2024 in Apache.

Look up CVE-2021-44228 in detail.

Find CVEs with EPSS score above 0.9 that have a Nuclei template.

What fields can I filter on when searching vulnx?
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PDCP_API_KEY` | ProjectDiscovery Cloud Platform API key (optional, removes rate limits) |

---

## Project Structure

```
vulnx-mcp/
├── Dockerfile          # Multi-stage: Go build → Node.js runtime
├── package.json        # MCP SDK dependency
├── server.js           # MCP stdio server wrapping vulnx CLI
└── README.md
```

---

## Updating vulnx

Simply rebuild the image — the Dockerfile always clones the latest commit:

```bash
docker build --no-cache -t vulnx-mcp .
```
