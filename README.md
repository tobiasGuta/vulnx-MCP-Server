# vulnx MCP Server

A self-contained [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for [ProjectDiscovery vulnx](https://github.com/projectdiscovery/vulnx). It exposes focused tools for vulnerability search, CVE lookup, and filter discovery without requiring Go or Node.js on the host.

> [!IMPORTANT]
> Results are vulnerability intelligence, not proof that a particular system is vulnerable. Confirm versions, configurations, exploitability, and remediation guidance before making security decisions.

## Prerequisites

- Docker Desktop or Docker Engine
- An MCP-compatible client
- Optionally, a ProjectDiscovery Cloud Platform API key in `PDCP_API_KEY`; unauthenticated requests may be rate-limited

## Quick start

Clone the repository, enter its actual directory, and build the image:

```bash
git clone https://github.com/tobiasGuta/vulnx-MCP-Server.git
cd vulnx-MCP-Server
docker build -t vulnx-mcp .
```

The build compiles the exact vulnx revision recorded in the Dockerfile, then copies only the binary into the Node.js runtime image. Override the pin deliberately when testing an upstream update:

```bash
docker build \
  --build-arg VULNX_REF=2bea077946026d06814ad5c0f82f6e4291dda93f \
  -t vulnx-mcp .
```

## Test the MCP handshake

Install the locked Node dependencies and run the Docker smoke client:

```bash
npm ci
npm run smoke:docker
```

The smoke client performs the required `initialize` exchange and initialized notification before calling `tools/list`. Set `VULNX_MCP_IMAGE` if the image has a different name. The regular `npm test` suite also performs an in-memory initialize, list, and call flow.

## Connect an MCP client

Build the `vulnx-mcp` image before registering it with a client. The examples below use the same hardened Docker command and pass `PDCP_API_KEY` through from the environment that launches the client. If the variable is unset, vulnx runs without a key and may be rate-limited.

### Codex CLI

[Codex supports local stdio MCP servers](https://learn.chatgpt.com/docs/extend/mcp). Add this server with:

```bash
codex mcp add vulnx -- docker run --rm -i --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m -e PDCP_API_KEY vulnx-mcp
```

Verify or remove the registration:

```bash
codex mcp list
codex mcp get vulnx
codex mcp remove vulnx
```

Codex stores the registration in its local `config.toml`. Codex CLI, the Codex IDE extension, and the ChatGPT desktop app on the same Codex host share this MCP configuration, so it normally only needs to be added once. Restart an already-running client after adding the server.

### Claude Code CLI

[Claude Code also supports local stdio MCP servers](https://code.claude.com/docs/en/mcp). The default registration is local to the current project:

```bash
claude mcp add vulnx -- docker run --rm -i --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m -e PDCP_API_KEY vulnx-mcp
```

Verify or remove it with:

```bash
claude mcp list
claude mcp get vulnx
claude mcp remove vulnx
```

Use `--scope user` when adding it if you want the registration available across all projects. Use `--scope project` only when you intentionally want Claude Code to create a shareable `.mcp.json`; never put API-key values in that file.

### Claude Desktop and JSON-config clients

For Claude Desktop, edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Other clients that accept the common `mcpServers` JSON shape can use the same entry:

```json
{
  "mcpServers": {
    "vulnx": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-e", "PDCP_API_KEY",
        "vulnx-mcp"
      ]
    }
  }
}
```

Set `PDCP_API_KEY` in the environment that launches the MCP client. If no API key is used, remove `"-e", "PDCP_API_KEY",` from the arguments. Restart the client after changing its configuration.

The container runs as the unprivileged `node` user. The suggested runtime flags also make its filesystem read-only, remove Linux capabilities, prevent privilege escalation, and provide a small temporary filesystem.

## Tools

| Tool | Description |
| --- | --- |
| `vulnx_search` | Free-text and structured CVE search with boolean operators, field filters, a 1–100 result limit, and optional detailed mode |
| `vulnx_cve` | Full details for one validated CVE identifier |
| `vulnx_filters` | A compact summary, or optional raw output, of searchable fields |

Example prompts:

```text
Search for critical remote-exploitable CVEs from 2024 in Apache.
Look up CVE-2021-44228 in detail.
Find CVEs with EPSS above 0.9 that have a Nuclei template.
What fields can I filter on when searching vulnx?
```

Successful JSON responses are returned both as readable text and as MCP `structuredContent`. A shortened CVE response may look like:

```json
{
  "id": "CVE-2021-44228",
  "severity": "critical",
  "cvss_score": 10
}
```

Exact fields depend on the pinned upstream vulnx API response.

## Security design

- The server invokes `vulnx` with `execFile` and a literal argument array; it never sends model-controlled values through a shell.
- Runtime schemas reject missing, mistyped, oversized, out-of-range, and unexpected arguments.
- Each process has a 30-second timeout and a 10 MB output limit, and MCP cancellation is forwarded to the child process.
- Nonzero CLI exits set MCP `isError: true`.
- The upstream vulnx source revision and npm dependency graph are locked for reproducible builds.
- The runtime image uses a non-root user and needs no exposed port.

Do not give the container unnecessary bind mounts. If a mount is required, prefer the narrowest possible read-only mount and treat all model-supplied tool input as untrusted.

To report a vulnerability, use the repository's private security-reporting channel rather than a public issue when possible. Do not include live credentials or sensitive target data.

## Development

```bash
npm ci
npm test
npm start
```

Tests cover literal argument handling, runtime validation, CVE validation, limit boundaries, timeouts, malformed and empty output, nonzero exits, structured output, filter truncation, cancellation forwarding, and the MCP initialize/list/call lifecycle.

## Updating dependencies

Updates are controlled rather than fetched implicitly:

1. Select a reviewed vulnx tag or commit.
2. Build with `--build-arg VULNX_REF=<commit>` and run `npm test` plus `npm run smoke:docker`.
3. Replace the default `VULNX_REF` in the Dockerfile only after verification.
4. Update exact npm versions intentionally and commit the resulting `package-lock.json`.

Automated dependency tooling such as Dependabot or Renovate can propose these changes for review.

## Project structure

```text
vulnx-MCP-Server/
├── .github/workflows/ci.yml
├── .gitignore
├── scripts/docker-smoke.js
├── test/server.test.js
├── Dockerfile
├── package.json
├── package-lock.json
├── server.js
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance. This project is available under the [MIT License](LICENSE).
