# vulnx MCP Server 1.1.0

A self-contained [Model Context Protocol](https://modelcontextprotocol.io/) server for [ProjectDiscovery vulnx](https://github.com/projectdiscovery/vulnx). It exposes nine focused tools for vulnerability search, lookup, comparison, prioritization, exposure research, scan-report enrichment, and safe runtime status.

> [!IMPORTANT]
> Results are vulnerability intelligence and decision support. They are not proof that a system is vulnerable, reachable, exploitable, or correctly identified. Confirm installed versions, affected ranges, configuration, reachability, and remediation guidance independently.

## Prerequisites

- Docker Desktop or Docker Engine
- An MCP-compatible client
- Optionally, a ProjectDiscovery Cloud Platform API key in `PDCP_API_KEY`; unauthenticated requests may be rate-limited

## Build

```bash
git clone https://github.com/tobiasGuta/vulnx-MCP-Server.git
cd vulnx-MCP-Server
docker build -t vulnx-mcp .
```

The multi-stage image compiles the immutable upstream revision stored in `config/vulnx.json`, installs the locked npm dependency graph with `npm ci`, and runs as the unprivileged `node` user. Go, Node.js, and vulnx are not required on the host at runtime.

## Connect an MCP client

The examples pass `PDCP_API_KEY` from the client process environment into Docker without storing its value in repository configuration.

### Codex CLI

```bash
codex mcp add vulnx -- docker run --rm -i --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m -e PDCP_API_KEY vulnx-mcp
codex mcp get vulnx
```

Codex CLI, the Codex IDE extension, and the ChatGPT desktop app on the same Codex host share the local MCP configuration. Restart an already-running client after adding the server.

### Claude Code CLI

```bash
claude mcp add vulnx -- docker run --rm -i --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m -e PDCP_API_KEY vulnx-mcp
claude mcp get vulnx
```

Use `--scope user` to make the registration available across projects. Use `--scope project` only when intentionally creating a shareable `.mcp.json`, and never place API-key values in that file.

### JSON-config clients

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

Remove `"-e", "PDCP_API_KEY",` when no key is used. To pass an operational override, add another pair such as `"-e", "VULNX_CACHE_TTL_SECONDS=600",`.

## Tools

| Tool | Purpose | Maximum input |
| --- | --- | --- |
| `vulnx_search` | Free-text and structured vulnerability search | 100 results |
| `vulnx_cve` | Fetch one validated CVE | 1 CVE |
| `vulnx_filters` | Discover supported upstream filters | 200 summarized fields |
| `vulnx_batch_cve` | Concurrent, order-preserving CVE lookup | 50 CVEs |
| `vulnx_prioritize` | Deterministic v1 risk-priority scoring | 50 CVEs or records |
| `vulnx_product_exposure` | Vendor/product relevance lookup with version caveats | 100 results |
| `vulnx_compare` | Normalize and compare CVE intelligence | 20 CVEs |
| `vulnx_enrich_findings` | Enrich submitted findings by CVE ID only | 100 findings |
| `vulnx_status` | Safe server, runtime, cache, and build metadata | No input |

Every schema rejects unexpected fields. CVE identifiers must match `^CVE-\d{4}-\d{4,}$` and are normalized to uppercase.

### Search

```json
{
  "query": "severity:critical && is_remote:true",
  "limit": 20,
  "detailed": true,
  "full_details": false,
  "vendor": "vendor-name",
  "product": "product-name"
}
```

- `detailed` asks the upstream CLI for richer vulnerability records.
- `full_details` controls MCP output compaction. It does not change the upstream query.
- With `full_details: false`, long strings, deeply nested values, and oversized nested arrays are compacted while the top-level result list is retained.
- The serialized response-size ceiling applies in both modes.
- Identical normalized searches are cache eligible.

### Single and batch CVE lookup

```json
{ "cve_id": "CVE-2025-1234" }
```

```json
{
  "cve_ids": ["CVE-2025-1234", "CVE-2024-5678"],
  "continue_on_error": true
}
```

Batch lookup removes duplicates while preserving first-seen order. It uses four concurrent subprocesses by default, configurable from 1 through 10. When `continue_on_error` is `true`, successful and failed items are returned together. When false, execution is sequential and stops at the first failure.

Abbreviated batch output:

```json
{
  "requested": 3,
  "unique": 2,
  "successful": 1,
  "failed": 1,
  "results": [
    { "cve_id": "CVE-2025-1234", "success": true, "data": {} },
    { "cve_id": "CVE-2024-5678", "success": false, "error": "vulnx exited with code 1" }
  ],
  "cache": { "enabled": true, "hits": 0, "misses": 2, "ttl_seconds": 300 }
}
```

### Vulnerability prioritization

Provide exactly one input mode:

```json
{ "cve_ids": ["CVE-2025-1234", "CVE-2024-5678"] }
```

```json
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-2025-1234",
      "cvss_score": 9.4,
      "epss_score": 0.91,
      "is_kev": true,
      "is_remote": true,
      "has_poc": true,
      "has_nuclei_template": false,
      "known_ransomware": false
    }
  ]
}
```

The immutable `v1` scoring method is:

| Signal | Points |
| --- | ---: |
| CISA KEV | 30 |
| EPSS ≥ 0.90 / 0.70 / 0.40 / 0.10 | 25 / 18 / 10 / 5 |
| CVSS ≥ 9.0 / 7.0 / 4.0 | 20 / 14 / 7 |
| Remote exploitability | 10 |
| Public proof of concept | 8 |
| Nuclei template available | 5 |
| Known ransomware association | 15 |

Priority thresholds are critical ≥ 75, high ≥ 50, medium ≥ 25, and low below 25. Equal scores are ordered by KEV, EPSS, CVSS, then CVE ID. Missing fields add zero points and appear in `missing_signals`. Output contains `ranking_method: "v1"` so future methods can be versioned explicitly.

Prioritization is decision support, not proof of exploitability, target exposure, or remediation urgency in a particular environment.

### Product and version exposure research

```json
{
  "vendor": "vendor-name",
  "product": "product-name",
  "version": "1.2.3",
  "limit": 25,
  "detailed": true
}
```

The pinned vulnx CLI supports literal `--vendor` and `--product` filters but has no dedicated version flag. Therefore a submitted version is not sent as a definitive upstream filter. Output reports `match_confidence: "unavailable"` for version-specific matching and includes the actual vendor/product query description.

Results only indicate potentially relevant vulnerability records. They do not prove that the submitted version or any installed target is vulnerable. Confirm affected version ranges manually against authoritative advisories.

### CVE comparison

```json
{
  "cve_ids": ["CVE-2025-1234", "CVE-2024-5678"]
}
```

Comparison tolerates differing upstream JSON shapes and normalizes CVSS, EPSS, severity, KEV, remote exploitability, PoC and template availability, affected vendors/products, publication date, and modification date. Failed lookups are listed separately. `highest_priority` reuses scoring method `v1` rather than duplicating ranking logic.

### Scan-report enrichment

```json
{
  "findings": [
    {
      "host": "asset.example",
      "port": 443,
      "protocol": "https",
      "source": "scanner-name",
      "cve_id": "CVE-2025-1234",
      "title": "Submitted finding",
      "severity": "high",
      "metadata": { "owner": "team-name" }
    }
  ],
  "deduplicate_cves": true,
  "include_priority": true
}
```

The tool preserves original finding order and data, deduplicates intelligence lookups, and attaches matching CVE intelligence. Only normalized CVE IDs are sent to vulnx. Hosts, URLs, ports, titles, scanner names, and metadata are never sent to the CLI. Findings without CVEs remain in the result with an unenriched reason.

This tool enriches submitted data only. It does not connect to, probe, or scan hosts.

### Status and metadata

```json
{}
```

`vulnx_status` performs a short local `vulnx version --disable-update-check` execution and returns useful partial status if the binary is unavailable. It reports:

- server and package version;
- Node version, platform, and architecture;
- vulnx availability and parsed semantic version;
- safe numeric configuration from the same centralized configuration object used by handlers;
- whether an API key exists as a Boolean only;
- the pinned upstream revision and version metadata.

It never returns API-key values, environment dumps, filesystem paths, command lines, container IDs, host identifiers, or raw version-command diagnostics.

## Caching

The in-memory cache stores only successful, valid JSON responses from read-only vulnx operations:

- single and batch CVE lookup components;
- filters;
- product searches;
- general searches with identical normalized arguments.

Validation failures, nonzero exits, malformed JSON, cancelled executions, and internal errors are never cached. Keys use deterministic serialization of normalized operation arguments and pinned behavior metadata. Sensitive-looking fields, authorization data, environment contents, cancellation objects, and `PDCP_API_KEY` are excluded from key material.

The cache uses TTL expiration and LRU eviction. It is process-local and disappears when the container exits. Cache metadata is returned separately from upstream vulnerability data.

Set `VULNX_CACHE_TTL_SECONDS=0` to disable caching.

## Environment variables

Invalid or out-of-range numeric values safely fall back to the documented default.

| Variable | Default | Accepted range | Purpose |
| --- | ---: | ---: | --- |
| `PDCP_API_KEY` | unset | n/a | Optional upstream API credential; never returned or cached |
| `VULNX_BATCH_CONCURRENCY` | `4` | `1–10` | Maximum simultaneous batch subprocesses |
| `VULNX_CACHE_TTL_SECONDS` | `300` | `0–86400` | Cache lifetime; zero disables caching |
| `VULNX_CACHE_MAX_ENTRIES` | `500` | `1–10000` | LRU cache capacity |
| `VULNX_MAX_RESPONSE_BYTES` | `524288` | `4096–5242880` | Maximum serialized MCP tool response |
| `VULNX_PROCESS_TIMEOUT_MS` | `30000` | `1000–120000` | Child-process timeout |
| `VULNX_PROCESS_MAX_BUFFER_BYTES` | `10485760` | `1048576–52428800` | Maximum collected child output |

Operational values are parsed once through `config.js`. They are never copied into cache keys unless they change cached output behavior, and secret values are never exposed.

## Response-size policy

The child-process output limit and MCP response limit are separate defenses. A successful response that exceeds the MCP ceiling becomes bounded truncation metadata with:

```json
{
  "truncated": true,
  "originalResponseBytes": 900000,
  "maxResponseBytes": 524288,
  "previewFormat": "partial-json-text",
  "previewText": "..."
}
```

`previewText` is deliberately labeled partial JSON text and is not guaranteed to be parseable JSON.

## Security design

- Every model-controlled CLI value remains one literal `execFile` argument; no shell command is constructed.
- Strict Zod schemas reject missing, malformed, oversized, out-of-range, and unexpected input.
- Batch concurrency, process duration, child output, cache size, cache lifetime, and serialized response size are bounded.
- Cancellation is forwarded to child processes, and cancelled results are not cached.
- Nonzero CLI exits set MCP `isError: true` where the tool operation fails.
- Unexpected stacks and internal diagnostics go only to stderr; MCP clients receive a fixed message.
- The upstream source revision, npm dependencies, and Docker base images are pinned.
- Docker runs as a non-root user with no exposed port; recommended client commands also use a read-only filesystem, no capabilities, and no-new-privileges.
- No vulnerability records, target mappings, vendor mappings, or product mappings are embedded in production code.

Do not add unnecessary bind mounts. If one is required, use the narrowest read-only mount possible.

## Development and verification

```bash
npm ci
npm test
docker build -t vulnx-mcp .
npm run smoke:docker
```

The smoke client performs the MCP initialize exchange, verifies all nine tools, calls `vulnx_status`, and performs a safe filter operation through the hardened container.

## Manual test prompts and screenshots

After adding this MCP server to your client, restart the client and run the prompts below. Each prompt has a reserved screenshot area. Replace the placeholder text with Markdown such as `![Server health result](docs/screenshots/01-server-health.png)` when the screenshot is ready.

### 1. Server health

```text
Use the vulnx_status tool. Show the server version, vulnx availability, cache configuration, response-size limit, and pinned vulnx revision. Do not display secrets.
```

**Screenshot 1:** Server health result

<!-- Add screenshot here: docs/screenshots/01-server-health.png -->

<br><br><br><br>

### 2. Available filters

```text
Use vulnx_filters to list the vulnerability search filters supported by the installed vulnx CLI. Return a compact summary.
```

**Screenshot 2:** Available filters result

<!-- Add screenshot here: docs/screenshots/02-available-filters.png -->

<br><br><br><br>

### 3. General search

```text
Use vulnx_search to search for vulnerabilities related to remote code execution in web servers. Limit the result to 5 records and summarize the most important findings.
```

**Screenshot 3:** General search result

<!-- Add screenshot here: docs/screenshots/03-general-search.png -->

<br><br><br><br>

### 4. Detailed search

```text
Use vulnx_search with detailed=true and full_details=false to find authentication bypass vulnerabilities. Limit the response to 5 results. Explain which fields were compacted, if any.
```

**Screenshot 4:** Detailed search result

<!-- Add screenshot here: docs/screenshots/04-detailed-search.png -->

<br><br><br><br>

### 5. Single CVE lookup

```text
Use vulnx_cve to retrieve intelligence for CVE-2023-44487. Summarize CVSS, EPSS, KEV status, exploitability, affected products, and available proof-of-concept information.
```

**Screenshot 5:** Single CVE lookup result

<!-- Add screenshot here: docs/screenshots/05-single-cve.png -->

<br><br><br><br>

### 6. Batch CVE lookup

```text
Use vulnx_batch_cve for these identifiers:

- cve-2023-44487
- CVE-2024-3094
- CVE-2017-0144
- CVE-2023-44487

Continue when an individual lookup fails. Confirm that identifiers were normalized, duplicates were removed, and report successful and failed counts.
```

**Screenshot 6:** Batch CVE lookup result

<!-- Add screenshot here: docs/screenshots/06-batch-cve.png -->

<br><br><br><br>

### 7. Prioritization using live lookups

```text
Use vulnx_prioritize to rank these vulnerabilities:

- CVE-2023-44487
- CVE-2024-3094
- CVE-2017-0144

Show the score, priority, reasons, missing signals, ranking method, and disclaimer for each result.
```

**Screenshot 7:** Live prioritization result

<!-- Add screenshot here: docs/screenshots/07-live-prioritization.png -->

<br><br><br><br>

### 8. Prioritization using supplied data

```text
Use vulnx_prioritize with these supplied vulnerability signals:

[
  {
    "cve_id": "CVE-2025-1001",
    "cvss_score": 9.8,
    "epss_score": 0.92,
    "is_kev": true,
    "is_remote": true,
    "has_poc": true,
    "has_nuclei_template": false
  },
  {
    "cve_id": "CVE-2025-1002",
    "cvss_score": 7.5,
    "epss_score": 0.15,
    "is_kev": false,
    "is_remote": true,
    "has_poc": false
  }
]

Explain why one ranks above the other.
```

**Screenshot 8:** Supplied-data prioritization result

<!-- Add screenshot here: docs/screenshots/08-supplied-prioritization.png -->

<br><br><br><br>

### 9. Product exposure research

```text
Use vulnx_product_exposure with vendor "openssl", product "openssl", version "3.0.7", limit 10, and detailed=true. Clearly state the match confidence and why the result does not prove that an installed target is vulnerable.
```

**Screenshot 9:** Product exposure result

<!-- Add screenshot here: docs/screenshots/09-product-exposure.png -->

<br><br><br><br>

### 10. CVE comparison

```text
Use vulnx_compare to compare CVE-2023-44487, CVE-2024-3094, and CVE-2017-0144. Show the normalized comparison, highest CVSS, highest EPSS, KEV-listed entries, and highest-priority CVE.
```

**Screenshot 10:** CVE comparison result

<!-- Add screenshot here: docs/screenshots/10-cve-comparison.png -->

<br><br><br><br>

### 11. Finding enrichment

```text
Use vulnx_enrich_findings to enrich these submitted findings. Include priority scoring and preserve their original order and metadata:

[
  {
    "host": "app.internal.test",
    "port": 443,
    "protocol": "https",
    "source": "security-scanner",
    "cve_id": "CVE-2023-44487",
    "title": "Possible HTTP/2 resource exhaustion",
    "metadata": {
      "environment": "staging"
    }
  },
  {
    "host": "database.internal.test",
    "port": 5432,
    "protocol": "tcp",
    "source": "inventory",
    "title": "Finding without a CVE",
    "metadata": {
      "owner": "platform-team"
    }
  }
]

Confirm that no host, port, title, or metadata was sent to vulnx.
```

**Screenshot 11:** Finding enrichment result

<!-- Add screenshot here: docs/screenshots/11-finding-enrichment.png -->

<br><br><br><br>

### 12. Cache test

Run this exact prompt twice:

```text
Use vulnx_cve to retrieve CVE-2023-44487. Include the cache metadata in your answer.
```

The first response should normally report `cache.hit: false`; the second should report `cache.hit: true`, provided caching is enabled and the TTL has not expired.

**Screenshot 12:** First and second cache results

<!-- Add screenshot here: docs/screenshots/12-cache-test.png -->

<br><br><br><br>

## Updating dependencies and vulnx

Dependabot checks npm packages, GitHub Actions, and Docker base-image digests weekly. The upstream vulnx revision remains a manual review:

1. Review the upstream change.
2. Update `config/vulnx.json`.
3. Run unit, MCP integration, image-build, status, and Docker smoke tests.
4. Commit the metadata and resulting behavior together.

## Project structure

```text
vulnx-MCP-Server/
├── .github/dependabot.yml
├── .github/workflows/ci.yml
├── config/vulnx.json
├── scripts/docker-smoke.js
├── test/
├── cache.js
├── config.js
├── operations.js
├── vulnerability.js
├── server.js
├── Dockerfile
├── package.json
├── package-lock.json
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

See [CONTRIBUTING.md](CONTRIBUTING.md). This project is available under the [MIT License](LICENSE).
