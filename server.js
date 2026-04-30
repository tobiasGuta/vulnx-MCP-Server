/**
 * vulnx MCP Server
 * ─────────────────
 * Wraps the ProjectDiscovery `vulnx` CLI as a set of MCP tools so Claude
 *   - vulnx_filters  : list all searchable fields / operators
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "child_process";

// ─── helpers ──────────────────────────────────────────────────────────────────

/**
 * Run vulnx with the supplied arguments.
 * Always passes --json so we get machine-readable output.
 * Returns { stdout, stderr, exitCode }.
 */
function runVulnx(args = []) {
  const apiKey = process.env.PDCP_API_KEY || "";
  const env = { ...process.env };
  if (apiKey) env.PDCP_API_KEY = apiKey;

  // Build command string (all args are already validated / escaped by callers)
  const cmd = ["vulnx", ...args, "--json"].join(" ");

  try {
    const stdout = execSync(cmd, {
      env,
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024, // 10 MB
    }).toString();
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err) {
    return {
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? err.message,
      exitCode: err.status ?? 1,
    };
  }
}

/**
 * Format the raw vulnx output into a clean text block for Claude.
 * If the output is valid JSON we pretty-print it; otherwise return as-is.
 */
function formatOutput({ stdout, stderr, exitCode }) {
  if (exitCode !== 0) {
    return `❌ vulnx exited with code ${exitCode}:\n${stderr || stdout}`;
  }
  if (!stdout.trim()) return "No results returned.";

  try {
    const parsed = JSON.parse(stdout);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return stdout;
  }
}

/**
 * Summarise a potentially large filters JSON into a compact list of field
 * summaries so the MCP doesn't return huge payloads that the host will
 * need to write to temp files. Returns a string or null on failure.
 */
function summarizeFiltersJson(stdout) {
  try {
    const parsed = JSON.parse(stdout);
    const summary = [];

    // If the CLI returns an object with a `fields` mapping, prefer that.
    if (parsed && typeof parsed === "object") {
      if (parsed.fields && typeof parsed.fields === "object") {
        for (const [name, info] of Object.entries(parsed.fields)) {
          const type = (info && info.type) || (info && info.example ? typeof info.example : typeof info);
          const example = info && (info.example ?? info.sample ?? info.example_value ?? null);
          summary.push({ name, type, example });
        }
        return JSON.stringify({ summary, truncated: false }, null, 2);
      }

      // If it's an array of field descriptors, map first N entries.
      if (Array.isArray(parsed)) {
        for (const item of parsed.slice(0, 200)) {
          if (item && item.name) {
            summary.push({ name: item.name, type: item.type || typeof item.example, example: item.example ?? null });
          }
        }
        return JSON.stringify({ summary, truncated: parsed.length > 200 }, null, 2);
      }

      // Generic fallback: list top-level keys with sample types/values.
      for (const [k, v] of Object.entries(parsed)) {
        if (k === "count") continue;
        const type = Array.isArray(v) ? "array" : typeof v;
        let example;
        if (Array.isArray(v)) example = v.length ? v[0] : null;
        else if (v && typeof v === "object") example = Object.fromEntries(Object.entries(v).slice(0, 2));
        else example = v;
        summary.push({ name: k, type, example });
      }
      return JSON.stringify({ summary, truncated: false }, null, 2);
    }
    return null;
  } catch (err) {
    return null;
  }
}

// ─── tool definitions ─────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "vulnx_search",
    description:
      "Search the ProjectDiscovery vulnerability database. Supports free-text queries, boolean operators (&&, ||, NOT), and field-specific filters such as severity:critical, cvss_score:>8.0, is_kev:true, cve_created_at:>=2024, affected_products.vendor:microsoft, etc. Returns a JSON list of matching vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            'Search query. Examples: "apache", "severity:critical && is_remote:true", "log4j || log4shell", "cvss_score:>9.0 && cve_created_at:>=2024"',
        },
        limit: {
          type: "integer",
          description: "Maximum number of results to return (default: 10, max: 100).",
          default: 10,
          minimum: 1,
          maximum: 100,
        },
        detailed: {
          type: "boolean",
          description: "Request detailed information for each vulnerability (slower but richer).",
          default: false,
        },
        product: {
          type: "string",
          description: "Comma-separated list of product names to filter by (e.g. 'apache,nginx').",
        },
        vendor: {
          type: "string",
          description: "Comma-separated list of vendor names to filter by (e.g. 'microsoft,oracle').",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "vulnx_cve",
    description:
      "Fetch full details for a specific CVE identifier (e.g. CVE-2021-44228 / Log4Shell). Returns CVSS scores, EPSS, affected products, PoC availability, KEV status, Nuclei template availability, and more.",
    inputSchema: {
      type: "object",
      properties: {
        cve_id: {
          type: "string",
          description: "CVE identifier, e.g. CVE-2021-44228",
          pattern: "^CVE-\\d{4}-\\d+$",
        },
      },
      required: ["cve_id"],
    },
  },
  {
    name: "vulnx_filters",
    description:
      "List all available search fields, their data types, descriptions, and example values. Use this to discover what you can filter on before building complex queries.",
    inputSchema: {
      type: "object",
      properties: {
        raw: {
          type: "boolean",
          description: "If true, return the full raw filters JSON (may be large).",
          default: false,
        },
      },
    },
  },
];

// ─── server setup ─────────────────────────────────────────────────────────────

const server = new Server(
  { name: "vulnx-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      // ── vulnx_search ──────────────────────────────────────────────────────
      case "vulnx_search": {
        const { query, limit = 10, detailed = false, product, vendor } = args;

        const cliArgs = ["search", query, "--limit", String(limit)];
        if (detailed) cliArgs.push("--detailed");
        if (product) cliArgs.push("--product", product);
        if (vendor) cliArgs.push("--vendor", vendor);

        const result = runVulnx(cliArgs);
        return {
          content: [{ type: "text", text: formatOutput(result) }],
        };
      }

      // ── vulnx_cve ─────────────────────────────────────────────────────────
      case "vulnx_cve": {
        const { cve_id } = args;

        // Basic CVE-ID sanitisation — only alphanumerics and hyphens allowed
        if (!/^CVE-\d{4}-\d+$/i.test(cve_id)) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Invalid CVE ID format: "${cve_id}". Expected format: CVE-YYYY-NNNNN`,
              },
            ],
            isError: true,
          };
        }

        const result = runVulnx(["id", cve_id.toUpperCase()]);
        return {
          content: [{ type: "text", text: formatOutput(result) }],
        };
      }

      // ── vulnx_filters ─────────────────────────────────────────────────────
      case "vulnx_filters": {
        const { raw = false } = args || {};
        const result = runVulnx(["filters"]);

        // If the CLI errored, return the full error blob so callers can debug.
        if (result.exitCode !== 0) {
          return { content: [{ type: "text", text: formatOutput(result) }] };
        }

        // If the caller explicitly wants raw output, return as-is (may be large).
        if (raw) {
          return { content: [{ type: "text", text: formatOutput(result) }] };
        }

        // Otherwise try to summarise the JSON into a compact field list.
        const summary = summarizeFiltersJson(result.stdout);
        if (summary) {
          return {
            content: [
              {
                type: "text",
                text: `Filter fields summary (truncated):\n${summary}\n\nCall with { raw: true } to retrieve full JSON if needed.`,
              },
            ],
          };
        }

        // Fallback to the full formatted output if summarisation failed.
        return { content: [{ type: "text", text: formatOutput(result) }] };
      }

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (err) {
    return {
      content: [{ type: "text", text: `Internal error: ${err.message}` }],
      isError: true,
    };
  }
});

// ─── start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
// MCP servers must not write anything to stdout except protocol messages
process.stderr.write("vulnx MCP server started (stdio transport)\n");
