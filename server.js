/**
 * MCP server exposing the ProjectDiscovery vulnx CLI over stdio.
 */

import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const PROCESS_TIMEOUT_MS = 30_000;
const PROCESS_MAX_BUFFER = 10 * 1024 * 1024;
const MAX_FILTER_FIELDS = 200;
const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
const MIN_MAX_RESPONSE_BYTES = 4 * 1024;
const MAX_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const COMPACT_MAX_STRING_BYTES = 4 * 1024;
const COMPACT_MAX_NESTED_ARRAY_ITEMS = 25;
const COMPACT_MAX_DEPTH = 8;

const searchArgumentsSchema = z
  .object({
    query: z.string().trim().min(1).max(1_000),
    limit: z.number().int().min(1).max(100).default(10),
    detailed: z.boolean().default(false),
    full_details: z.boolean().default(false),
    product: z.string().trim().min(1).max(256).optional(),
    vendor: z.string().trim().min(1).max(256).optional(),
  })
  .strict();

const cveArgumentsSchema = z
  .object({
    cve_id: z.string().trim().max(32).regex(/^CVE-\d{4}-\d{4,}$/i),
  })
  .strict();

const filtersArgumentsSchema = z
  .object({
    raw: z.boolean().default(false),
  })
  .strict();

export const TOOLS = [
  {
    name: "vulnx_search",
    description:
      "Search the ProjectDiscovery vulnerability database. Supports free-text queries, boolean operators (&&, ||, NOT), and field-specific filters such as severity:critical, cvss_score:>8.0, is_kev:true, cve_created_at:>=2024, and affected_products.vendor:microsoft.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        query: {
          type: "string",
          minLength: 1,
          maxLength: 1000,
          description:
            'Search query. Examples: "apache", "severity:critical && is_remote:true", or "cvss_score:>9.0 && cve_created_at:>=2024".',
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
          description: "Request detailed information for each vulnerability.",
          default: false,
        },
        full_details: {
          type: "boolean",
          description:
            "Disable compact field truncation. The configured response-size ceiling still applies.",
          default: false,
        },
        product: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          description: "Comma-separated product names, for example apache,nginx.",
        },
        vendor: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          description: "Comma-separated vendor names, for example microsoft,oracle.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "vulnx_cve",
    description:
      "Fetch full details for a CVE identifier, including scores, affected products, PoC availability, KEV status, and Nuclei template availability.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        cve_id: {
          type: "string",
          maxLength: 32,
          description: "CVE identifier, for example CVE-2021-44228.",
          pattern: "^CVE-\\d{4}-\\d{4,}$",
        },
      },
      required: ["cve_id"],
    },
  },
  {
    name: "vulnx_filters",
    description:
      "List available search fields, data types, descriptions, and example values.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        raw: {
          type: "boolean",
          description: "Return the full filters JSON instead of a compact summary.",
          default: false,
        },
      },
    },
  },
];

function exitCodeForError(error) {
  if (typeof error?.code === "number") return error.code;
  if (error?.code === "ABORT_ERR") return 130;
  if (error?.killed || error?.signal === "SIGTERM") return 124;
  return 1;
}

/**
 * Run vulnx without a shell. Every caller-supplied value remains one literal
 * argv entry, so shell metacharacters cannot become commands.
 */
export function runVulnx(args = [], options = {}) {
  const {
    signal,
    execFileImpl = execFile,
    timeout = PROCESS_TIMEOUT_MS,
    maxBuffer = PROCESS_MAX_BUFFER,
  } = options;

  return new Promise((resolve) => {
    const finish = (error, stdout = "", stderr = "") => {
      resolve({
        stdout: String(stdout ?? ""),
        stderr: String(stderr || error?.message || ""),
        exitCode: error ? exitCodeForError(error) : 0,
      });
    };

    try {
      execFileImpl(
        "vulnx",
        [...args, "--json"],
        {
          env: { ...process.env },
          encoding: "utf8",
          timeout,
          maxBuffer,
          signal,
        },
        finish,
      );
    } catch (error) {
      finish(error);
    }
  });
}

export function formatOutput({ stdout, stderr, exitCode }) {
  if (exitCode !== 0) {
    return `vulnx exited with code ${exitCode}:\n${stderr || stdout || "Unknown error"}`;
  }
  if (!stdout.trim()) return "No results returned.";

  try {
    return JSON.stringify(JSON.parse(stdout), null, 2);
  } catch {
    return stdout;
  }
}

function parsedOutput(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    return undefined;
  }
}

function serializedBytes(value) {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function truncateUtf8(value, maxBytes, suffix = "… [truncated]") {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return value;
  const suffixBytes = Buffer.byteLength(suffix, "utf8");
  if (suffixBytes >= maxBytes) return suffix.slice(0, maxBytes);

  let low = 0;
  let high = value.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    const candidate = value.slice(0, middle);
    if (Buffer.byteLength(candidate, "utf8") + suffixBytes <= maxBytes) low = middle;
    else high = middle - 1;
  }
  return `${value.slice(0, low)}${suffix}`;
}

export function getMaxResponseBytes(value = process.env.VULNX_MAX_RESPONSE_BYTES) {
  if (value === undefined || value === "") return DEFAULT_MAX_RESPONSE_BYTES;
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) return DEFAULT_MAX_RESPONSE_BYTES;
  if (parsed < MIN_MAX_RESPONSE_BYTES || parsed > MAX_MAX_RESPONSE_BYTES) {
    return DEFAULT_MAX_RESPONSE_BYTES;
  }
  return parsed;
}

function compactJsonValue(value, state, depth = 0) {
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") <= COMPACT_MAX_STRING_BYTES) return value;
    state.truncatedValues += 1;
    return truncateUtf8(value, COMPACT_MAX_STRING_BYTES);
  }
  if (!value || typeof value !== "object") return value;
  if (depth >= COMPACT_MAX_DEPTH) {
    state.truncatedValues += 1;
    return "[omitted: maximum nesting depth reached]";
  }
  if (Array.isArray(value)) {
    const limit = depth === 0
      ? value.length
      : Math.min(value.length, COMPACT_MAX_NESTED_ARRAY_ITEMS);
    const compacted = value
      .slice(0, limit)
      .map((item) => compactJsonValue(item, state, depth + 1));
    if (limit < value.length) {
      state.truncatedValues += 1;
      compacted.push({
        _vulnx_mcp_truncated: true,
        omittedItems: value.length - limit,
      });
    }
    return compacted;
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      compactJsonValue(item, state, depth + 1),
    ]),
  );
}

function fitOversizedJsonResponse(response, maxResponseBytes, originalResponseBytes) {
  const source = JSON.stringify(response.structuredContent ?? {});
  const message =
    `The vulnx response exceeded the ${maxResponseBytes}-byte MCP response limit and was truncated. ` +
    "A bounded partial-JSON text preview is available in structuredContent.previewText.";

  const build = (previewText) => ({
    content: [{ type: "text", text: message }],
    structuredContent: {
      truncated: true,
      originalResponseBytes,
      maxResponseBytes,
      previewFormat: "partial-json-text",
      previewText,
    },
    isError: response.isError === true,
  });

  let low = 0;
  let high = source.length;
  let best = build("");
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = build(source.slice(0, middle));
    if (serializedBytes(candidate) <= maxResponseBytes) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

export function boundToolResponse(response, maxResponseBytes = getMaxResponseBytes()) {
  const originalResponseBytes = serializedBytes(response);
  if (originalResponseBytes <= maxResponseBytes) return response;
  if (response.structuredContent) {
    return fitOversizedJsonResponse(response, maxResponseBytes, originalResponseBytes);
  }

  const originalText = response.content?.[0]?.text ?? "Response truncated.";
  const suffix = `\n\n[truncated to the ${maxResponseBytes}-byte MCP response limit]`;
  let low = 0;
  let high = originalText.length;
  let best = {
    ...response,
    content: [{ type: "text", text: suffix.trim() }],
  };
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = {
      ...response,
      content: [{ type: "text", text: `${originalText.slice(0, middle)}${suffix}` }],
    };
    if (serializedBytes(candidate) <= maxResponseBytes) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

function describeJson(data) {
  if (Array.isArray(data)) return `${data.length} JSON item${data.length === 1 ? "" : "s"}`;
  if (data && typeof data === "object") {
    const count = Object.keys(data).length;
    return `${count} JSON field${count === 1 ? "" : "s"}`;
  }
  return "one JSON value";
}

export function toolResult(result, options = {}) {
  const {
    compact = false,
    maxResponseBytes = getMaxResponseBytes(),
  } = options;
  const response = {
    content: [{ type: "text", text: formatOutput(result) }],
    isError: result.exitCode !== 0,
  };
  const data = result.exitCode === 0 ? parsedOutput(result.stdout) : undefined;
  if (data !== undefined) {
    if (compact) {
      const state = { truncatedValues: 0 };
      const compacted = compactJsonValue(data, state);
      response.content[0].text =
        `Returned ${describeJson(compacted)} in compact mode. ` +
        "Use full_details=true to request unabridged fields; the response-size limit always applies.";
      response.structuredContent = {
        data: compacted,
        compact: true,
        truncatedValues: state.truncatedValues,
      };
    } else {
      response.structuredContent = { data };
    }
  }
  return boundToolResponse(response, maxResponseBytes);
}

/** Return a compact, structured view of filters, or null for invalid JSON. */
export function summarizeFiltersJson(stdout) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object") return null;

  const summary = [];
  if (Array.isArray(parsed)) {
    for (const item of parsed.slice(0, MAX_FILTER_FIELDS)) {
      if (item && typeof item === "object" && item.name) {
        summary.push({
          name: item.name,
          type: item.type || typeof item.example,
          example: item.example ?? null,
        });
      }
    }
    return { summary, truncated: parsed.length > MAX_FILTER_FIELDS };
  }

  if (parsed.fields && typeof parsed.fields === "object") {
    const entries = Object.entries(parsed.fields);
    for (const [name, info] of entries.slice(0, MAX_FILTER_FIELDS)) {
      summary.push({
        name,
        type: info?.type || (info?.example !== undefined ? typeof info.example : typeof info),
        example: info?.example ?? info?.sample ?? info?.example_value ?? null,
      });
    }
    return { summary, truncated: entries.length > MAX_FILTER_FIELDS };
  }

  const entries = Object.entries(parsed).filter(([key]) => key !== "count");
  for (const [name, value] of entries.slice(0, MAX_FILTER_FIELDS)) {
    const type = Array.isArray(value) ? "array" : typeof value;
    let example = value;
    if (Array.isArray(value)) example = value[0] ?? null;
    else if (value && typeof value === "object") {
      example = Object.fromEntries(Object.entries(value).slice(0, 2));
    }
    summary.push({ name, type, example });
  }
  return { summary, truncated: entries.length > MAX_FILTER_FIELDS };
}

function invalidArgumentsResult(toolName, error) {
  const details = error.issues
    .map((issue) => `${issue.path.join(".") || "arguments"}: ${issue.message}`)
    .join("; ");
  return {
    content: [{ type: "text", text: `Invalid arguments for ${toolName}: ${details}` }],
    isError: true,
  };
}

function parseArguments(schema, toolName, args) {
  const parsed = schema.safeParse(args ?? {});
  if (!parsed.success) return { error: invalidArgumentsResult(toolName, parsed.error) };
  return { data: parsed.data };
}

export async function handleToolCall(name, args, options = {}) {
  const {
    signal,
    runner = runVulnx,
    maxResponseBytes = getMaxResponseBytes(),
  } = options;

  switch (name) {
    case "vulnx_search": {
      const parsed = parseArguments(searchArgumentsSchema, name, args);
      if (parsed.error) return parsed.error;
      const { query, limit, detailed, full_details, product, vendor } = parsed.data;
      const cliArgs = ["search", query, "--limit", String(limit)];
      if (detailed) cliArgs.push("--detailed");
      if (product) cliArgs.push("--product", product);
      if (vendor) cliArgs.push("--vendor", vendor);
      return toolResult(await runner(cliArgs, { signal }), {
        compact: !full_details,
        maxResponseBytes,
      });
    }

    case "vulnx_cve": {
      const parsed = parseArguments(cveArgumentsSchema, name, args);
      if (parsed.error) return parsed.error;
      return toolResult(
        await runner(["id", parsed.data.cve_id.toUpperCase()], { signal }),
        { maxResponseBytes },
      );
    }

    case "vulnx_filters": {
      const parsed = parseArguments(filtersArgumentsSchema, name, args);
      if (parsed.error) return parsed.error;
      const result = await runner(["filters"], { signal });
      if (result.exitCode !== 0 || parsed.data.raw) {
        return toolResult(result, { maxResponseBytes });
      }

      const data = summarizeFiltersJson(result.stdout);
      if (!data) return toolResult(result, { maxResponseBytes });
      return boundToolResponse({
        content: [
          {
            type: "text",
            text: `Filter fields summary${data.truncated ? " (truncated)" : ""}:\n${JSON.stringify(data, null, 2)}\n\nCall with {"raw":true} to retrieve the full JSON.`,
          },
        ],
        structuredContent: data,
        isError: false,
      }, maxResponseBytes);
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}

export function internalErrorResult(error, logger = (message) => process.stderr.write(message)) {
  const diagnostics = error instanceof Error
    ? error.stack || error.message
    : String(error);
  logger(`Internal error: ${diagnostics}\n`);
  return {
    content: [
      {
        type: "text",
        text: "The vulnx MCP server encountered an internal error.",
      },
    ],
    isError: true,
  };
}

export function createServer(options = {}) {
  const {
    runner = runVulnx,
    logger,
    maxResponseBytes = getMaxResponseBytes(),
  } = options;
  const server = new Server(
    { name: "vulnx-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    try {
      return await handleToolCall(request.params.name, request.params.arguments, {
        runner,
        signal: extra.signal,
        maxResponseBytes,
      });
    } catch (error) {
      return internalErrorResult(error, logger);
    }
  });
  return server;
}

export async function startServer() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  // Stdout is reserved exclusively for MCP protocol messages.
  process.stderr.write("vulnx MCP server started (stdio transport)\n");
}

const isMainModule =
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMainModule) await startServer();
