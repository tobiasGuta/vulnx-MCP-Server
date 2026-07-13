/** MCP server exposing the ProjectDiscovery vulnx CLI over stdio. */

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

import { ResultCache } from "./cache.js";
import { CONFIG, loadConfiguration } from "./config.js";
import { executeCachedVulnx, lookupCveBatch } from "./operations.js";
import {
  CVE_PATTERN,
  comparePriority,
  normalizeCveId,
  normalizeCveIds,
  normalizeVulnerability,
  prioritizeVulnerabilities,
  scoreVulnerability,
} from "./vulnerability.js";

const cveStringSchema = z
  .string()
  .trim()
  .max(CONFIG.validation.cveMaximumLength)
  .regex(CVE_PATTERN);

const searchArgumentsSchema = z
  .object({
    query: z.string().trim().min(1).max(CONFIG.validation.queryMaximumLength),
    limit: z.number().int().min(1).max(CONFIG.search.maximumResults).default(CONFIG.search.defaultResults),
    detailed: z.boolean().default(false),
    full_details: z.boolean().default(false),
    product: z.string().trim().min(1).max(CONFIG.validation.productMaximumLength).optional(),
    vendor: z.string().trim().min(1).max(CONFIG.validation.vendorMaximumLength).optional(),
  })
  .strict();

const cveArgumentsSchema = z.object({ cve_id: cveStringSchema }).strict();
const filtersArgumentsSchema = z.object({ raw: z.boolean().default(false) }).strict();
const batchArgumentsSchema = z
  .object({
    cve_ids: z.array(cveStringSchema).min(1).max(CONFIG.batch.maximum),
    continue_on_error: z.boolean().default(true),
  })
  .strict();

const suppliedVulnerabilitySchema = z
  .object({
    cve_id: cveStringSchema,
    cvss_score: z.number().min(0).max(10).optional(),
    epss_score: z.number().min(0).max(1).optional(),
    severity: z.string().trim().min(1).max(CONFIG.validation.severityMaximumLength).optional(),
    is_kev: z.boolean().optional(),
    is_remote: z.boolean().optional(),
    has_poc: z.boolean().optional(),
    has_nuclei_template: z.boolean().optional(),
    known_ransomware: z.boolean().optional(),
  })
  .strict();

const prioritizeArgumentsSchema = z
  .object({
    cve_ids: z.array(cveStringSchema).min(1).max(CONFIG.prioritization.maximum).optional(),
    vulnerabilities: z
      .array(suppliedVulnerabilitySchema)
      .min(1)
      .max(CONFIG.prioritization.maximum)
      .optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (Boolean(value.cve_ids) === Boolean(value.vulnerabilities)) {
      context.addIssue({
        code: "custom",
        message: "Provide exactly one of cve_ids or vulnerabilities",
      });
    }
  });

const productExposureArgumentsSchema = z
  .object({
    vendor: z.string().trim().min(1).max(CONFIG.validation.vendorMaximumLength),
    product: z.string().trim().min(1).max(CONFIG.validation.productMaximumLength),
    version: z.string().trim().min(1).max(CONFIG.validation.versionMaximumLength).optional(),
    limit: z
      .number()
      .int()
      .min(1)
      .max(CONFIG.search.maximumResults)
      .default(CONFIG.search.productDefaultResults),
    detailed: z.boolean().default(false),
  })
  .strict();

const compareArgumentsSchema = z
  .object({
    cve_ids: z.array(cveStringSchema).min(2).max(CONFIG.comparison.maximum),
  })
  .strict()
  .superRefine((value, context) => {
    if (normalizeCveIds(value.cve_ids).length < 2) {
      context.addIssue({
        code: "custom",
        path: ["cve_ids"],
        message: "At least two unique CVE identifiers are required",
      });
    }
  });

function isBoundedJsonValue(value, depth = 0) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (depth >= CONFIG.compact.maximumDepth || typeof value !== "object") return false;
  if (Array.isArray(value)) {
    return value.every((item) => isBoundedJsonValue(item, depth + 1));
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Object.values(value).every((item) => isBoundedJsonValue(item, depth + 1));
}

const metadataSchema = z.record(z.string(), z.unknown()).superRefine((value, context) => {
  if (!isBoundedJsonValue(value)) {
    context.addIssue({
      code: "custom",
      message: `metadata must contain JSON values nested no deeper than ${CONFIG.compact.maximumDepth} levels`,
    });
    return;
  }
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > CONFIG.validation.metadataMaximumBytes) {
    context.addIssue({ code: "custom", message: "metadata exceeds the maximum serialized size" });
  }
});

const findingSchema = z
  .object({
    host: z.string().trim().min(1).max(CONFIG.validation.hostMaximumLength).optional(),
    port: z
      .number()
      .int()
      .min(CONFIG.validation.portMinimum)
      .max(CONFIG.validation.portMaximum)
      .optional(),
    protocol: z.string().trim().min(1).max(CONFIG.validation.protocolMaximumLength).optional(),
    source: z.string().trim().min(1).max(CONFIG.validation.sourceMaximumLength).optional(),
    template_id: z.string().trim().min(1).max(CONFIG.validation.templateMaximumLength).optional(),
    cve_id: cveStringSchema.optional(),
    title: z.string().trim().min(1).max(CONFIG.validation.titleMaximumLength).optional(),
    severity: z.string().trim().min(1).max(CONFIG.validation.severityMaximumLength).optional(),
    metadata: metadataSchema.default({}),
  })
  .strict();

const enrichArgumentsSchema = z
  .object({
    findings: z.array(findingSchema).min(1).max(CONFIG.enrichment.maximum),
    deduplicate_cves: z.boolean().default(true),
    include_priority: z.boolean().default(true),
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.findings.some((finding) => normalizeCveId(finding.cve_id))) {
      context.addIssue({
        code: "custom",
        path: ["findings"],
        message: "At least one finding must contain a valid CVE identifier",
      });
    }
  });

const statusArgumentsSchema = z.object({}).strict();

function objectSchema(properties, required = []) {
  return { type: "object", additionalProperties: false, properties, required };
}

const cveProperty = {
  type: "string",
  maxLength: CONFIG.validation.cveMaximumLength,
  pattern: "^CVE-\\d{4}-\\d{4,}$",
};

const suppliedVulnerabilityInputSchema = objectSchema({
  cve_id: cveProperty,
  cvss_score: { type: "number", minimum: 0, maximum: 10 },
  epss_score: { type: "number", minimum: 0, maximum: 1 },
  severity: { type: "string", minLength: 1, maxLength: CONFIG.validation.severityMaximumLength },
  is_kev: { type: "boolean" },
  is_remote: { type: "boolean" },
  has_poc: { type: "boolean" },
  has_nuclei_template: { type: "boolean" },
  known_ransomware: { type: "boolean" },
}, ["cve_id"]);

const findingInputSchema = objectSchema({
  host: { type: "string", minLength: 1, maxLength: CONFIG.validation.hostMaximumLength },
  port: { type: "integer", minimum: CONFIG.validation.portMinimum, maximum: CONFIG.validation.portMaximum },
  protocol: { type: "string", minLength: 1, maxLength: CONFIG.validation.protocolMaximumLength },
  source: { type: "string", minLength: 1, maxLength: CONFIG.validation.sourceMaximumLength },
  template_id: { type: "string", minLength: 1, maxLength: CONFIG.validation.templateMaximumLength },
  cve_id: cveProperty,
  title: { type: "string", minLength: 1, maxLength: CONFIG.validation.titleMaximumLength },
  severity: { type: "string", minLength: 1, maxLength: CONFIG.validation.severityMaximumLength },
  metadata: { type: "object" },
});

export const TOOLS = [
  {
    name: "vulnx_search",
    description: "Search vulnerability intelligence with free text and supported structured filters.",
    inputSchema: objectSchema({
      query: { type: "string", minLength: 1, maxLength: CONFIG.validation.queryMaximumLength },
      limit: { type: "integer", minimum: 1, maximum: CONFIG.search.maximumResults, default: CONFIG.search.defaultResults },
      detailed: { type: "boolean", default: false, description: "Ask vulnx for richer records." },
      full_details: { type: "boolean", default: false, description: "Disable compact field truncation; the response ceiling still applies." },
      product: { type: "string", minLength: 1, maxLength: CONFIG.validation.productMaximumLength },
      vendor: { type: "string", minLength: 1, maxLength: CONFIG.validation.vendorMaximumLength },
    }, ["query"]),
  },
  {
    name: "vulnx_cve",
    description: "Fetch vulnerability intelligence for one CVE identifier.",
    inputSchema: objectSchema({ cve_id: cveProperty }, ["cve_id"]),
  },
  {
    name: "vulnx_filters",
    description: "List supported upstream search fields and filters.",
    inputSchema: objectSchema({ raw: { type: "boolean", default: false } }),
  },
  {
    name: "vulnx_batch_cve",
    description: "Fetch multiple CVE records with normalized IDs and bounded concurrency.",
    inputSchema: objectSchema({
      cve_ids: { type: "array", minItems: 1, maxItems: CONFIG.batch.maximum, items: cveProperty },
      continue_on_error: { type: "boolean", default: true },
    }, ["cve_ids"]),
  },
  {
    name: "vulnx_prioritize",
    description: "Deterministically prioritize supplied CVE IDs or vulnerability signal objects.",
    inputSchema: objectSchema({
      cve_ids: { type: "array", minItems: 1, maxItems: CONFIG.prioritization.maximum, items: cveProperty },
      vulnerabilities: { type: "array", minItems: 1, maxItems: CONFIG.prioritization.maximum, items: suppliedVulnerabilityInputSchema },
    }),
  },
  {
    name: "vulnx_product_exposure",
    description: "Find vulnerability records relevant to validated vendor and product input without asserting target exposure.",
    inputSchema: objectSchema({
      vendor: { type: "string", minLength: 1, maxLength: CONFIG.validation.vendorMaximumLength },
      product: { type: "string", minLength: 1, maxLength: CONFIG.validation.productMaximumLength },
      version: { type: "string", minLength: 1, maxLength: CONFIG.validation.versionMaximumLength },
      limit: { type: "integer", minimum: 1, maximum: CONFIG.search.maximumResults, default: CONFIG.search.productDefaultResults },
      detailed: { type: "boolean", default: false },
    }, ["vendor", "product"]),
  },
  {
    name: "vulnx_compare",
    description: "Compare normalized vulnerability intelligence for two or more unique CVE identifiers.",
    inputSchema: objectSchema({
      cve_ids: { type: "array", minItems: 2, maxItems: CONFIG.comparison.maximum, items: cveProperty },
    }, ["cve_ids"]),
  },
  {
    name: "vulnx_enrich_findings",
    description: "Enrich submitted findings by CVE ID only; this tool never scans supplied targets.",
    inputSchema: objectSchema({
      findings: { type: "array", minItems: 1, maxItems: CONFIG.enrichment.maximum, items: findingInputSchema },
      deduplicate_cves: { type: "boolean", default: true },
      include_priority: { type: "boolean", default: true },
    }, ["findings"]),
  },
  {
    name: "vulnx_status",
    description: "Report safe server, runtime, cache, and pinned-build metadata without exposing secrets.",
    inputSchema: objectSchema({}),
  },
];

function exitCodeForError(error) {
  if (typeof error?.code === "number") return error.code;
  if (error?.code === "ABORT_ERR") return 130;
  if (error?.killed || error?.signal === "SIGTERM") return 124;
  return 1;
}

export function runVulnx(args = [], options = {}) {
  const {
    signal,
    execFileImpl = execFile,
    timeout = CONFIG.process.timeoutMs,
    maxBuffer = CONFIG.process.maxBufferBytes,
  } = options;
  return new Promise((resolve) => {
    const finish = (error, stdout = "", stderr = "") => resolve({
      stdout: String(stdout ?? ""),
      stderr: String(stderr || error?.message || ""),
      exitCode: error ? exitCodeForError(error) : 0,
    });
    try {
      execFileImpl("vulnx", [...args, "--json"], {
        env: { ...process.env },
        encoding: "utf8",
        timeout,
        maxBuffer,
        signal,
      }, finish);
    } catch (error) {
      finish(error);
    }
  });
}

function stripAnsi(value) {
  return value.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "");
}

export function runVulnxVersion(options = {}) {
  const {
    signal,
    execFileImpl = execFile,
    configuration = CONFIG,
  } = options;
  return new Promise((resolve) => {
    const finish = (error, stdout = "", stderr = "") => {
      const output = stripAnsi(`${stdout}\n${stderr}`);
      const match = output.match(/\bv?\d+\.\d+\.\d+\b/i);
      resolve({ available: !error, version: match?.[0] ?? null });
    };
    try {
      execFileImpl("vulnx", ["version", "--disable-update-check", "--silent"], {
        env: { ...process.env },
        encoding: "utf8",
        timeout: configuration.status.processTimeoutMs,
        maxBuffer: configuration.status.processMaxBufferBytes,
        signal,
      }, finish);
    } catch (error) {
      finish(error);
    }
  });
}

export function formatOutput({ stdout, stderr, exitCode }) {
  if (exitCode !== 0) return `vulnx exited with code ${exitCode}:\n${stderr || stdout || "Unknown error"}`;
  if (!stdout.trim()) return "No results returned.";
  try {
    return JSON.stringify(JSON.parse(stdout), null, 2);
  } catch {
    return stdout;
  }
}

function parseOutput(stdout) {
  try {
    return { success: true, data: JSON.parse(stdout) };
  } catch {
    return { success: false, data: null };
  }
}

function serializedBytes(value) {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function truncateUtf8(value, maxBytes, suffix = "… [truncated]") {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return value;
  const suffixBytes = Buffer.byteLength(suffix, "utf8");
  let low = 0;
  let high = value.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(value.slice(0, middle), "utf8") + suffixBytes <= maxBytes) low = middle;
    else high = middle - 1;
  }
  return `${value.slice(0, low)}${suffix}`;
}

export function getMaxResponseBytes(value = process.env.VULNX_MAX_RESPONSE_BYTES) {
  if (value === undefined) return CONFIG.response.maxBytes;
  return loadConfiguration({ VULNX_MAX_RESPONSE_BYTES: String(value) }).response.maxBytes;
}

function compactJsonValue(value, state, configuration, depth = 0) {
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") <= configuration.compact.stringBytes) return value;
    state.truncatedValues += 1;
    return truncateUtf8(value, configuration.compact.stringBytes);
  }
  if (!value || typeof value !== "object") return value;
  if (depth >= configuration.compact.maximumDepth) {
    state.truncatedValues += 1;
    return "[omitted: maximum nesting depth reached]";
  }
  if (Array.isArray(value)) {
    const limit = depth === 0 ? value.length : Math.min(value.length, configuration.compact.nestedArrayItems);
    const compacted = value.slice(0, limit).map((item) => compactJsonValue(item, state, configuration, depth + 1));
    if (limit < value.length) {
      state.truncatedValues += 1;
      compacted.push({ _vulnx_mcp_truncated: true, omittedItems: value.length - limit });
    }
    return compacted;
  }
  return Object.fromEntries(Object.entries(value).map(([key, nested]) => [
    key,
    compactJsonValue(nested, state, configuration, depth + 1),
  ]));
}

function fitOversizedJsonResponse(response, maxResponseBytes, originalResponseBytes) {
  const source = JSON.stringify(response.structuredContent ?? {});
  const message = `The vulnx response exceeded the ${maxResponseBytes}-byte MCP response limit and was truncated. A bounded partial-JSON text preview is available in structuredContent.previewText.`;
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
    } else high = middle - 1;
  }
  return best;
}

export function boundToolResponse(response, maxResponseBytes = CONFIG.response.maxBytes) {
  const originalResponseBytes = serializedBytes(response);
  if (originalResponseBytes <= maxResponseBytes) return response;
  if (response.structuredContent) return fitOversizedJsonResponse(response, maxResponseBytes, originalResponseBytes);
  const originalText = response.content?.[0]?.text ?? "Response truncated.";
  const suffix = `\n\n[truncated to the ${maxResponseBytes}-byte MCP response limit]`;
  let low = 0;
  let high = originalText.length;
  let best = { ...response, content: [{ type: "text", text: suffix.trim() }] };
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = { ...response, content: [{ type: "text", text: `${originalText.slice(0, middle)}${suffix}` }] };
    if (serializedBytes(candidate) <= maxResponseBytes) {
      best = candidate;
      low = middle + 1;
    } else high = middle - 1;
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
    metadata = {},
    configuration = CONFIG,
    maxResponseBytes = configuration.response.maxBytes,
  } = options;
  const response = {
    content: [{
      type: "text",
      text: result.exitCode === 0
        ? formatOutput(result)
        : `vulnx exited with code ${result.exitCode}`,
    }],
    isError: result.exitCode !== 0,
  };
  const parsed = result.exitCode === 0 ? parseOutput(result.stdout) : { success: false };
  if (parsed.success) {
    if (compact) {
      const state = { truncatedValues: 0 };
      const data = compactJsonValue(parsed.data, state, configuration);
      response.content[0].text = `Returned ${describeJson(data)} in compact mode. Use full_details=true to request unabridged fields; the response-size limit always applies.`;
      response.structuredContent = { data, compact: true, truncatedValues: state.truncatedValues, ...metadata };
    } else response.structuredContent = { data: parsed.data, ...metadata };
  }
  return boundToolResponse(response, maxResponseBytes);
}

function jsonToolResult(data, text, options = {}) {
  const { isError = false, configuration = CONFIG } = options;
  return boundToolResponse({
    content: [{ type: "text", text }],
    structuredContent: data,
    isError,
  }, configuration.response.maxBytes);
}

export function summarizeFiltersJson(stdout, configuration = CONFIG) {
  const parsed = parseOutput(stdout);
  if (!parsed.success || !parsed.data || typeof parsed.data !== "object") return null;
  const value = parsed.data;
  const summary = [];
  if (Array.isArray(value)) {
    for (const item of value.slice(0, configuration.filters.maximumFields)) {
      if (item && typeof item === "object" && item.name) summary.push({ name: item.name, type: item.type || typeof item.example, example: item.example ?? null });
    }
    return { summary, truncated: value.length > configuration.filters.maximumFields };
  }
  if (value.fields && typeof value.fields === "object") {
    const entries = Object.entries(value.fields);
    for (const [name, info] of entries.slice(0, configuration.filters.maximumFields)) {
      summary.push({ name, type: info?.type || typeof info?.example, example: info?.example ?? info?.sample ?? info?.example_value ?? null });
    }
    return { summary, truncated: entries.length > configuration.filters.maximumFields };
  }
  const entries = Object.entries(value).filter(([key]) => key !== "count");
  for (const [name, nested] of entries.slice(0, configuration.filters.maximumFields)) {
    summary.push({ name, type: Array.isArray(nested) ? "array" : typeof nested, example: Array.isArray(nested) ? nested[0] ?? null : nested });
  }
  return { summary, truncated: entries.length > configuration.filters.maximumFields };
}

function invalidArgumentsResult(toolName, error) {
  const details = error.issues.map((issue) => `${issue.path.join(".") || "arguments"}: ${issue.message}`).join("; ");
  return { content: [{ type: "text", text: `Invalid arguments for ${toolName}: ${details}` }], isError: true };
}

function parseArguments(schema, toolName, argumentsValue) {
  const parsed = schema.safeParse(argumentsValue ?? {});
  return parsed.success ? { data: parsed.data } : { error: invalidArgumentsResult(toolName, parsed.error) };
}

function batchOptions(context, requested, continueOnError = true) {
  return {
    runner: context.runner,
    cache: context.cache,
    signal: context.signal,
    concurrency: context.configuration.batch.concurrency,
    requested,
    continueOnError,
  };
}

async function handleSearch(argumentsValue, context) {
  const parsed = parseArguments(searchArgumentsSchema, "vulnx_search", argumentsValue);
  if (parsed.error) return parsed.error;
  const { query, limit, detailed, full_details, product, vendor } = parsed.data;
  const cliArguments = ["search", query, "--limit", String(limit)];
  if (detailed) cliArguments.push("--detailed");
  if (product) cliArguments.push("--product", product);
  if (vendor) cliArguments.push("--vendor", vendor);
  const execution = await executeCachedVulnx("search", cliArguments, {
    ...context,
    cacheArguments: parsed.data,
  });
  return toolResult(execution.result, {
    compact: !full_details,
    metadata: { cache: execution.cache },
    configuration: context.configuration,
  });
}

async function handleCve(argumentsValue, context) {
  const parsed = parseArguments(cveArgumentsSchema, "vulnx_cve", argumentsValue);
  if (parsed.error) return parsed.error;
  const cveId = normalizeCveId(parsed.data.cve_id);
  const execution = await executeCachedVulnx("cve", ["id", cveId], {
    ...context,
    cacheArguments: { cve_id: cveId },
  });
  return toolResult(execution.result, {
    metadata: { cache: execution.cache },
    configuration: context.configuration,
  });
}

async function handleFilters(argumentsValue, context) {
  const parsed = parseArguments(filtersArgumentsSchema, "vulnx_filters", argumentsValue);
  if (parsed.error) return parsed.error;
  const execution = await executeCachedVulnx("filters", ["filters"], {
    ...context,
    cacheArguments: { raw: parsed.data.raw },
  });
  if (execution.result.exitCode !== 0 || parsed.data.raw) {
    return toolResult(execution.result, { metadata: { cache: execution.cache }, configuration: context.configuration });
  }
  const data = summarizeFiltersJson(execution.result.stdout, context.configuration);
  if (!data) return toolResult(execution.result, { metadata: { cache: execution.cache }, configuration: context.configuration });
  return jsonToolResult({ ...data, cache: execution.cache }, `Returned ${data.summary.length} filter summaries.`, { configuration: context.configuration });
}

async function handleBatch(argumentsValue, context) {
  const parsed = parseArguments(batchArgumentsSchema, "vulnx_batch_cve", argumentsValue);
  if (parsed.error) return parsed.error;
  const result = await lookupCveBatch(parsed.data.cve_ids, batchOptions(context, parsed.data.cve_ids.length, parsed.data.continue_on_error));
  const stoppedOnFailure = !parsed.data.continue_on_error && result.failed > 0;
  return jsonToolResult(
    result,
    stoppedOnFailure ? "Batch lookup stopped after the first vulnx failure." : `Completed ${result.results.length} batch lookup results.`,
    { isError: stoppedOnFailure, configuration: context.configuration },
  );
}

async function handlePrioritize(argumentsValue, context) {
  const parsed = parseArguments(prioritizeArgumentsSchema, "vulnx_prioritize", argumentsValue);
  if (parsed.error) return parsed.error;
  let results;
  let failures = [];
  let cache = null;
  if (parsed.data.vulnerabilities) {
    const normalized = parsed.data.vulnerabilities.map((item) => ({ ...item, cve_id: normalizeCveId(item.cve_id) }));
    results = prioritizeVulnerabilities(normalized, context.configuration.prioritization.scoring);
  } else {
    const batch = await lookupCveBatch(parsed.data.cve_ids, batchOptions(context, parsed.data.cve_ids.length));
    results = batch.results
      .filter((item) => item.success)
      .map((item) => scoreVulnerability(item.data, context.configuration.prioritization.scoring, item.cve_id))
      .sort(comparePriority);
    failures = batch.results.filter((item) => !item.success);
    cache = batch.cache;
  }
  const output = {
    ranking_method: context.configuration.prioritization.scoring.version,
    disclaimer: context.configuration.prioritization.scoring.disclaimer,
    results,
    failures,
    ...(cache ? { cache } : {}),
  };
  return jsonToolResult(output, `Prioritized ${results.length} vulnerability records using ${output.ranking_method}.`, { configuration: context.configuration });
}

async function handleProductExposure(argumentsValue, context) {
  const parsed = parseArguments(productExposureArgumentsSchema, "vulnx_product_exposure", argumentsValue);
  if (parsed.error) return parsed.error;
  const { vendor, product, version, limit, detailed } = parsed.data;
  const cliArguments = ["search", product, "--limit", String(limit), "--vendor", vendor, "--product", product];
  if (detailed) cliArguments.push("--detailed");
  const execution = await executeCachedVulnx("product_exposure", cliArguments, {
    ...context,
    cacheArguments: parsed.data,
  });
  if (execution.result.exitCode !== 0) return toolResult(execution.result, { configuration: context.configuration });
  const upstream = parseOutput(execution.result.stdout);
  if (!upstream.success) return { content: [{ type: "text", text: "vulnx returned malformed JSON." }], isError: true };
  const output = {
    vendor,
    product,
    ...(version ? { version } : {}),
    match_confidence: version ? "unavailable" : "approximate",
    query_used: `search query=${JSON.stringify(product)} vendor=${JSON.stringify(vendor)} product=${JSON.stringify(product)}`,
    results: upstream.data,
    warnings: [
      "Version matching depends on upstream vulnerability metadata.",
      "Confirm affected version ranges manually; this result does not prove target exposure.",
    ],
    cache: execution.cache,
  };
  return jsonToolResult(output, "Returned product-relevant vulnerability intelligence with exposure caveats.", { configuration: context.configuration });
}

function highestCveBy(records, field) {
  return records
    .filter((record) => typeof record[field] === "number")
    .sort((left, right) => right[field] - left[field] || String(left.cve_id).localeCompare(String(right.cve_id)))[0]?.cve_id ?? null;
}

async function handleCompare(argumentsValue, context) {
  const parsed = parseArguments(compareArgumentsSchema, "vulnx_compare", argumentsValue);
  if (parsed.error) return parsed.error;
  const batch = await lookupCveBatch(parsed.data.cve_ids, batchOptions(context, parsed.data.cve_ids.length));
  const comparison = batch.results.filter((item) => item.success).map((item) => normalizeVulnerability(item.data, item.cve_id));
  const priorities = comparison.map((item) => scoreVulnerability(item, context.configuration.prioritization.scoring)).sort(comparePriority);
  const output = {
    compared: comparison.length,
    highest_priority: priorities[0]?.cve_id ?? null,
    scoring_version: context.configuration.prioritization.scoring.version,
    comparison,
    failures: batch.results.filter((item) => !item.success),
    summary: {
      highest_cvss: highestCveBy(comparison, "cvss_score"),
      highest_epss: highestCveBy(comparison, "epss_score"),
      kev_listed: comparison.filter((item) => item.is_kev === true).map((item) => item.cve_id),
    },
    cache: batch.cache,
  };
  return jsonToolResult(output, `Compared ${comparison.length} normalized vulnerability records.`, { configuration: context.configuration });
}

async function handleEnrichment(argumentsValue, context) {
  const parsed = parseArguments(enrichArgumentsSchema, "vulnx_enrich_findings", argumentsValue);
  if (parsed.error) return parsed.error;
  const cveIds = normalizeCveIds(parsed.data.findings.map((finding) => finding.cve_id).filter(Boolean));
  const batch = await lookupCveBatch(cveIds, batchOptions(context, cveIds.length));
  const lookup = new Map(batch.results.map((item) => [item.cve_id, item]));
  let enriched = 0;
  const results = parsed.data.findings.map((finding) => {
    const cveId = normalizeCveId(finding.cve_id);
    if (!cveId) return { finding, success: false, reason: "No valid CVE identifier was provided" };
    const intelligence = lookup.get(cveId);
    if (!intelligence?.success) return { finding, success: false, reason: intelligence?.error ?? "No enrichment was available" };
    enriched += 1;
    const enrichment = { cve: intelligence.data };
    if (parsed.data.include_priority) {
      const priority = scoreVulnerability(intelligence.data, context.configuration.prioritization.scoring, cveId);
      enrichment.priority = {
        scoring_version: context.configuration.prioritization.scoring.version,
        score: priority.score,
        priority: priority.priority,
        reasons: priority.reasons,
        missing_signals: priority.missing_signals,
      };
    }
    return { finding, enrichment, success: true };
  });
  const output = {
    findings_received: parsed.data.findings.length,
    unique_cves: cveIds.length,
    lookup_deduplicated: true,
    enriched,
    unenriched: results.length - enriched,
    results,
    cache: batch.cache,
  };
  return jsonToolResult(output, `Enriched ${enriched} of ${results.length} submitted findings by CVE ID only.`, { configuration: context.configuration });
}

async function handleStatus(argumentsValue, context) {
  const parsed = parseArguments(statusArgumentsSchema, "vulnx_status", argumentsValue);
  if (parsed.error) return parsed.error;
  const vulnx = await context.versionRunner({ signal: context.signal, configuration: context.configuration });
  const output = {
    server: context.configuration.server,
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    vulnx: { available: Boolean(vulnx.available), version: vulnx.version ?? null },
    configuration: {
      api_key_configured: Boolean(context.environment.PDCP_API_KEY),
      batch_maximum: context.configuration.batch.maximum,
      batch_concurrency: context.configuration.batch.concurrency,
      comparison_maximum: context.configuration.comparison.maximum,
      enrichment_maximum: context.configuration.enrichment.maximum,
      max_response_bytes: context.configuration.response.maxBytes,
      process_timeout_ms: context.configuration.process.timeoutMs,
      process_max_buffer_bytes: context.configuration.process.maxBufferBytes,
      cache_enabled: context.cache.enabled,
      cache_ttl_seconds: context.configuration.cache.ttlSeconds,
      cache_max_entries: context.configuration.cache.maxEntries,
    },
    build: { pinned_vulnx_ref: context.configuration.build.revision, upstream_vulnx_version: context.configuration.build.upstreamVersion },
  };
  return jsonToolResult(output, "Returned safe vulnx MCP server status metadata.", { configuration: context.configuration });
}

const TOOL_HANDLERS = new Map([
  ["vulnx_search", handleSearch],
  ["vulnx_cve", handleCve],
  ["vulnx_filters", handleFilters],
  ["vulnx_batch_cve", handleBatch],
  ["vulnx_prioritize", handlePrioritize],
  ["vulnx_product_exposure", handleProductExposure],
  ["vulnx_compare", handleCompare],
  ["vulnx_enrich_findings", handleEnrichment],
  ["vulnx_status", handleStatus],
]);

export async function handleToolCall(name, argumentsValue, options = {}) {
  const configuration = options.configuration ?? CONFIG;
  const handler = TOOL_HANDLERS.get(name);
  if (!handler) {
    return boundToolResponse(
      { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true },
      configuration.response.maxBytes,
    );
  }
  const context = {
    runner: options.runner ?? runVulnx,
    versionRunner: options.versionRunner ?? runVulnxVersion,
    cache: options.cache ?? new ResultCache(configuration.cache),
    signal: options.signal,
    configuration,
    environment: options.environment ?? process.env,
  };
  const response = await handler(argumentsValue, context);
  return boundToolResponse(response, configuration.response.maxBytes);
}

export function internalErrorResult(error, logger = (message) => process.stderr.write(message)) {
  const diagnostics = error instanceof Error ? error.stack || error.message : String(error);
  logger(`Internal error: ${diagnostics}\n`);
  return { content: [{ type: "text", text: "The vulnx MCP server encountered an internal error." }], isError: true };
}

export function createServer(options = {}) {
  const configuration = options.configuration ?? CONFIG;
  const cache = options.cache ?? new ResultCache(configuration.cache);
  const server = new Server(configuration.server, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    try {
      return await handleToolCall(request.params.name, request.params.arguments, {
        ...options,
        cache,
        configuration,
        signal: extra.signal,
      });
    } catch (error) {
      return boundToolResponse(
        internalErrorResult(error, options.logger),
        configuration.response.maxBytes,
      );
    }
  });
  return server;
}

export async function startServer() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  process.stderr.write(`${CONFIG.server.name} ${CONFIG.server.version} started (stdio transport)\n`);
}

const isMainModule = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMainModule) await startServer();
