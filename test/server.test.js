import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  boundToolResponse,
  createServer,
  formatOutput,
  getMaxResponseBytes,
  handleToolCall,
  internalErrorResult,
  runVulnx,
  summarizeFiltersJson,
  toolResult,
} from "../server.js";

const ok = (stdout = "[]") => ({ stdout, stderr: "", exitCode: 0 });

test("runVulnx passes shell metacharacters as one literal argv entry", async () => {
  let invocation;
  const execFileImpl = (file, args, options, callback) => {
    invocation = { file, args, options };
    callback(null, "[]", "");
  };

  const result = await runVulnx(["search", "apache; id"], { execFileImpl });

  assert.equal(result.exitCode, 0);
  assert.equal(invocation.file, "vulnx");
  assert.deepEqual(invocation.args, ["search", "apache; id", "--json"]);
  assert.equal(invocation.options.timeout, 30_000);
  assert.equal(invocation.options.maxBuffer, 10 * 1024 * 1024);
});

test("runVulnx maps a killed timeout to a nonzero result", async () => {
  const execFileImpl = (_file, _args, _options, callback) => {
    const error = Object.assign(new Error("timed out"), {
      killed: true,
      signal: "SIGTERM",
    });
    callback(error, "partial", "");
  };

  const result = await runVulnx(["filters"], { execFileImpl });
  assert.equal(result.exitCode, 124);
  assert.equal(result.stdout, "partial");
  assert.match(result.stderr, /timed out/);
});

test("formatOutput handles malformed JSON, empty output, and errors", () => {
  assert.equal(formatOutput(ok("not-json")), "not-json");
  assert.equal(formatOutput(ok("  ")), "No results returned.");
  assert.match(
    formatOutput({ stdout: "", stderr: "failure", exitCode: 2 }),
    /code 2:\nfailure/,
  );
});

test("toolResult flags CLI failures and exposes parsed JSON structurally", () => {
  const failure = toolResult({ stdout: "", stderr: "bad query", exitCode: 2 });
  assert.equal(failure.isError, true);
  assert.equal(failure.structuredContent, undefined);

  const success = toolResult(ok('{"id":"CVE-2021-44228"}'));
  assert.equal(success.isError, false);
  assert.deepEqual(success.structuredContent, {
    data: { id: "CVE-2021-44228" },
  });
});

test("response-size configuration accepts only safe byte ceilings", () => {
  assert.equal(getMaxResponseBytes(), 512 * 1024);
  assert.equal(getMaxResponseBytes("4096"), 4096);
  assert.equal(getMaxResponseBytes("5242880"), 5 * 1024 * 1024);
  assert.equal(getMaxResponseBytes("4095"), 512 * 1024);
  assert.equal(getMaxResponseBytes("not-a-number"), 512 * 1024);
});

test("oversized structured and text responses obey the serialized-byte ceiling", () => {
  const structured = toolResult(
    ok(JSON.stringify({ payload: "x".repeat(50_000) })),
    { maxResponseBytes: 4096 },
  );
  assert.ok(Buffer.byteLength(JSON.stringify(structured), "utf8") <= 4096);
  assert.equal(structured.structuredContent.truncated, true);
  assert.equal(structured.structuredContent.maxResponseBytes, 4096);

  const text = boundToolResponse({
    content: [{ type: "text", text: "y".repeat(50_000) }],
    isError: true,
  }, 4096);
  assert.ok(Buffer.byteLength(JSON.stringify(text), "utf8") <= 4096);
  assert.match(text.content[0].text, /truncated to the 4096-byte/);
});

test("search compacts large fields by default and supports explicit full details", async () => {
  const description = "detail ".repeat(2_000);
  const runner = async () => ok(JSON.stringify([{ id: "CVE-2025-1234", description }]));

  const compact = await handleToolCall(
    "vulnx_search",
    { query: "apache" },
    { runner, maxResponseBytes: 100_000 },
  );
  assert.equal(compact.structuredContent.compact, true);
  assert.equal(compact.structuredContent.truncatedValues, 1);
  assert.ok(
    Buffer.byteLength(compact.structuredContent.data[0].description, "utf8") <= 4096,
  );
  assert.match(compact.content[0].text, /compact mode/);

  const full = await handleToolCall(
    "vulnx_search",
    { query: "apache", full_details: true },
    { runner, maxResponseBytes: 100_000 },
  );
  assert.equal(full.structuredContent.data[0].description, description);
  assert.equal(full.structuredContent.compact, undefined);
});

test("unexpected internal errors are logged but not exposed to MCP clients", () => {
  const logged = [];
  const secret = "C:\\private\\workspace\\dependency.js";
  const response = internalErrorResult(
    new Error(`failure in ${secret}`),
    (message) => logged.push(message),
  );
  assert.equal(
    response.content[0].text,
    "The vulnx MCP server encountered an internal error.",
  );
  assert.equal(response.isError, true);
  assert.doesNotMatch(JSON.stringify(response), /private|dependency\.js/);
  assert.match(logged.join(""), /private\\workspace\\dependency\.js/);
});

test("search validates types and boundaries before invoking vulnx", async () => {
  let calls = 0;
  const runner = async () => {
    calls += 1;
    return ok();
  };

  for (const args of [
    {},
    { query: " " },
    { query: "apache", limit: 0 },
    { query: "apache", limit: 101 },
    { query: "apache", limit: 1.5 },
    { query: "apache", detailed: "yes" },
    { query: "apache", full_details: "yes" },
    { query: "apache", product: "x".repeat(257) },
    { query: "apache", unexpected: true },
  ]) {
    const result = await handleToolCall("vulnx_search", args, { runner });
    assert.equal(result.isError, true);
  }

  assert.equal(calls, 0);
  const valid = await handleToolCall(
    "vulnx_search",
    { query: "apache", limit: 100, detailed: true },
    { runner },
  );
  assert.equal(valid.isError, false);
  assert.equal(calls, 1);
});

test("all search strings remain distinct literal CLI arguments", async () => {
  let received;
  const runner = async (args) => {
    received = args;
    return ok();
  };
  await handleToolCall(
    "vulnx_search",
    {
      query: "apache; id",
      product: "httpd && whoami",
      vendor: "$(uname)",
    },
    { runner },
  );
  assert.deepEqual(received, [
    "search",
    "apache; id",
    "--limit",
    "10",
    "--product",
    "httpd && whoami",
    "--vendor",
    "$(uname)",
  ]);
});

test("CVE and filter arguments are validated at runtime", async () => {
  const runner = async () => ok();
  assert.equal(
    (await handleToolCall("vulnx_cve", { cve_id: "CVE-2024-1;id" }, { runner })).isError,
    true,
  );
  assert.equal(
    (await handleToolCall("vulnx_filters", { raw: "true" }, { runner })).isError,
    true,
  );
  assert.equal(
    (await handleToolCall("vulnx_filters", undefined, { runner })).isError,
    false,
  );
});

test("CLI failures from every tool become MCP errors", async () => {
  const runner = async () => ({ stdout: "", stderr: "upstream failed", exitCode: 7 });
  const search = await handleToolCall("vulnx_search", { query: "apache" }, { runner });
  const cve = await handleToolCall("vulnx_cve", { cve_id: "CVE-2021-44228" }, { runner });
  const filters = await handleToolCall("vulnx_filters", {}, { runner });
  assert.equal(search.isError, true);
  assert.equal(cve.isError, true);
  assert.equal(filters.isError, true);
});

test("filter summaries cap large arrays and report truncation accurately", () => {
  const fields = Array.from({ length: 205 }, (_, index) => ({
    name: `field_${index}`,
    type: "string",
    example: `value_${index}`,
  }));
  const result = summarizeFiltersJson(JSON.stringify(fields));
  assert.equal(result.summary.length, 200);
  assert.equal(result.truncated, true);
  assert.equal(summarizeFiltersJson("broken"), null);
});

test("request cancellation signal is forwarded to the CLI runner", async () => {
  const controller = new AbortController();
  let receivedSignal;
  const runner = async (_args, options) => {
    receivedSignal = options.signal;
    return ok();
  };
  await handleToolCall("vulnx_search", { query: "apache" }, {
    runner,
    signal: controller.signal,
  });
  assert.equal(receivedSignal, controller.signal);
});

test("MCP initialize, tools/list, and tools/call work end to end", async (t) => {
  const runner = async (args) => ok(JSON.stringify({ argv: args }));
  const server = createServer({ runner });
  const client = new Client({ name: "vulnx-test-client", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(async () => {
    await client.close();
    await server.close();
  });

  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map((tool) => tool.name), [
    "vulnx_search",
    "vulnx_cve",
    "vulnx_filters",
  ]);

  const called = await client.callTool({
    name: "vulnx_cve",
    arguments: { cve_id: "CVE-2021-44228" },
  });
  assert.equal(called.isError, false);
  assert.deepEqual(called.structuredContent, {
    data: { argv: ["id", "CVE-2021-44228"] },
  });
});

test("MCP request handler redacts a runner exception end to end", async (t) => {
  const logged = [];
  const runner = async () => {
    throw new Error("failure at C:\\private\\runner.js");
  };
  const server = createServer({ runner, logger: (message) => logged.push(message) });
  const client = new Client({ name: "vulnx-error-client", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(async () => {
    await client.close();
    await server.close();
  });

  const called = await client.callTool({
    name: "vulnx_filters",
    arguments: {},
  });
  assert.equal(called.isError, true);
  assert.equal(
    called.content[0].text,
    "The vulnx MCP server encountered an internal error.",
  );
  assert.doesNotMatch(JSON.stringify(called), /private|runner\.js/);
  assert.match(logged.join(""), /private\\runner\.js/);
});
