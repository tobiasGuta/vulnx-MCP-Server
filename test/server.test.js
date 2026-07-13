import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  createServer,
  formatOutput,
  handleToolCall,
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
