import assert from "node:assert/strict";
import test from "node:test";

import { ResultCache } from "../cache.js";
import { CONFIG, loadConfiguration } from "../config.js";
import { handleToolCall } from "../server.js";

const ok = (data) => ({ stdout: JSON.stringify(data), stderr: "", exitCode: 0 });

test("batch lookup normalizes case, removes duplicates, and preserves order", async () => {
  const calls = [];
  const runner = async (args, options) => {
    calls.push({ args, signal: options.signal });
    return ok({ cve_id: args[1] });
  };
  const controller = new AbortController();
  const result = await handleToolCall("vulnx_batch_cve", {
    cve_ids: ["cve-2025-1000", "CVE-2025-2000", "CVE-2025-1000"],
  }, { runner, signal: controller.signal });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.requested, 3);
  assert.equal(result.structuredContent.unique, 2);
  assert.deepEqual(
    result.structuredContent.results.map((item) => item.cve_id),
    ["CVE-2025-1000", "CVE-2025-2000"],
  );
  assert.equal(calls.length, 2);
  assert.ok(calls.every((call) => call.signal === controller.signal));
});

test("batch lookup returns mixed failures or stops early as requested", async () => {
  const failingId = "CVE-2025-2000";
  const runner = async (args) => args[1] === failingId
    ? { stdout: "", stderr: "private diagnostic", exitCode: 7 }
    : ok({ cve_id: args[1] });
  const ids = ["CVE-2025-1000", failingId, "CVE-2025-3000"];

  const continued = await handleToolCall("vulnx_batch_cve", {
    cve_ids: ids,
    continue_on_error: true,
  }, { runner });
  assert.equal(continued.isError, false);
  assert.equal(continued.structuredContent.successful, 2);
  assert.equal(continued.structuredContent.failed, 1);
  assert.doesNotMatch(JSON.stringify(continued), /private diagnostic/);

  const calls = [];
  const stoppingRunner = async (args) => {
    calls.push(args[1]);
    return runner(args);
  };
  const stopped = await handleToolCall("vulnx_batch_cve", {
    cve_ids: ids,
    continue_on_error: false,
  }, { runner: stoppingRunner });
  assert.equal(stopped.isError, true);
  assert.deepEqual(calls, ["CVE-2025-1000", failingId]);
  assert.equal(stopped.structuredContent.stopped_early, true);
});

test("batch concurrency never exceeds configured limit", async () => {
  let active = 0;
  let maximumActive = 0;
  const runner = async (args) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    return ok({ cve_id: args[1] });
  };
  const configuration = loadConfiguration({ VULNX_BATCH_CONCURRENCY: "3" });
  const cveIds = Array.from({ length: 12 }, (_, index) => `CVE-2025-${String(index + 1000)}`);
  const result = await handleToolCall("vulnx_batch_cve", { cve_ids: cveIds }, {
    runner,
    configuration,
  });
  assert.equal(result.structuredContent.successful, 12);
  assert.ok(maximumActive <= 3);
});

test("batch validation enforces maximum size and CVE format", async () => {
  let calls = 0;
  const runner = async () => {
    calls += 1;
    return ok({});
  };
  const tooMany = Array.from({ length: CONFIG.batch.maximum + 1 }, (_, index) => `CVE-2025-${index + 1000}`);
  const maximum = tooMany.slice(0, CONFIG.batch.maximum);
  const boundary = await handleToolCall("vulnx_batch_cve", { cve_ids: maximum }, { runner });
  assert.equal(boundary.structuredContent.successful, CONFIG.batch.maximum);
  assert.equal(calls, CONFIG.batch.maximum);
  assert.equal((await handleToolCall("vulnx_batch_cve", { cve_ids: tooMany }, { runner })).isError, true);
  assert.equal((await handleToolCall("vulnx_batch_cve", { cve_ids: ["invalid"] }, { runner })).isError, true);
  assert.equal(calls, CONFIG.batch.maximum);
});

test("prioritization supports supplied records and CVE lookup mode", async () => {
  const supplied = await handleToolCall("vulnx_prioritize", {
    vulnerabilities: [
      { cve_id: "cve-2025-1000", cvss_score: 9.2, epss_score: 0.95, is_kev: true },
      { cve_id: "CVE-2025-2000", cvss_score: 4.1, epss_score: 0.11, is_kev: false },
    ],
  });
  assert.equal(supplied.structuredContent.ranking_method, "v1");
  assert.equal(supplied.structuredContent.results[0].cve_id, "CVE-2025-1000");
  assert.match(supplied.structuredContent.disclaimer, /decision support/i);

  const runner = async (args) => ok({
    cve_id: args[1],
    cvss_score: 8,
    epss_score: 0.5,
    is_remote: true,
  });
  const lookedUp = await handleToolCall("vulnx_prioritize", {
    cve_ids: ["CVE-2025-3000"],
  }, { runner });
  assert.equal(lookedUp.structuredContent.results[0].cve_id, "CVE-2025-3000");
  assert.equal(lookedUp.structuredContent.results[0].score, 34);
});

test("prioritization rejects absent, mixed, and unexpected input modes", async () => {
  assert.equal((await handleToolCall("vulnx_prioritize", {})).isError, true);
  assert.equal((await handleToolCall("vulnx_prioritize", {
    cve_ids: ["CVE-2025-1000"],
    vulnerabilities: [{ cve_id: "CVE-2025-1000" }],
  })).isError, true);
  assert.equal((await handleToolCall("vulnx_prioritize", {
    vulnerabilities: [{ cve_id: "CVE-2025-1000", extra: true }],
  })).isError, true);
});

test("product exposure uses literal supported flags and makes no exact version claim", async () => {
  let received;
  const runner = async (args) => {
    received = args;
    return ok([{ cve_id: "CVE-2025-1000" }]);
  };
  const result = await handleToolCall("vulnx_product_exposure", {
    vendor: "generic-vendor;id",
    product: "generic-product && whoami",
    version: "1.2.3",
    detailed: true,
  }, { runner });
  assert.deepEqual(received, [
    "search",
    "generic-product && whoami",
    "--limit",
    "25",
    "--vendor",
    "generic-vendor;id",
    "--product",
    "generic-product && whoami",
    "--detailed",
  ]);
  assert.equal(result.structuredContent.match_confidence, "unavailable");
  assert.match(result.structuredContent.warnings.join(" "), /does not prove target exposure/i);
  assert.doesNotMatch(JSON.stringify(received), /1\.2\.3/);
});

test("product exposure validates input and bounds oversized responses", async () => {
  let calls = 0;
  const runner = async () => {
    calls += 1;
    return ok([{ description: "x".repeat(50_000) }]);
  };
  assert.equal((await handleToolCall("vulnx_product_exposure", {
    vendor: "",
    product: "value",
  }, { runner })).isError, true);
  assert.equal(calls, 0);

  const configuration = loadConfiguration({ VULNX_MAX_RESPONSE_BYTES: "4096" });
  const bounded = await handleToolCall("vulnx_product_exposure", {
    vendor: "vendor",
    product: "product",
  }, { runner, configuration });
  assert.ok(Buffer.byteLength(JSON.stringify(bounded), "utf8") <= 4096);
  assert.equal(bounded.structuredContent.truncated, true);
});

test("comparison normalizes successful records, reports failures, and builds summaries", async () => {
  const runner = async (args) => {
    if (args[1] === "CVE-2025-3000") return { stdout: "", stderr: "failure", exitCode: 2 };
    return ok({
      data: {
        id: args[1],
        cvss: args[1] === "CVE-2025-1000" ? 9.8 : 7.5,
        epss: args[1] === "CVE-2025-1000" ? 0.91 : 0.4,
        kev: args[1] === "CVE-2025-1000",
      },
    });
  };
  const result = await handleToolCall("vulnx_compare", {
    cve_ids: ["CVE-2025-1000", "CVE-2025-2000", "CVE-2025-3000"],
  }, { runner });
  assert.equal(result.structuredContent.compared, 2);
  assert.equal(result.structuredContent.failures.length, 1);
  assert.equal(result.structuredContent.summary.highest_cvss, "CVE-2025-1000");
  assert.equal(result.structuredContent.summary.highest_epss, "CVE-2025-1000");
  assert.deepEqual(result.structuredContent.summary.kev_listed, ["CVE-2025-1000"]);
  assert.equal(result.structuredContent.highest_priority, "CVE-2025-1000");
  assert.equal(result.structuredContent.scoring_version, "v1");
});

test("comparison requires two unique valid CVE identifiers", async () => {
  assert.equal((await handleToolCall("vulnx_compare", {
    cve_ids: ["CVE-2025-1000", "cve-2025-1000"],
  })).isError, true);
});

test("finding enrichment fetches unique CVEs once and never sends target details", async () => {
  const calls = [];
  const runner = async (args) => {
    calls.push(args);
    return ok({
      cve_id: args[1],
      cvss_score: 9.1,
      epss_score: 0.8,
      is_kev: true,
    });
  };
  const findings = [
    { host: "host-one.test", port: 443, cve_id: "CVE-2025-1000", metadata: { owner: "team-a" } },
    { host: "host-two.test", cve_id: "cve-2025-1000", title: "finding-two" },
    { host: "host-three.test" },
  ];
  const result = await handleToolCall("vulnx_enrich_findings", { findings }, { runner });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], ["id", "CVE-2025-1000"]);
  assert.equal(result.structuredContent.results[0].finding.host, "host-one.test");
  assert.deepEqual(result.structuredContent.results[0].finding.metadata, { owner: "team-a" });
  assert.equal(result.structuredContent.results[1].finding.title, "finding-two");
  assert.equal(result.structuredContent.results[2].success, false);
  assert.match(result.structuredContent.results[2].reason, /No valid CVE/);
  assert.equal(result.structuredContent.results[0].enrichment.priority.scoring_version, "v1");
  assert.equal(result.structuredContent.enriched, 2);
  assert.equal(result.structuredContent.unenriched, 1);
  assert.doesNotMatch(JSON.stringify(calls), /host-one|443|team-a|finding-two/);
});

test("finding enrichment validates ports and requires at least one CVE", async () => {
  assert.equal((await handleToolCall("vulnx_enrich_findings", {
    findings: [{ host: "host.test", port: 0, cve_id: "CVE-2025-1000" }],
  })).isError, true);
  assert.equal((await handleToolCall("vulnx_enrich_findings", {
    findings: [{ host: "host.test" }],
  })).isError, true);
  assert.equal((await handleToolCall("vulnx_enrich_findings", {
    findings: [{ cve_id: "CVE-2025-1000", metadata: { invalid: undefined } }],
  })).isError, true);
});

test("cache hits equivalent searches and CVE lookups without caching failures", async () => {
  const cache = new ResultCache({ ttlSeconds: 300, maxEntries: 10 });
  let searchCalls = 0;
  const searchRunner = async () => {
    searchCalls += 1;
    return ok([]);
  };
  const uncachedSearch = await handleToolCall("vulnx_search", { query: " value " }, { runner: searchRunner, cache });
  const cachedSearch = await handleToolCall("vulnx_search", { query: "value" }, { runner: searchRunner, cache });
  assert.equal(searchCalls, 1);
  assert.equal(uncachedSearch.structuredContent.cache.hit, false);
  assert.equal(cachedSearch.structuredContent.cache.hit, true);

  let failureCalls = 0;
  const failureRunner = async () => {
    failureCalls += 1;
    return { stdout: "", stderr: "failure", exitCode: 1 };
  };
  await handleToolCall("vulnx_cve", { cve_id: "CVE-2025-1000" }, { runner: failureRunner, cache });
  await handleToolCall("vulnx_cve", { cve_id: "CVE-2025-1000" }, { runner: failureRunner, cache });
  assert.equal(failureCalls, 2);
});

test("cancelled and malformed executions are never cached", async () => {
  const cache = new ResultCache({ ttlSeconds: 300, maxEntries: 10 });
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  const runner = async () => {
    calls += 1;
    return ok({ value: calls });
  };
  await handleToolCall("vulnx_cve", { cve_id: "CVE-2025-1000" }, {
    runner,
    cache,
    signal: controller.signal,
  });
  await handleToolCall("vulnx_cve", { cve_id: "CVE-2025-1000" }, { runner, cache });
  assert.equal(calls, 2);

  let malformedCalls = 0;
  const malformed = async () => {
    malformedCalls += 1;
    return { stdout: "not-json", stderr: "", exitCode: 0 };
  };
  await handleToolCall("vulnx_cve", { cve_id: "CVE-2025-2000" }, { runner: malformed, cache });
  await handleToolCall("vulnx_cve", { cve_id: "CVE-2025-2000" }, { runner: malformed, cache });
  assert.equal(malformedCalls, 2);
});

test("status reports only safe shared configuration and partial vulnx availability", async () => {
  const secret = "secret-value-that-must-not-appear";
  const unavailable = await handleToolCall("vulnx_status", {}, {
    versionRunner: async () => ({ available: false, version: null }),
    environment: { PDCP_API_KEY: secret, OTHER_SECRET: "also-private" },
  });
  const output = unavailable.structuredContent;
  assert.equal(output.server.version, "1.1.0");
  assert.equal(output.vulnx.available, false);
  assert.equal(output.vulnx.version, null);
  assert.equal(output.configuration.api_key_configured, true);
  assert.equal(output.configuration.max_response_bytes, CONFIG.response.maxBytes);
  assert.equal(output.configuration.cache_ttl_seconds, CONFIG.cache.ttlSeconds);
  assert.equal(output.build.pinned_vulnx_ref, CONFIG.build.revision);
  assert.doesNotMatch(JSON.stringify(unavailable), new RegExp(secret));
  assert.doesNotMatch(JSON.stringify(unavailable), /OTHER_SECRET|also-private|process\.env/);
});
