import assert from "node:assert/strict";
import test from "node:test";

import { createCacheKey, ResultCache, stableSerialize } from "../cache.js";
import { CONFIG, loadConfiguration, PRIORITY_SCORING_V1 } from "../config.js";

test("configuration provides centralized defaults and validated overrides", () => {
  assert.equal(CONFIG.batch.maximum, 50);
  assert.equal(CONFIG.batch.concurrency, 4);
  assert.equal(CONFIG.comparison.maximum, 20);
  assert.equal(CONFIG.enrichment.maximum, 100);
  assert.equal(CONFIG.process.timeoutMs, 30_000);
  assert.equal(CONFIG.process.maxBufferBytes, 10 * 1024 * 1024);
  assert.equal(CONFIG.response.maxBytes, 512 * 1024);
  assert.equal(CONFIG.cache.ttlSeconds, 300);
  assert.equal(CONFIG.cache.maxEntries, 500);
  assert.equal(CONFIG.server.version, "1.1.0");

  const overridden = loadConfiguration({
    VULNX_BATCH_CONCURRENCY: "7",
    VULNX_CACHE_TTL_SECONDS: "60",
    VULNX_CACHE_MAX_ENTRIES: "40",
    VULNX_MAX_RESPONSE_BYTES: "8192",
    VULNX_PROCESS_TIMEOUT_MS: "45000",
    VULNX_PROCESS_MAX_BUFFER_BYTES: String(2 * 1024 * 1024),
  });
  assert.equal(overridden.batch.concurrency, 7);
  assert.equal(overridden.cache.ttlSeconds, 60);
  assert.equal(overridden.cache.maxEntries, 40);
  assert.equal(overridden.response.maxBytes, 8192);
  assert.equal(overridden.process.timeoutMs, 45_000);
  assert.equal(overridden.process.maxBufferBytes, 2 * 1024 * 1024);
});

test("invalid environment settings fall back safely and configuration is immutable", () => {
  const invalid = loadConfiguration({
    VULNX_BATCH_CONCURRENCY: "0",
    VULNX_CACHE_TTL_SECONDS: "86401",
    VULNX_CACHE_MAX_ENTRIES: "secret",
    VULNX_MAX_RESPONSE_BYTES: "1",
    VULNX_PROCESS_TIMEOUT_MS: "999",
  });
  assert.equal(invalid.batch.concurrency, CONFIG.batch.concurrency);
  assert.equal(invalid.cache.ttlSeconds, CONFIG.cache.ttlSeconds);
  assert.equal(invalid.cache.maxEntries, CONFIG.cache.maxEntries);
  assert.equal(invalid.response.maxBytes, CONFIG.response.maxBytes);
  assert.equal(invalid.process.timeoutMs, CONFIG.process.timeoutMs);
  assert.equal(Object.isFrozen(invalid), true);
  assert.equal(Object.isFrozen(PRIORITY_SCORING_V1.weights), true);
});

test("stable cache keys normalize object order and exclude sensitive values", () => {
  const first = createCacheKey("operation", {
    query: "value",
    nested: { second: 2, first: 1 },
    PDCP_API_KEY: "never-cache-this",
    signal: { aborted: false },
  });
  const second = createCacheKey("operation", {
    nested: { first: 1, second: 2 },
    query: "value",
  });
  assert.equal(first, second);
  assert.doesNotMatch(first, /never-cache-this|PDCP_API_KEY|aborted/);
  assert.equal(stableSerialize({ z: 1, a: 2 }), '{"a":2,"z":1}');
});

test("result cache reports hits, expires entries, and supports disabled mode", () => {
  let now = 1_000;
  const cache = new ResultCache({ ttlSeconds: 2, maxEntries: 2, clock: () => now });
  assert.equal(cache.get("missing"), null);
  cache.set("key", { value: 1 });
  now = 2_500;
  assert.deepEqual(cache.get("key"), { value: { value: 1 }, ageSeconds: 1 });
  now = 3_001;
  assert.equal(cache.get("key"), null);

  const disabled = new ResultCache({ ttlSeconds: 0, maxEntries: 2 });
  disabled.set("key", { value: 1 });
  assert.equal(disabled.size, 0);
  assert.equal(disabled.get("key"), null);
});

test("result cache enforces LRU maximum-entry eviction", () => {
  let now = 0;
  const cache = new ResultCache({ ttlSeconds: 100, maxEntries: 2, clock: () => now });
  cache.set("first", 1);
  now += 1;
  cache.set("second", 2);
  cache.get("first");
  now += 1;
  cache.set("third", 3);
  assert.equal(cache.get("second"), null);
  assert.equal(cache.get("first").value, 1);
  assert.equal(cache.get("third").value, 3);
  assert.equal(cache.size, 2);
});
