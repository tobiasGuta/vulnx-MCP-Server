import { createCacheKey } from "./cache.js";
import { CONFIG } from "./config.js";
import { normalizeCveIds } from "./vulnerability.js";

function parseJson(value) {
  try {
    return { success: true, data: JSON.parse(value) };
  } catch {
    return { success: false, data: null };
  }
}

function cacheMetadata(cache, hit, ageSeconds = 0) {
  return {
    enabled: Boolean(cache?.enabled),
    hit,
    age_seconds: ageSeconds,
    ttl_seconds: cache?.ttlSeconds ?? 0,
  };
}

export async function executeCachedVulnx(
  operation,
  cliArguments,
  options,
) {
  const {
    runner,
    signal,
    cache,
    cacheArguments = cliArguments,
    behavior = CONFIG.build.revision,
  } = options;
  const key = createCacheKey(operation, cacheArguments, behavior);
  const cached = cache?.get(key);
  if (cached) {
    return {
      result: cached.value,
      cache: cacheMetadata(cache, true, cached.ageSeconds),
      cacheKey: key,
    };
  }

  const result = await runner(cliArguments, { signal });
  const parsed = result.exitCode === 0 ? parseJson(result.stdout) : { success: false };
  const cancelled = signal?.aborted || result.exitCode === 130;
  if (cache?.enabled && result.exitCode === 0 && parsed.success && !cancelled) {
    cache.set(key, result);
  }
  return {
    result,
    cache: cacheMetadata(cache, false),
    cacheKey: key,
  };
}

function safeFailure(cveId, result) {
  return {
    cve_id: cveId,
    success: false,
    error: result.exitCode === 0
      ? "vulnx returned malformed JSON"
      : `vulnx exited with code ${result.exitCode}`,
  };
}

async function oneCve(cveId, options) {
  const execution = await executeCachedVulnx(
    "cve",
    ["id", cveId],
    {
      ...options,
      cacheArguments: { cve_id: cveId },
    },
  );
  if (execution.result.exitCode !== 0) {
    return { item: safeFailure(cveId, execution.result), cache: execution.cache };
  }
  const parsed = parseJson(execution.result.stdout);
  if (!parsed.success) {
    return { item: safeFailure(cveId, execution.result), cache: execution.cache };
  }
  return {
    item: {
      cve_id: cveId,
      success: true,
      data: parsed.data,
    },
    cache: execution.cache,
  };
}

export async function mapWithConcurrency(items, concurrency, worker, signal) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(concurrency, items.length);

  async function consume() {
    while (nextIndex < items.length) {
      if (signal?.aborted) return;
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await worker(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: workerCount }, consume));
  return results;
}

export async function lookupCveBatch(cveIds, options) {
  const {
    requested = cveIds.length,
    continueOnError = true,
    concurrency = CONFIG.batch.concurrency,
    signal,
  } = options;
  const uniqueCveIds = normalizeCveIds(cveIds);
  let entries;

  if (continueOnError) {
    entries = await mapWithConcurrency(
      uniqueCveIds,
      concurrency,
      (cveId) => oneCve(cveId, options),
      signal,
    );
  } else {
    entries = [];
    for (const cveId of uniqueCveIds) {
      if (signal?.aborted) break;
      const entry = await oneCve(cveId, options);
      entries.push(entry);
      if (!entry.item.success) break;
    }
  }

  const completedEntries = entries.filter(Boolean);
  const results = completedEntries.map((entry) => entry.item);
  const successful = results.filter((item) => item.success).length;
  const failed = results.length - successful;
  const cacheHits = completedEntries.filter((entry) => entry.cache.hit).length;
  return {
    requested,
    unique: uniqueCveIds.length,
    successful,
    failed,
    stopped_early: !continueOnError && failed > 0 && results.length < uniqueCveIds.length,
    results,
    cache: {
      enabled: Boolean(options.cache?.enabled),
      hits: cacheHits,
      misses: completedEntries.length - cacheHits,
      ttl_seconds: options.cache?.ttlSeconds ?? 0,
    },
  };
}
