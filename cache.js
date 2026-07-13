import { BUILD_METADATA } from "./config.js";

const SENSITIVE_KEY_PATTERN = /(api.?key|authorization|credential|password|secret|signal|token)/i;

function cloneValue(value) {
  return structuredClone(value);
}

function safeKeyValue(value) {
  if (Array.isArray(value)) return value.map(safeKeyValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !SENSITIVE_KEY_PATTERN.test(key))
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, safeKeyValue(nested)]),
  );
}

export function stableSerialize(value) {
  return JSON.stringify(safeKeyValue(value));
}

export function createCacheKey(operation, argumentsValue, behavior = BUILD_METADATA.revision) {
  return stableSerialize({
    operation,
    arguments: argumentsValue,
    behavior,
  });
}

export class ResultCache {
  constructor({ ttlSeconds, maxEntries, clock = () => Date.now() }) {
    this.ttlSeconds = ttlSeconds;
    this.maxEntries = maxEntries;
    this.clock = clock;
    this.entries = new Map();
  }

  get enabled() {
    return this.ttlSeconds > 0;
  }

  get size() {
    return this.entries.size;
  }

  get(key) {
    if (!this.enabled) return null;
    const entry = this.entries.get(key);
    if (!entry) return null;
    const now = this.clock();
    const ageMilliseconds = now - entry.createdAt;
    if (ageMilliseconds >= this.ttlSeconds * 1_000) {
      this.entries.delete(key);
      return null;
    }

    this.entries.delete(key);
    this.entries.set(key, entry);
    return {
      value: cloneValue(entry.value),
      ageSeconds: Math.max(0, Math.floor(ageMilliseconds / 1_000)),
    };
  }

  set(key, value) {
    if (!this.enabled) return;
    this.pruneExpired();
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldestKey = this.entries.keys().next().value;
      this.entries.delete(oldestKey);
    }
    this.entries.set(key, {
      value: cloneValue(value),
      createdAt: this.clock(),
    });
  }

  pruneExpired() {
    if (!this.enabled) {
      this.entries.clear();
      return;
    }
    const now = this.clock();
    for (const [key, entry] of this.entries) {
      if (now - entry.createdAt >= this.ttlSeconds * 1_000) this.entries.delete(key);
    }
  }

  clear() {
    this.entries.clear();
  }
}
