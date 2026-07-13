import { readFileSync } from "node:fs";

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function readBuildMetadata() {
  const contents = readFileSync(new URL("./config/vulnx.json", import.meta.url), "utf8");
  return JSON.parse(contents);
}

function integerSetting(env, name, fallback, minimum, maximum) {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^-?\d+$/.test(String(raw))) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) return fallback;
  return value;
}

export const SERVER_METADATA = deepFreeze({
  name: "vulnx-mcp",
  version: "1.1.0",
});

export const BUILD_METADATA = deepFreeze(readBuildMetadata());

export const PRIORITY_SCORING_V1 = deepFreeze({
  version: "v1",
  weights: {
    kev: 30,
    remote: 10,
    publicPoc: 8,
    nucleiTemplate: 5,
    ransomware: 15,
  },
  reasons: {
    kev: "CISA KEV listed",
    remote: "Remote exploitation is possible",
    publicPoc: "Public proof of concept is available",
    nucleiTemplate: "Nuclei template is available",
    ransomware: "Known ransomware association is present",
  },
  epssBands: [
    { minimum: 0.9, points: 25, reason: "EPSS score is at least 0.90" },
    { minimum: 0.7, points: 18, reason: "EPSS score is at least 0.70" },
    { minimum: 0.4, points: 10, reason: "EPSS score is at least 0.40" },
    { minimum: 0.1, points: 5, reason: "EPSS score is at least 0.10" },
  ],
  cvssBands: [
    { minimum: 9, points: 20, reason: "CVSS score is at least 9.0" },
    { minimum: 7, points: 14, reason: "CVSS score is at least 7.0" },
    { minimum: 4, points: 7, reason: "CVSS score is at least 4.0" },
  ],
  priorityThresholds: {
    critical: 75,
    high: 50,
    medium: 25,
  },
  disclaimer:
    "Prioritization is decision support based on available vulnerability intelligence; it is not proof of exploitability or target exposure.",
});

export function loadConfiguration(env = process.env) {
  const configuration = {
    server: SERVER_METADATA,
    build: BUILD_METADATA,
    batch: {
      maximum: 50,
      concurrency: integerSetting(env, "VULNX_BATCH_CONCURRENCY", 4, 1, 10),
    },
    comparison: {
      maximum: 20,
    },
    prioritization: {
      maximum: 50,
      scoring: PRIORITY_SCORING_V1,
    },
    enrichment: {
      maximum: 100,
    },
    search: {
      maximumResults: 100,
      defaultResults: 10,
      productDefaultResults: 25,
    },
    process: {
      timeoutMs: integerSetting(env, "VULNX_PROCESS_TIMEOUT_MS", 30_000, 1_000, 120_000),
      maxBufferBytes: integerSetting(
        env,
        "VULNX_PROCESS_MAX_BUFFER_BYTES",
        10 * 1024 * 1024,
        1024 * 1024,
        50 * 1024 * 1024,
      ),
    },
    response: {
      maxBytes: integerSetting(
        env,
        "VULNX_MAX_RESPONSE_BYTES",
        512 * 1024,
        4 * 1024,
        5 * 1024 * 1024,
      ),
    },
    cache: {
      ttlSeconds: integerSetting(env, "VULNX_CACHE_TTL_SECONDS", 300, 0, 86_400),
      maxEntries: integerSetting(env, "VULNX_CACHE_MAX_ENTRIES", 500, 1, 10_000),
    },
    compact: {
      stringBytes: 4 * 1024,
      nestedArrayItems: 25,
      maximumDepth: 8,
    },
    filters: {
      maximumFields: 200,
    },
    status: {
      processTimeoutMs: 5_000,
      processMaxBufferBytes: 64 * 1024,
      maximumVersionTextBytes: 256,
    },
    validation: {
      cveMaximumLength: 32,
      queryMaximumLength: 1_000,
      vendorMaximumLength: 128,
      productMaximumLength: 128,
      versionMaximumLength: 128,
      hostMaximumLength: 253,
      protocolMaximumLength: 32,
      sourceMaximumLength: 64,
      templateMaximumLength: 128,
      titleMaximumLength: 512,
      severityMaximumLength: 32,
      metadataMaximumBytes: 64 * 1024,
      portMinimum: 1,
      portMaximum: 65_535,
    },
  };
  return deepFreeze(configuration);
}

export const CONFIG = loadConfiguration();
