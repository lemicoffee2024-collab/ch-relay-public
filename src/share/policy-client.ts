/**
 * Agent-side policy bundle loader.
 *
 * Flow: POST {policyUrl}/v1/policy {license} → {v, bundle} → setPolicy().
 * The bundle lives in memory only. An encrypted on-disk cache lets the agent
 * survive restarts while the licensing server is unreachable; the cache key
 * is derived from the license, so the file is inert without it.
 *
 * Fail-closed: no bundle + no valid cache = refuse to start.
 */

import { createHash, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "../paths.ts";
import { pinnedFetch } from "../net/pin.ts";
import { getSetting, setSetting } from "../store/db.ts";
import { setPolicy, clearPolicy, type PolicySpec } from "./policy.ts";
import { log } from "../lib/log.ts";

const CACHE_FILE = () => join(HOME, "policy.cache");
export const LICENSE_FILE = () => join(HOME, "license.key");
const CACHE_TTL_MS = Number(process.env.CH_POLICY_CACHE_TTL_MS ?? 72 * 3600_000);
// Built-in default so a licensed binary works with only license.key —
// CH_POLICY_URL remains the override for staging/alternate hosts.
const DEFAULT_POLICY_URL = "https://codex2.nhtbgr.online";

export function policyBaseUrl(): string {
  return (process.env.CH_POLICY_URL ?? DEFAULT_POLICY_URL).replace(/\/+$/, "");
}

// Wire-transport secret compiled into the agent: the /v1/policy response is
// AES-256-GCM ciphertext keyed on it, so a license alone + curl yields only
// noise. Split into fragments — a plain strings scan finds two inert halves;
// reading them requires pulling the actual module out of the binary anyway.
const W_A = "";
const W_B = "";
const WIRE_SECRET = () => `${W_A}${W_B}`;

interface PolicyResponse {
  v: number;
  ct: string;
  expiresAt?: number | null;
}

function unsealBundle(license: string, ct64: string): PolicySpec {
  const key = createHash("sha256").update(`${WIRE_SECRET()}|${license}`).digest();
  const buf = Buffer.from(ct64, "base64");
  const d = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(buf.length - 16));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString("utf8"));
}

function cacheKey(license: string): Buffer {
  return createHash("sha256").update(`ch-relay-cache:${license}`).digest();
}

function dropCache(): void {
  try { rmSync(CACHE_FILE(), { force: true }); } catch { /* best effort */ }
}

const DEVICE_FILE = () => join(HOME, "device.id");
let cachedDevice: string | null = null;
/** Stable per-install machine id — generated once, lets the policy server
 *  count how many distinct machines a license is activated on. */
export function deviceId(): string {
  if (cachedDevice) return cachedDevice;
  try {
    if (existsSync(DEVICE_FILE())) {
      const d = readFileSync(DEVICE_FILE(), "utf8").trim();
      if (d) return (cachedDevice = d);
    }
  } catch { /* fallthrough */ }
  const d = randomBytes(12).toString("hex");
  try {
    mkdirSync(HOME, { recursive: true });
    writeFileSync(DEVICE_FILE(), d + "\n");
  } catch { /* best effort — still usable this run */ }
  return (cachedDevice = d);
}

function saveCache(license: string, bundle: PolicySpec): void {
  try {
    mkdirSync(HOME, { recursive: true });
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", cacheKey(license), iv);
    const enc = Buffer.concat([c.update(JSON.stringify(bundle), "utf8"), c.final()]);
    writeFileSync(
      CACHE_FILE(),
      JSON.stringify({ iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: enc.toString("base64"), at: Date.now() }),
      { mode: 0o600 },
    );
  } catch (err) {
    log.info(`policy cache write failed: ${err instanceof Error ? err.message : err}`);
  }
}

function loadCache(license: string): PolicySpec | null {
  try {
    if (!existsSync(CACHE_FILE())) return null;
    const j = JSON.parse(readFileSync(CACHE_FILE(), "utf8"));
    if (Date.now() - (j.at ?? 0) > CACHE_TTL_MS) return null;
    const d = createDecipheriv("aes-256-gcm", cacheKey(license), Buffer.from(j.iv, "base64"));
    d.setAuthTag(Buffer.from(j.tag, "base64"));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(j.data, "base64")), d.final()]).toString("utf8"));
  } catch {
    return null;
  }
}

export function readLicense(flagValue?: string): string | null {
  if (flagValue) return flagValue.trim();
  const env = process.env.CH_LICENSE;
  if (env?.trim()) return env.trim();
  try {
    if (existsSync(LICENSE_FILE())) return readFileSync(LICENSE_FILE(), "utf8").trim() || null;
  } catch { /* fallthrough */ }
  return null;
}

/**
 * Fetch the policy bundle. Throws when neither the server nor a fresh cache
 * can provide one — callers must not start the data plane without a policy.
 */
export async function loadPolicy(license: string): Promise<{ source: "server" | "cache"; v: number }> {
  const url = policyBaseUrl();
  if (url) {
    try {
      const res = await pinnedFetch(`${url}/v1/policy`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${license}` },
        body: JSON.stringify({ license, device: deviceId() }),
        signal: AbortSignal.timeout(15_000),
      });
      if (res.ok) {
        const j = (await res.json()) as PolicyResponse;
        if (j?.ct && typeof j.ct === "string") {
          const bundle = unsealBundle(license, j.ct);
          setPolicy(bundle);
          saveCache(license, bundle);
          void postPendingFlags();
          return { source: "server", v: j.v ?? bundle.v ?? 0 };
        }
      } else {
        // 403 with our JSON error = explicit rejection (revoked/expired/
        // unknown). Wipe RAM bundle AND disk cache — otherwise the cache
        // would resurrect the bundle every refresh. A Cloudflare/WAF block
        // page is also 403 but HTML, so it does not parse as our error
        // shape and falls through to the cache rescue like a network
        // failure — correct, that is an infra problem not a revocation.
        if (res.status === 403) {
          const j = (await res.json().catch(() => null)) as { error?: string } | null;
          if (j && typeof j.error === "string") {
            dropCache();
            clearPolicy();
            throw new Error(`license rejected: ${j.error}`);
          }
        }
        log.info(`policy fetch status=${res.status}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("license rejected")) throw err;
      log.info(`policy fetch failed: ${err instanceof Error ? err.message : err}`);
    }
  }
  const cached = loadCache(license);
  if (cached) {
    setPolicy(cached);
    return { source: "cache", v: cached.v };
  }
  throw new Error("no policy bundle: license unreachable and no valid cache");
}

/** Background refresh — picks up bundle updates and revokes over time.
 *  Default 1h (CH_POLICY_REFRESH_MS overrides); on explicit 403 the sealed
 *  bundle and disk cache are wiped, so a revoked key stops working within
 *  one interval instead of waiting for a restart. */
const REFRESH_MS = Number(process.env.CH_POLICY_REFRESH_MS ?? 3600_000);
export function startPolicyRefresh(license: string, intervalMs = REFRESH_MS): void {
  const tick = async () => {
    try {
      await loadPolicy(license);
      // Telemetry rides the same cadence — dynamic import keeps the upload
      // module (which depends on this file's license/device helpers) out of
      // a require cycle.
      const { reportTelemetry } = await import("./telemetry-upload.ts");
      await reportTelemetry();
    } catch (err) {
      log.info(`policy refresh failed: ${err instanceof Error ? err.message : err}`);
    }
  };
  const t = setInterval(tick, intervalMs);
  t.unref();
  // First tick shortly after start: a fresh install's sign-of-life and the
  // operator's first telemetry row shouldn't wait a full interval.
  const first = setTimeout(tick, 60_000);
  first.unref();
}

/** Extraction tripwire: RAM + disk bundle wiped immediately. The refresh
 *  timer may re-fetch later — only a server-side license flag makes the
 *  kill stick, so callers should also reportFlag(). */
export function wipePolicy(): void {
  dropCache();
  clearPolicy();
}

/** Pending flag reports survive restart/network loss: a tripwire hit is
 *  queued in settings and reposted on every policy refresh until the server
 *  acknowledges it — otherwise a probe fired while the edge blocks the client
 *  IP (e.g. Cloudflare rate-limit) would evaporate. */
const FLAG_PENDING_KEY = "flag_pending";

async function postPendingFlags(): Promise<void> {
  let pending: string[];
  try {
    pending = getSetting<string[]>(FLAG_PENDING_KEY, []);
  } catch {
    return;
  }
  if (!pending.length) return;
  const license = readLicense();
  const url = policyBaseUrl();
  if (!license || !url) return;
  const left: string[] = [];
  for (let i = 0; i < pending.length; i++) {
    const hit = pending[i]!;
    try {
      const res = await pinnedFetch(`${url}/v1/flag`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${license}` },
        body: JSON.stringify({ license, device: deviceId(), hit }),
        signal: AbortSignal.timeout(8_000),
      });
      if (!res.ok) left.push(hit);
    } catch {
      left.push(...pending.slice(i));
      break;
    }
  }
  try {
    setSetting(FLAG_PENDING_KEY, left.slice(-10));
  } catch { /* best effort */ }
}

/** Tell the server this device probed for secret tokens. Queued first, then
 *  posted — retries ride the hourly policy refresh until acknowledged. */
export function reportFlag(hit: string): void {
  try {
    const pending = getSetting<string[]>(FLAG_PENDING_KEY, []);
    pending.push(hit.slice(0, 80));
    setSetting(FLAG_PENDING_KEY, pending.slice(-10));
    void postPendingFlags();
  } catch { /* never let reporting break the data path */ }
}
