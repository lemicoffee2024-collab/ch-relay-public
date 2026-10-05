/**
 * Support telemetry — hourly aggregate counters to the license server so the
 * operator can see whether a customer's agent is actually serving traffic
 * (the policy fetch cadence alone only proves the process is alive).
 *
 * Privacy: counts only — request totals per model/status/error-kind plus the
 * reporting window. No prompts, no tool arguments, no user text. Customers on
 * locked-down networks or who object can disable it with CH_TELEMETRY=0.
 *
 * The window is anchored in settings (telemetry_last_at) so a missed upload
 * — server unreachable, edge block — carries forward into the next report
 * instead of silently dropping the period's counts.
 */
import { getDb, getSetting, setSetting } from "../store/db.ts";
import { pinnedFetch } from "../net/pin.ts";
import { policyBaseUrl, readLicense, deviceId } from "./policy-client.ts";
import { errorKind } from "../lib/error-kind.ts";
import { log } from "../lib/log.ts";

const LAST_KEY = "telemetry_last_at";
/** Floor between reports — the refresh tick is hourly; this only guards
 *  against callers invoking us more often than intended. */
const MIN_SPAN_MS = 15 * 60_000;

export async function reportTelemetry(): Promise<void> {
  if (process.env.CH_TELEMETRY === "0") return;
  const license = readLicense();
  const url = policyBaseUrl();
  if (!license || !url) return;
  const last = Number(getSetting<number>(LAST_KEY, 0)) || 0;
  const now = Date.now();
  if (now - last < MIN_SPAN_MS) return;
  try {
    const rows = getDb()
      .query(
        `SELECT requested_model m, status s, error e, COUNT(*) n, AVG(duration_ms) d
         FROM usage WHERE ts > ? GROUP BY m, s, e`,
      )
      .all(last) as Array<{ m: string; s: number; e: string | null; n: number; d: number | null }>;

    let requests = 0;
    let errors = 0;
    let msSum = 0;
    const models: Record<string, number> = {};
    const statuses: Record<string, number> = {};
    const kinds: Record<string, number> = {};
    for (const r of rows) {
      requests += r.n;
      msSum += (r.d ?? 0) * r.n;
      models[r.m || "?"] = (models[r.m || "?"] ?? 0) + r.n;
      statuses[String(r.s)] = (statuses[String(r.s)] ?? 0) + r.n;
      const k = errorKind(r.s, r.e);
      if (k !== "ok") {
        errors += r.n;
        kinds[k] = (kinds[k] ?? 0) + r.n;
      }
    }

    const res = await pinnedFetch(`${url}/v1/telemetry`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${license}` },
      body: JSON.stringify({
        license,
        device: deviceId(),
        at: now,
        spanMs: now - last,
        requests,
        errors,
        avgMs: requests ? Math.round(msSum / requests) : 0,
        models,
        statuses,
        kinds,
      }),
      signal: AbortSignal.timeout(8_000),
    });
    // Only advance the window once the server acknowledged — on failure the
    // same rows are recounted into the next report.
    if (res.ok) setSetting(LAST_KEY, now);
    else log.info(`telemetry upload status=${res.status}`);
  } catch (err) {
    log.info(`telemetry upload failed: ${err instanceof Error ? err.message : err}`);
  }
}
