import { providers } from "./providers/index.ts";
import {
  clearCooldown,
  deleteAccount,
  getAccount,
  listAccounts,
  publicAccount,
  updateAccountSettings,
} from "./store/accounts.ts";
import { queryRequests, SPAN_MAX_MS, usageSummary } from "./usage.ts";
import { syncCodex, unsyncCodex } from "./codex-sync.ts";
import { AUTO_REVIEW_SLUG } from "./providers/chatgpt/catalog.ts";
import { jsonError } from "./lib/sse.ts";
import { pinnedFetch } from "./net/pin.ts";
import { getSetting, setSetting } from "./store/db.ts";
import { spawn } from "node:child_process";
import { AGENT_EXE_PATH, DEFAULT_SHARE_PORT, installKeyQuery } from "./paths.ts";
import { addShareUser, listShareUsers, removeShareUser, setShareUserEnabled, setShareUserExpiry, shareAccountId } from "./share/users.ts";
import { publicBaseUrl } from "./share/server.ts";
import { shareLast24h, shareStats, shareUserStats } from "./share/stats.ts";
import { listShareEvents } from "./share/telemetry.ts";
import { log } from "./lib/log.ts";
import type { ProviderId } from "./types.ts";

const PROVIDER_IDS = Object.keys(providers) as ProviderId[];
const RANGES: Record<string, number> = { "1h": 3600_000, "24h": 86400_000, "7d": 7 * 86400_000, "30d": 30 * 86400_000, "90d": SPAN_MAX_MS };

// Query-string parsing for the read-only stats routes: strict, bounded, never NaN.
const INT = /^\d{1,15}$/;
function intParam(url: URL, name: string, min: number, max: number): number | undefined {
  const v = url.searchParams.get(name);
  if (v === null || !INT.test(v)) return undefined;
  return Math.max(min, Math.min(max, Number(v)));
}
function textParam(url: URL, name: string, max = 120): string | undefined {
  const v = url.searchParams.get(name)?.trim();
  return v ? v.slice(0, max) : undefined;
}
function enumParam<T extends string>(url: URL, name: string, allowed: readonly T[]): T | undefined {
  const v = url.searchParams.get(name);
  return allowed.includes(v as T) ? (v as T) : undefined;
}
/** `?range=1h|24h|7d|30d|90d` (default 24h) or an explicit `?from=&to=` in epoch ms; never wider than 90 days. */
function windowParam(url: URL): { since: number; until: number } {
  const now = Date.now();
  const from = intParam(url, "from", 0, now);
  const to = intParam(url, "to", 0, now + 60_000);
  if (from !== undefined && to !== undefined && to > from) return { since: Math.max(from, to - SPAN_MAX_MS), until: to };
  const span = RANGES[url.searchParams.get("range") ?? "24h"] ?? RANGES["24h"]!;
  return { since: now - span, until: now };
}
const ACCOUNT_RE = /^[A-Za-z0-9:._@+-]{1,200}$/;

let serverPort = 0;
let serverStartedAt = Date.now();
export function setApiServerInfo(port: number, startedAt: number) {
  serverPort = port;
  serverStartedAt = startedAt;
}

/**
 * Management API guard. The server only binds 127.0.0.1, but a web page in the user's
 * browser could still send requests to localhost: reject foreign Origins, and require a
 * custom header on writes (forces a CORS preflight we never approve).
 */
function forbidden(req: Request, url: URL): string | null {
  const origin = req.headers.get("origin");
  if (origin) {
    // Behind a tunnel (admin/share ports) the public origin is https://<forwarded host>.
    const proto = req.headers.get("x-forwarded-proto") ?? url.protocol.replace(/:$/, "");
    const hosts = [url.host, req.headers.get("x-forwarded-host")?.split(",")[0]?.trim()];
    if (!hosts.some((h) => h && origin === `${proto}://${h}`)) return "foreign origin";
  }
  if (req.method !== "GET" && req.headers.get("x-ch-relay") !== "1") return "missing x-ch-relay header";
  return null;
}

async function readJson<T>(req: Request): Promise<T> {
  try {
    return (await req.json()) as T;
  } catch {
    return {} as T;
  }
}

export async function handleApi(req: Request, url: URL): Promise<Response> {
  const why = forbidden(req, url);
  if (why) return jsonError(403, why, "forbidden");
  const parts = url.pathname.split("/").filter(Boolean).slice(1); // drop "api"
  const [head, a, b, c] = parts;
  const m = req.method;

  try {
    // GET /api/status
    if (head === "status" && m === "GET") {
      return Response.json({
        version: "0.1.0",
        port: serverPort,
        uptimeMs: Date.now() - serverStartedAt,
        providers: PROVIDER_IDS.map((id) => {
          const accs = listAccounts(id);
          return { id, accounts: accs.length, enabled: accs.filter((x) => x.enabled && x.status === "ok").length };
        }),
      });
    }

    // /api/accounts
    if (head === "accounts") {
      if (!a && m === "GET") return Response.json(listAccounts().map(publicAccount));
      // POST /api/accounts/:provider/login  {device?}
      if (a && b === "login" && m === "POST") {
        const p = providers[a as ProviderId];
        if (!p?.login) return jsonError(400, `${a} has no OAuth login`);
        const body = await readJson<{ device?: boolean }>(req);
        return Response.json(await p.login.start({ device: !!body.device }));
      }
      // POST /api/accounts/:provider/apikey {apiKey, label}
      if (a && b === "apikey" && m === "POST") {
        const p = providers[a as ProviderId];
        if (!p?.addApiKey) return jsonError(400, `${a} does not use API keys`);
        const body = await readJson<{ apiKey?: string; label?: string }>(req);
        if (!body.apiKey?.trim()) return jsonError(400, "apiKey required");
        return Response.json(publicAccount(await p.addApiKey(body.apiKey.trim(), body.label)));
      }
      const acc = a ? getAccount(a) : null;
      if (!acc) return jsonError(404, "account not found", "not_found");
      if (!b && m === "PATCH") {
        updateAccountSettings(acc.id, await readJson(req));
        return Response.json(publicAccount(getAccount(acc.id)!));
      }
      if (!b && m === "DELETE") {
        deleteAccount(acc.id);
        return Response.json({ ok: true });
      }
      if (b === "quota" && m === "POST") {
        await providers[acc.provider].refreshQuota?.(acc);
        return Response.json(publicAccount(getAccount(acc.id)!));
      }
      if (b === "cooldown" && m === "DELETE") {
        clearCooldown(acc.id);
        return Response.json(publicAccount(getAccount(acc.id)!));
      }
    }

    // GET /api/login/:provider/:loginId   DELETE = cancel
    if (head === "login" && a && b) {
      const p = providers[a as ProviderId];
      if (!p?.login) return jsonError(404, "no login flow", "not_found");
      if (m === "GET") return Response.json(p.login.status(b));
      if (m === "DELETE") {
        p.login.cancel(b);
        return Response.json({ ok: true });
      }
    }

    // GET /api/models
    if (head === "models" && m === "GET") {
      const out = [];
      for (const id of PROVIDER_IDS) {
        const hasAccount = listAccounts(id).some((x) => x.enabled);
        const models = hasAccount ? await providers[id].models().catch(() => []) : [];
        for (const mm of models) {
          const { raw: _raw, ...rest } = mm;
          // Auto Review is retired — never surface it, not even masked.
          if (rest.slug === AUTO_REVIEW_SLUG) continue;
          out.push(rest);
        }
      }
      return Response.json(out);
    }

    // GET /api/license — activation state for the GUI license box.
    // POST /api/license {key} — verify against the policy server, persist
    // license.key, load the bundle; on a stub build also fetch the licensed
    // binary (the "missing piece") and hand off to it.
    if (head === "license") {
      const { AUTOCUT_STUB } = await import("./share/autocut.ts");
      const { policyLoaded } = await import("./share/policy.ts");
      const { LICENSE_FILE, loadPolicy, policyBaseUrl, startPolicyRefresh } = await import("./share/policy-client.ts");
      if (m === "GET") {
        const { existsSync, readFileSync } = await import("node:fs");
        const lf = LICENSE_FILE();
        return Response.json({
          hasKey: existsSync(lf) && !!readFileSync(lf, "utf8").trim(),
          policyLoaded: policyLoaded(),
          stub: AUTOCUT_STUB,
        });
      }
      if (m === "POST") {
        const key = String((await req.json().catch(() => ({}))).key ?? "").trim();
        if (!key) return jsonError(400, "Paste the license key.", "bad_key");
        // Validates the key server-side and loads the bundle in one step.
        let src;
        try {
          src = await loadPolicy(key);
        } catch (err) {
          return jsonError(403, `License rejected: ${err instanceof Error ? err.message : err}`, "license_rejected");
        }
        const { writeFileSync } = await import("node:fs");
        writeFileSync(LICENSE_FILE(), key + "\n");
        if (AUTOCUT_STUB) {
          // Download the licensed binary — gated by this same key.
          const res = await pinnedFetch(`${policyBaseUrl()}/v1/agent?license=${encodeURIComponent(key)}`);
          if (!res.ok) return jsonError(502, `License ok but engine download failed (HTTP ${res.status}) — try again.`, "engine_download");
          const buf = Buffer.from(await res.arrayBuffer());
          writeFileSync(AGENT_EXE_PATH, buf);
          // Hand off: the full build starts with our argv after we exit.
          setTimeout(() => {
            spawn(AGENT_EXE_PATH, process.argv.slice(2), {
              env: { ...process.env, CH_WAIT_PID: String(process.pid), CH_CHAINED: "1" },
              detached: true,
              stdio: "ignore",
              windowsHide: true,
            }).unref();
            process.exit(0);
          }, 800);
          return Response.json({ ok: true, upgraded: true, bytes: buf.length });
        }
        if (policyLoaded()) startPolicyRefresh(key);
        return Response.json({ ok: true, licensed: true, policyV: src.v });
      }
    }

    // /api/licenses — operator key management, proxied to the policy server's
    // admin API. The admin key lives in settings/env, never in the GUI.
    //   GET    /api/licenses            → {licenses:[…]} or {configured:false}
    //   PUT    /api/licenses/adminkey   {key}  — save the admin key once
    //   POST   /api/licenses            {label?, expiresAt?} → mint
    //   DELETE /api/licenses/:key       → revoke
    //   PATCH  /api/licenses/:key       {expiresAt} → extend
    if (head === "licenses") {
      const { policyBaseUrl } = await import("./share/policy-client.ts");
      if (a === "adminkey" && m === "PUT") {
        const k = String((await req.json().catch(() => ({}))).key ?? "").trim();
        setSetting("license.adminKey", k);
        return Response.json({ ok: true });
      }
      const admin = process.env.CH_POLICY_ADMIN_KEY ?? getSetting<string>("license.adminKey", "");
      if (!admin) return Response.json({ configured: false });
      const path = a && b === "devices" && m === "DELETE" ? `/licenses/${encodeURIComponent(a)}/devices`
        : a && m !== "GET" ? `/licenses/${encodeURIComponent(a)}`
        : "/licenses";
      const res = await pinnedFetch(`${policyBaseUrl()}${path}`, {
        method: m === "GET" ? "GET" : m,
        headers: { authorization: `Bearer ${admin}`, "content-type": "application/json" },
        body: m === "POST" || m === "PATCH" ? JSON.stringify(await req.json().catch(() => ({}))) : undefined,
      });
      const text = await res.text();
      if (res.status === 403) return jsonError(403, "Policy server rejected the admin key.", "admin_key_rejected");
      return new Response(text, { status: res.status, headers: { "content-type": "application/json" } });
    }

    // POST /api/sync | DELETE /api/sync
    // /api/update — self-update controls for the customer console.
    //   GET  /api/update          → {current, latest, updateAvailable, auto}
    //   POST /api/update/apply    → download + swap + restart (console drops ~5s)
    //   PUT  /api/update/auto     {enabled} — persist the auto-update toggle
    if (head === "update") {
      const { checkUpdate, applyUpdate, setAutoUpdate } = await import("./update.ts");
      if (a === "apply" && m === "POST") {
        try {
          return Response.json(await applyUpdate());
        } catch (err) {
          return jsonError(502, `Update failed: ${err instanceof Error ? err.message : err}`, "update_failed");
        }
      }
      if (a === "auto" && m === "PUT") {
        const body = await readJson<{ enabled?: boolean }>(req);
        setAutoUpdate(!!body.enabled);
        return Response.json({ ok: true, auto: !!body.enabled });
      }
      if (m === "GET") return Response.json(await checkUpdate());
    }
    if (head === "sync") {
      if (m === "POST") return Response.json(await syncCodex(serverPort));
      if (m === "DELETE") return Response.json({ ok: unsyncCodex() });
    }

    // GET /api/usage?range=1h|24h|7d|30d|90d (or from&to) [&provider=&source=pool|share]
    if (head === "usage" && m === "GET") {
      return Response.json(
        await usageSummary({
          ...windowParam(url),
          provider: PROVIDER_IDS.find((id) => id === url.searchParams.get("provider")),
          source: enumParam(url, "source", ["pool", "share"] as const),
        }),
      );
    }

    // /api/share: remote users who call ChatGPT with their own login through the share port
    if (head === "share") return await handleShareApi(req, url, m, a, b, c);

    // GET /api/requests?limit=&before=<id>&provider=&source=&account=&status=ok|err&model=&effort=&minMs=&q=
    if (head === "requests" && m === "GET") {
      const account = textParam(url, "account", 200);
      return Response.json(
        await queryRequests({
          limit: intParam(url, "limit", 1, 500) ?? 100,
          before: intParam(url, "before", 1, Number.MAX_SAFE_INTEGER),
          provider: PROVIDER_IDS.find((id) => id === url.searchParams.get("provider")),
          source: enumParam(url, "source", ["pool", "share"] as const),
          account: account && ACCOUNT_RE.test(account) ? account : undefined,
          status: enumParam(url, "status", ["ok", "err"] as const),
          model: textParam(url, "model"),
          effort: textParam(url, "effort", 20),
          minMs: intParam(url, "minMs", 0, 3600_000),
          q: textParam(url, "q", 100),
        }),
      );
    }

    return jsonError(404, `no api route ${m} ${url.pathname}`, "not_found");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error(`api ${m} ${url.pathname} failed`, msg);
    return jsonError(500, msg);
  }
}

async function handleShareApi(req: Request, url: URL, m: string, a: string | undefined, b: string | undefined, c: string | undefined): Promise<Response> {
  // Read-only statistics. Every route here must stay a pure GET: the remote viewer role is "GET/HEAD only".
  if (a === "stats" && !b && m === "GET") {
    const w = windowParam(url);
    return Response.json(await shareStats(w.since, w.until));
  }
  if (a === "events" && !b && m === "GET") {
    const email = textParam(url, "email", 200);
    return Response.json(listShareEvents({ limit: intParam(url, "limit", 1, 200) ?? 50, email: email ? email.toLowerCase() : undefined }));
  }
  if (a === "users" && b && c === "stats" && m === "GET") {
    const w = windowParam(url);
    return Response.json(await shareUserStats(decodeURIComponent(b), w.since, w.until));
  }
  if (!a && m === "GET") {
    const stats = await shareLast24h();
    const publicUrl = publicBaseUrl();
    return Response.json({
      publicUrl,
      port: DEFAULT_SHARE_PORT > 0 ? DEFAULT_SHARE_PORT : null,
      installCommand: publicUrl ? `irm "${publicUrl}/install.ps1${installKeyQuery()}" | iex` : null,
      uninstallCommand: publicUrl ? `irm "${publicUrl}/uninstall.ps1${installKeyQuery()}" | iex` : null,
      installCommandMac: publicUrl ? `curl -fsSL "${publicUrl}/install.sh${installKeyQuery()}" | bash` : null,
      uninstallCommandMac: publicUrl ? `curl -fsSL "${publicUrl}/uninstall.sh${installKeyQuery()}" | bash` : null,
      users: listShareUsers().map((u) => {
        const s = stats.get(shareAccountId(u.email));
        return { ...u, requests24h: s?.requests ?? 0, tokens24h: s?.tokens ?? 0 };
      }),
    });
  }
  if (a === "settings" && m === "PUT") {
    const { publicUrl } = await readJson<{ publicUrl?: string | null }>(req);
    const v = publicUrl?.trim().replace(/\/+$/, "") || null;
    if (v && !/^https?:\/\/[A-Za-z0-9.-]+(:\d+)?(\/[A-Za-z0-9._~\/-]*)?$/.test(v)) return jsonError(400, `invalid url: ${v}`, "invalid_request_error");
    setSetting("share.publicUrl", v);
    return Response.json({ ok: true });
  }
  if (a === "users" && !b && m === "POST") {
    const { email, label, expireHours } = await readJson<{ email?: string; label?: string; expireHours?: number | null }>(req);
    try {
      addShareUser(email ?? "", label, expireHours ?? null);
    } catch (err) {
      return jsonError(400, err instanceof Error ? err.message : String(err), "invalid_request_error");
    }
    return Response.json({ ok: true });
  }
  if (a === "users" && b && !c) {
    const email = decodeURIComponent(b);
    if (m === "PATCH") {
      const body = await readJson<{ enabled?: boolean; expireHours?: number | null }>(req);
      const hasEnabled = typeof body.enabled === "boolean";
      const hasExpiry = "expireHours" in body;
      if (!hasEnabled && !hasExpiry) return jsonError(400, "nothing to update (enabled or expireHours)", "invalid_request_error");
      try {
        if (hasExpiry && !setShareUserExpiry(email, body.expireHours ?? null)) return jsonError(404, "no such user", "not_found");
      } catch (err) {
        return jsonError(400, err instanceof Error ? err.message : String(err), "invalid_request_error");
      }
      if (hasEnabled && !setShareUserEnabled(email, body.enabled!)) return jsonError(404, "no such user", "not_found");
      return Response.json({ ok: true });
    }
    if (m === "DELETE") return removeShareUser(email) ? Response.json({ ok: true }) : jsonError(404, "no such user", "not_found");
  }
  return jsonError(404, `no api route ${m} /api/share`, "not_found");
}
