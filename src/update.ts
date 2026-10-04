/**
 * Agent self-update: query the policy server for the latest version, pull
 * the binary from /dl/agent, and hand the swap to a tiny detached helper
 * script (a running exe cannot overwrite itself). Auto-update is a
 * customer-visible toggle persisted in settings.
 */

import { getSetting, setSetting } from "./store/db.ts";
import { policyBaseUrl } from "./share/policy-client.ts";
import { HOME } from "./paths.ts";
import { AGENT_VERSION } from "./version.ts";
import { log } from "./lib/log.ts";
import { spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const OS_KEY = process.platform === "darwin" ? (process.arch === "arm64" ? "mac-arm64" : "mac-x64") : "win";
const CHECK_TTL_MS = 5 * 60_000;
const AUTO_CHECK_MS = 6 * 3600_000;

let latestCache: { v: string; at: number } | null = null;

function semverCmp(a: string, b: string): number {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export function autoUpdate(): boolean {
  const v = getSetting<unknown>("update.auto", true);
  return v === true || v === "1" || v === "true";
}

export function setAutoUpdate(on: boolean): void {
  setSetting("update.auto", on);
}

export function updateState() {
  const latest = latestCache?.v ?? null;
  return {
    current: AGENT_VERSION,
    latest,
    updateAvailable: !!latest && semverCmp(latest, AGENT_VERSION) > 0,
    auto: autoUpdate(),
    checkedAt: latestCache?.at ?? null,
  };
}

export async function checkUpdate(force = false): Promise<ReturnType<typeof updateState>> {
  if (!force && latestCache && Date.now() - latestCache.at < CHECK_TTL_MS) return updateState();
  try {
    const res = await fetch(`${policyBaseUrl()}/version?os=${OS_KEY}`, { signal: AbortSignal.timeout(10_000) });
    if (res.ok) {
      const j = (await res.json()) as { v?: string };
      if (typeof j?.v === "string" && j.v) latestCache = { v: j.v, at: Date.now() };
    }
  } catch { /* offline — keep last state */ }
  return updateState();
}

let applying = false;

/** Download the new binary then exit — the helper script performs the swap
 *  once this process releases the file. Guarded by `applying` so the auto
 *  tick and a manual click can never run two swaps at once. */
export async function applyUpdate(): Promise<{ ok: true }> {
  if (applying) throw new Error("update already in progress");
  applying = true;
  try {
    return await doApply();
  } catch (err) {
    applying = false;
    throw err;
  }
}

async function doApply(): Promise<{ ok: true }> {
  const res = await fetch(`${policyBaseUrl()}/dl/agent?os=${OS_KEY}`, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`download failed (${res.status})`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length < 1_000_000) throw new Error("download looks truncated");
  const exe = process.execPath;
  const tmp = `${exe}.new`;
  writeFileSync(tmp, buf);
  const pid = process.pid;
  if (process.platform === "win32") {
    // Single hidden VBS helper: waits for this PID to exit, retries the
    // copy while the exe is still releasing, relaunches the agent hidden,
    // and repairs the Startup-folder autostart file (earlier installers
    // wrote it with a quote bug that made it a syntax error).
    const startupVbs = join(
      process.env.APPDATA ?? join(HOME, "..", "AppData", "Roaming"),
      "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "ch-relay.vbs",
    );
    const relaunch = `""${exe}"" start --admin-port 11504`;
    // Exact line a healthy Startup VBS should contain — written out via
    // WriteLine, so every " is doubled for the VBS string literal.
    const startupLine = `CreateObject("Wscript.Shell").Run "${relaunch}", 0, False`;
    const startupLineEscaped = startupLine.replace(/"/g, '""');
    const vbs = join(HOME, `update-${pid}.vbs`);
    writeFileSync(vbs, [
      'Set fso = CreateObject("Scripting.FileSystemObject")',
      'Set sh = CreateObject("Wscript.Shell")',
      'Set wmi = GetObject("winmgmts:\\\\.\\root\\cimv2")',
      "Do",
      `  Set ps = wmi.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE ProcessId=${pid}")`,
      "  If ps.Count = 0 Then Exit Do",
      "  WScript.Sleep 500",
      "Loop",
      "WScript.Sleep 500",
      "On Error Resume Next",
      "For i = 1 To 60",
      "  Err.Clear",
      `  fso.CopyFile "${tmp}", "${exe}", True`,
      "  If Err.Number = 0 Then Exit For",
      "  WScript.Sleep 500",
      "Next",
      `fso.DeleteFile "${tmp}", True`,
      "On Error Goto 0",
      `Set tf = fso.CreateTextFile("${startupVbs}", True)`,
      `tf.WriteLine "${startupLineEscaped}"`,
      "tf.Close",
      `sh.Run "${relaunch}", 0, False`,
      "fso.DeleteFile WScript.ScriptFullName",
    ].join("\r\n"));
    spawn("wscript.exe", [vbs], { detached: true, stdio: "ignore" }).unref();
  } else {
    const sh = join(HOME, `update-${pid}.sh`);
    writeFileSync(sh, [
      "#!/bin/sh",
      `while kill -0 ${pid} 2>/dev/null; do sleep 1; done`,
      `mv "${tmp}" "${exe}"`,
      `chmod +x "${exe}"`,
      // The installer plist has KeepAlive — kickstart picks up the new
      // binary; fall back to a direct launch when there's no plist.
      `launchctl kickstart -k "gui/$(id -u)/com.chrelay.agent" 2>/dev/null || "${exe}" start --admin-port 11504 >/dev/null 2>&1 &`,
      `rm -f "${sh}"`,
      "",
    ].join("\n"));
    spawn("sh", [sh], { detached: true, stdio: "ignore" }).unref();
  }
  setTimeout(() => process.exit(0), 500).unref();
  return { ok: true };
}

/** Background auto-update loop: first check shortly after boot, then every
 *  6h. Only fires when the customer toggle is on. */
export function startAutoUpdate(): void {
  const tick = async () => {
    if (!autoUpdate()) return;
    const s = await checkUpdate(true);
    if (!s.updateAvailable) return;
    log.info(`update: auto-applying ${s.current} -> ${s.latest}`);
    try {
      await applyUpdate();
    } catch (err) {
      log.info(`update: apply failed: ${err instanceof Error ? err.message : err}`);
    }
  };
  setTimeout(tick, 60_000).unref();
  setInterval(tick, AUTO_CHECK_MS).unref();
}
