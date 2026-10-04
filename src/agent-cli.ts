#!/usr/bin/env bun
/**
 * ch-relay agent — packaged share endpoint for end-user machines.
 *
 *   ch-agent.exe start [--port 11500] [--license KEY]
 *
 * The binary ships only the stream engine; the operating parameters arrive
 * in the licensed policy bundle fetched at startup (see share/policy.ts).
 * Without a license the process is a no-op relay — by design.
 */
import { writeFileSync } from "node:fs";
import { DEFAULT_SHARE_PORT, PID_PATH, ensureHome } from "./paths.ts";
import { getDb } from "./store/db.ts";
import { log } from "./lib/log.ts";
import { loadPolicy, readLicense, startPolicyRefresh } from "./share/policy-client.ts";
import { policyLoaded } from "./share/policy.ts";

const [cmd = "start", ...args] = process.argv.slice(2);
const flag = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main() {
  switch (cmd) {
    case "start": {
      ensureHome();
      getDb();
      const license = readLicense(flag("license"));
      if (!license) {
        console.error("[ch-relay] no license — running as a plain relay (licensed features locked)");
      } else {
        try {
          const src = await loadPolicy(license);
          log.info(`policy loaded v${src.v} source=${src.source}`);
        } catch (err) {
          console.error(`[ch-relay] ${err instanceof Error ? err.message : err} — running as a plain relay`);
        }
      }
      if (policyLoaded()) startPolicyRefresh(license!);
      const sharePort = Number(flag("port") ?? DEFAULT_SHARE_PORT);
      const { startShareServer } = await import("./share/server.ts");
      startShareServer(sharePort);
      writeFileSync(PID_PATH, String(process.pid));
      log.info(`ch-relay agent listening on 127.0.0.1:${sharePort}`);
      break;
    }
    case "version":
      console.log("ch-relay agent");
      break;
    default:
      console.log("usage: ch-agent start [--port N] [--license KEY]");
  }
}

await main();
