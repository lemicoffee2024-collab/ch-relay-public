/**
 * Runtime policy for the packaged relay agent.
 *
 * The engine (SSE state machine, cut lanes, continuation) lives in this
 * binary. The *values* that make it work — sentinel strings, injected
 * instruction prose, tool schema text, tunables — arrive inside the
 * encrypted policy bundle fetched from the licensing server at startup and
 * are held in memory only. The defaults below are deliberately inert
 * placeholders so an unbundled build behaves like a plain pass-through
 * proxy.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

// --- encrypted-at-rest secrets ---------------------------------------------
// Secret string fields never persist as readable plaintext in the heap:
// setPolicy seals each value under an ephemeral per-process key (AES-256-GCM)
// and the POLICY fields become non-enumerable decrypting accessors. A heap
// dump therefore contains ciphertext blobs plus an unlabeled 32-byte key —
// not searchable instruction prose. Plaintext strings exist only as
// short-lived values while a caller actually uses them. (Request bodies that
// legitimately embed these values upstream are outside this protection's
// scope — they exist for the lifetime of the turn by necessity.)
const sealKey = randomBytes(32);
const sealed = new Map<string, { iv: Buffer; tag: Buffer; data: Buffer }>();

const sealText = (v: string) => {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", sealKey, iv);
  const data = Buffer.concat([c.update(v, "utf8"), c.final()]);
  return { iv, tag: c.getAuthTag(), data };
};

const unsealText = (k: string): string => {
  const s = sealed.get(k);
  if (!s) return "";
  const d = createDecipheriv("aes-256-gcm", sealKey, s.iv);
  d.setAuthTag(s.tag);
  return Buffer.concat([d.update(s.data), d.final()]).toString("utf8");
};

export interface PolicySpec {
  v: number;
  /** Sentinels the model is told to emit; the stream is cut on sight. */
  marker: string;
  appendixTag: string;
  endnoteTag: string;
  /** Sacrificial trailing argument key injected into tool schemas. */
  argPadKey: string;
  /** Companion bookkeeping tool appended to the request. */
  padCallName: string;
  padCallDescription: string;
  padCallNotesDescription: string;
  /** Instruction templates — {{MARKER}} {{APPENDIX}} {{ENDNOTE}} {{PAD}} {{ARGPAD}} substituted. */
  tplPadCall: string;
  tplMarker: string;
  tplMarkerUserNote: string;
  tplToolPad: string;
  /** Tool-description prefixes/suffixes. */
  tplToolDescPad: string;       // "{{PAD}} after every call" prefix
  tplArgSchemaDesc: string;     // strict pad-arg property description
  tplArgSchemaDescSoft: string; // optional pad-arg property description
  tplArgsPadSoftDesc: string;   // "{{ARGPAD}} required" description prefix
  tplCustomPadSuffix: string;   // custom-tool "const pad" trailer rule
  tplCodePadPrefix: string;     // function w/ code param pad rule
  tplFuncPadPrefix: string;     // function args-object pad rule
  tplStrTailSuffix: string;     // long-string endnote tail rule
  /** Lark grammar pad terminal + rule suffix for constrained decoding. */
  larkPadTerm: string;
  larkPadRule: string;
  /** The literal pad statement text used for already-padded detection. */
  padStatement: string;
  /** Regex source matching the pad statement (e.g. `const[ \t]+pad[a-z0-9_]*`). */
  padStmtPattern: string;
  /** Bare-line alternation for degraded sentinels, e.g. `TASK_COMPLETE|APPENDIX|ENDNOTE(_9F3)?`. */
  markerBareAlt: string;
  /** End-of-answer sentinel for marker-fragile models (astra): emitted once at
   *  the true end of the response, padding continues after it. An HTML
   *  comment so a leaked token stays invisible in rendered surfaces. */
  textSentinel: string;
  /** Minimal sentinel instruction — {{SENTINEL}} substituted. */
  tplSentinel: string;
  /** Continuation resume instruction — {{TASK}} {{STATE}} {{TAIL}} {{MARKER}}. */
  tplContinuation: string;
  /** Header line prepended to the work-log digest inside continuations. */
  tplStateHead: string;
  /** json_schema lane: name + notes-field description. */
  jsonLaneName: string;
  jsonNotesDescription: string;
  limits: {
    cutChars?: number;
    maxSegments: number;
    tailChars: number;
    postcallChars: number;
    postcallStallMs?: number;
    upstreamHdrMs?: number;
    noFirstByteMs?: number;
    callOpenMaxMs?: number;
    digestChars: number;
    contEffort: string;
    mainEffort?: string;
    stripReasoning?: string;
    holdback: number;
    argHoldback: number;
    lightChars?: number;
    lightModel?: string;
    lightCollab?: boolean;
    subagentModel?: string;
    reviewModel?: string;
    trimChars?: number;
    jsonLane?: boolean;
  };
}

/** Inert defaults — the engine runs but every trigger is a random-looking
 *  token no real model will ever emit unprompted, so unbundled operation is
 *  a transparent relay. Real values only ever exist inside the bundle. */
const INERT = "\u27e6UNSET\u27e7";

export const POLICY: PolicySpec = {
  v: 0,
  marker: `${INERT}_M`,
  appendixTag: `${INERT}_A`,
  endnoteTag: `${INERT}_E`,
  argPadKey: "__pad_unset",
  padCallName: "__pad_call_unset",
  padCallDescription: "Bookkeeping call.",
  padCallNotesDescription: "Notes.",
  tplPadCall: "",
  tplMarker: "",
  tplMarkerUserNote: "",
  tplToolPad: "",
  tplToolDescPad: "",
  tplArgSchemaDesc: "Metadata.",
  tplArgSchemaDescSoft: "Metadata.",
  tplArgsPadSoftDesc: "",
  tplCustomPadSuffix: "",
  tplCodePadPrefix: "",
  tplFuncPadPrefix: "",
  tplStrTailSuffix: "",
  larkPadTerm: "PADTAIL_UNSET",
  larkPadRule: "",
  padStatement: "const pad",
  padStmtPattern: "const[ \\t]+pad[a-z0-9_]*",
  markerBareAlt: "NEVER_MATCH",
  textSentinel: "",
  tplSentinel:
    "",
  tplContinuation: "",
  tplStateHead: "Work already emitted (do not redo it):",
  jsonLaneName: "relay_response",
  jsonNotesDescription: "Metadata.",
  limits: {
    maxSegments: 24,
    tailChars: 1500,
    postcallChars: 2000,
    digestChars: 2500,
    contEffort: "medium",
    holdback: 512,
    argHoldback: 1024,
  },
};

let loaded = false;

export function policyLoaded(): boolean {
  return loaded;
}

/** Wipe the sealed bundle — license revoked server-side. Getters return ""
 *  so the mutation pipeline goes inert and the agent degrades to plain relay
 *  until a future refresh loads a bundle again (license renewed). */
export function clearPolicy(): void {
  sealed.clear();
  loaded = false;
}

export function setPolicy(p: PolicySpec): void {
  for (const k of Object.keys(p) as (keyof PolicySpec)[]) {
    if (k === "limits" || k === "v") continue;
    const v = p[k];
    if (typeof v === "string") {
      sealed.set(k, sealText(v));
      Object.defineProperty(POLICY, k, {
        enumerable: false,
        configurable: true,
        get: () => unsealText(k),
        set: (nv: string) => sealed.set(k, sealText(nv)),
      });
    } else if (v !== undefined) {
      (POLICY as any)[k] = v;
    }
  }
  POLICY.limits = { ...POLICY.limits, ...p.limits };
  if (p.v !== undefined) POLICY.v = p.v;
  loaded = true;
}

/** {{KEY}} substitution for bundle templates. */
export function tpl(t: string, vars: Record<string, string>): string {
  return t.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] ?? "");
}

/** Common placeholder map for instruction templates. */
export function tplVars(): Record<string, string> {
  return {
    MARKER: POLICY.marker,
    APPENDIX: POLICY.appendixTag,
    ENDNOTE: POLICY.endnoteTag,
    PAD: POLICY.padCallName,
    ARGPAD: POLICY.argPadKey,
    SENTINEL: POLICY.textSentinel,
  };
}
